# -*- coding: utf-8 -*-
"""扫描引擎 v2（1.0.2 CPU 优化）
改进：
1. 单文件一次 I/O：一次性读取并同时计算 MD5/SHA256、截取文件头，避免重复读盘。
2. 多线程并行哈希（hashlib 释放 GIL），线程数由"扫描性能模式"控制。
3. 性能模式 low/balanced/high 控制 CPU 占用与节流，默认 balanced。
4. 威胁分级 high/medium/low，低风险提示不再计入"威胁"统计（解决误报感知）。
"""
import hashlib
import os
import queue
import threading
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from . import logger
from .config import config
from .heuristics import (
    detect_script_threat, detect_packer, read_text_safe,
    RISK_EXT_HINT,
)
from .signature import signature_db
from .whitelist import whitelist

_SCRIPT_EXT = {".vbs", ".vbe", ".ps1", ".psm1", ".bat", ".cmd", ".js", ".jse", ".hta", ".html", ".py", ".lnk"}
_ARCHIVE_EXT = {".zip"}
_SKIP_DIR_NAMES = {"$recycle.bin", "system volume information", "windows\\system32\\drivers\\etc"}

# 性能模式 -> (worker 线程数, 每文件节流秒)
# 实测基准（D:\python, 7315 文件, 本机 8 核）：
#   low(1,0.006)       -> CPU ~24%，耗时 ~133s
#   balanced(2,0.012)  -> CPU ~40%，耗时 ~90s   （默认）
#   high(2,0.001)      -> CPU ~110%，耗时 ~35s（追求速度）
PERF_MODES = {
    "low": (1, 0.006),
    "balanced": (2, 0.012),
    "high": (2, 0.001),
}
_BATCH = 200  # 分批提交的任务数（控制内存）


class ThreatItem:
    """威胁条目（兼容 Python 3.6）。severity: high/medium/low"""

    def __init__(self, path="", name="", detection="", threat="",
                 md5="", sha256="", size=0, action="未处理", time="", severity="medium"):
        self.path = path
        self.name = name
        self.detection = detection
        self.threat = threat
        self.md5 = md5
        self.sha256 = sha256
        self.size = size
        self.action = action
        self.time = time
        self.severity = severity


class ScanEngine:
    def __init__(self):
        self._stop_flag = threading.Event()
        self._thread = None
        self._result_lock = threading.Lock()
        self.results = []
        self.stats = {"scanned": 0, "skipped": 0, "threats": 0, "hints": 0, "errors": 0}
        self._start_time = 0.0
        self.on_progress = None
        self.on_threat = None
        self.on_done = None

    # ---------------- 单文件检测 ----------------
    def scan_file(self, path, inside_archive=False):
        """
        返回 ThreatItem 或 None。检测链：
        白名单 -> 哈希特征库 -> 扩展名提示 -> 脚本启发式 -> 加壳检测
        全程尽量单次读取文件，减少磁盘 I/O。
        """
        p = Path(path)
        try:
            if not p.exists() or not p.is_file():
                return None
            size = p.stat().st_size
            if size <= 0:
                return None

            # 1) 白名单
            if whitelist.contains(str(p)):
                return None

            # 2) 一次读取（大小受限时），同时计算双哈希 + 文件头
            max_mb = config.get("max_file_mb", 100)
            data = None
            if size <= max_mb * 1024 * 1024:
                try:
                    with open(p, "rb") as f:
                        data = f.read()
                except Exception:
                    data = None

            md5 = sha256 = ""
            rec = None
            if data is not None:
                md5 = hashlib.md5(data).hexdigest()
                sha256 = hashlib.sha256(data).hexdigest()
                rec = signature_db.lookup(md5=md5, sha256=sha256)
                if rec:
                    return ThreatItem(
                        path=str(p), name=p.name,
                        detection="Signature." + str(rec.get("type", "unknown")),
                        threat=rec.get("name", "已知威胁"),
                        md5=md5, sha256=sha256, size=size, severity="high",
                    )

            head = data[:65536] if data is not None else b""
            ext = p.suffix.lower()

            # 3) 高危扩展名 -> 低风险提示
            if ext in RISK_EXT_HINT and not inside_archive:
                name, desc = RISK_EXT_HINT[ext]
                return ThreatItem(
                    path=str(p), name=p.name, detection="Risk.Ext",
                    threat=f"{name} - {desc}", md5=md5, sha256=sha256,
                    size=size, severity="low",
                )

            # 4) 脚本启发式（带分级）
            if config.get("deep_heuristic", True) and ext in _SCRIPT_EXT:
                text = read_text_safe(p, data=data)
                if text:
                    name, desc, sev = detect_script_threat(p, text, ext)
                    if name and sev:
                        return ThreatItem(
                            path=str(p), name=p.name, detection="Heuristic",
                            threat=f"{name} - {desc}",
                            md5=md5, sha256=sha256, size=size, severity=sev,
                        )

            # 5) 加壳 / 特殊文件头（低风险提示）
            if head:
                name, desc, sev = detect_packer(p, head)
                if name and sev:
                    return ThreatItem(
                        path=str(p), name=p.name, detection="Packer",
                        threat=f"{name} - {desc}",
                        md5=md5, sha256=sha256, size=size, severity=sev,
                    )
            return None
        except Exception as e:
            logger.warn(f"扫描文件异常 {path}: {e}")
            return None

    # ---------------- 目录扫描 ----------------
    def start_scan(self, roots, follow_links=False):
        # 防并发：若上一次扫描线程仍在运行（如跨页重复点"开始扫描"），先停止它，
        # 否则两个线程会同时写进度回调，导致进度条来回跳（v1.0.55 修复）
        if self._thread and self._thread.is_alive():
            self._stop_flag.set()
            try:
                self._thread.join(timeout=10)
            except Exception:
                pass
        self._stop_flag.clear()
        self.results = []
        self.stats = {"scanned": 0, "skipped": 0, "threats": 0, "hints": 0, "errors": 0}
        self._start_time = time.time()
        self._thread = threading.Thread(
            target=self._run, args=(list(roots), follow_links), daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_flag.set()

    @property
    def running(self):
        return self._thread is not None and self._thread.is_alive()

    def _perf_params(self):
        mode = config.get("scan_perf_mode", "balanced")
        return PERF_MODES.get(mode, PERF_MODES["balanced"])

    def _run(self, roots, follow_links):
        try:
            files = []
            for root in roots:
                root = os.path.abspath(root)
                if not os.path.exists(root):
                    logger.warn(f"扫描路径不存在: {root}")
                    continue
                if os.path.isfile(root):
                    files.append(root)
                else:
                    files.extend(self._walk(root, follow_links))

            total = len(files)
            workers, throttle = self._perf_params()
            processed = [0]  # 用列表包裹便于闭包内修改

            def account(fp, item):
                if self._stop_flag.is_set():
                    return
                processed[0] += 1
                self.stats["scanned"] += 1
                if self.on_progress:
                    self.on_progress(processed[0], total, fp)
                if item:
                    with self._result_lock:
                        self.results.append(item)
                    if item.severity in ("high", "medium"):
                        self.stats["threats"] += 1
                        logger.warning(f"[威胁] {item.detection} {item.threat} @ {item.path}")
                    else:
                        self.stats["hints"] += 1
                        logger.info(f"[提示] {item.detection} {item.threat} @ {item.path}")
                    if self.on_threat:
                        self.on_threat(item)

            if workers <= 1:
                # 低 CPU 模式：单线程 + 节流
                for fp in files:
                    if self._stop_flag.is_set():
                        break
                    account(fp, self.scan_file(fp))
                    if throttle:
                        time.sleep(throttle)
            else:
                # 多线程并行 + 分批提交；每个 worker 处理后按节流参数限速，控制 CPU
                def work(fp):
                    if self._stop_flag.is_set():
                        return None
                    item = self.scan_file(fp)
                    if throttle:
                        time.sleep(throttle)
                    return item

                with ThreadPoolExecutor(max_workers=workers) as ex:
                    batch = []
                    for fp in files:
                        if self._stop_flag.is_set():
                            break
                        batch.append((fp, ex.submit(work, fp)))
                        if len(batch) >= _BATCH:
                            self._drain(batch, account)
                            batch = []
                    self._drain(batch, account)

            self.stats["elapsed"] = round(time.time() - self._start_time, 2)
            if self.on_done:
                self.on_done(self.stats)
        except Exception as e:
            logger.error(f"扫描线程异常: {e}")
            if self.on_done:
                self.on_done(self.stats)

    def _drain(self, batch, account):
        for fp, fut in batch:
            try:
                account(fp, fut.result())
            except Exception:
                account(fp, None)

    def _walk(self, root, follow_links):
        out = []
        for dirpath, dirnames, filenames in os.walk(root, followlinks=follow_links):
            if self._stop_flag.is_set():
                break
            dirnames[:] = [
                d for d in dirnames
                if d.lower() not in _SKIP_DIR_NAMES and not d.lower().startswith("$")
            ]
            for fn in filenames:
                if self._stop_flag.is_set():
                    break
                try:
                    full = os.path.join(dirpath, fn)
                    if os.path.islink(full) and not follow_links:
                        continue
                    out.append(full)
                except Exception:
                    continue
        return out

    # ---------------- 压缩包扫描 ----------------
    def scan_archive(self, zip_path):
        threats = []
        if not config.get("scan_archives", False):
            return threats
        try:
            with zipfile.ZipFile(zip_path) as zf:
                for info in zf.infolist():
                    if info.is_dir():
                        continue
                    name = info.filename.lower()
                    if name.endswith((".exe", ".scr", ".bat", ".cmd", ".ps1",
                                      ".vbs", ".vbe", ".js", ".jse", ".hta")):
                        threats.append(ThreatItem(
                            path=f"{zip_path}::>{info.filename}",
                            name=info.filename.rsplit("/", 1)[-1],
                            detection="Archive.Content",
                            threat="压缩包内含高危类型文件",
                            size=info.file_size, severity="low",
                        ))
        except Exception:
            pass
        return threats


# 全局单例
engine = ScanEngine()
