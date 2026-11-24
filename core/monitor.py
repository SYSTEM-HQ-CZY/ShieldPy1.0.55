# -*- coding: utf-8 -*-
"""主动防御引擎 v1.0.55（实时监控加强版）：
1. 文件实时监控（watchdog / 轮询）—— 监控目录内新增/修改文件并自动扫描
2. 威胁自动处置 —— 发现威胁后按策略：仅告警 / 自动隔离 / 自动删除
3. 自启动项监控 —— 注册表 Run/RunOnce + 启动文件夹新增条目检测
4. hosts 保护 —— 系统 hosts 文件被篡改检测
所有防御事件记录到 data/defense.log 并保存在内存 events 列表（防御中心展示）。
"""
import os
import re
import threading
import time
from pathlib import Path

from . import logger
from .config import config, DATA_DIR
from .scanner import engine
from .quarantine import quarantine

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    HAS_WATCHDOG = True
except Exception:
    HAS_WATCHDOG = False

# 实时监控关注的可执行 / 脚本 / 宏文件扩展名（其余文件不做内容分析，降低开销）
MONITOR_EXTS = {
    ".exe", ".dll", ".scr", ".pif", ".com", ".bat", ".cmd", ".vbs", ".vbe",
    ".ps1", ".psm1", ".js", ".jse", ".hta", ".wsf", ".py", ".msi", ".jar",
}
EXEC_EXTS = (".exe", ".bat", ".cmd", ".vbs", ".ps1", ".js", ".hta", ".com", ".scr", ".pif")

STARTUP_KEY_PATHS = [
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
]


class DefenseEvent:
    """一次主动防御事件记录。"""
    __slots__ = ("time", "kind", "target", "action", "detail", "severity")

    def __init__(self, kind, target, action, detail="", severity="medium"):
        self.time = time.strftime("%m-%d %H:%M:%S")
        self.kind = kind          # file / startup / hosts
        self.target = target
        self.action = action      # 已自动隔离 / 已自动删除 / 仅告警 / 已告警...
        self.detail = detail
        self.severity = severity  # high / medium / low


class RealtimeMonitor:
    def __init__(self):
        self._observer = None
        self._poll_thread = None
        self._aux_thread = None
        self._stop = threading.Event()
        self.on_threat = None     # callback(ThreatItem)
        self._seen = {}           # 轮询模式: path -> (mtime, size)
        self.running = False
        self.events = []          # 防御事件（最新在前，最多 200 条）
        self._last_notify = {}    # path -> 时间，防重复告警

    # ---------- 防御事件 ----------
    def _log_event(self, ev):
        self.events.insert(0, ev)
        del self.events[200:]
        try:
            line = "[{t}] {k} | {a} | {d} | {tg}\n".format(
                t=ev.time, k=ev.kind, a=ev.action, d=ev.detail, tg=ev.target)
            with open(str(DATA_DIR / "defense.log"), "a", encoding="utf-8") as f:
                f.write(line)
        except Exception:
            pass

    def clear_events(self):
        self.events.clear()

    # ---------- 启停 ----------
    @staticmethod
    def all_drives():
        """返回本机所有存在的磁盘分区根目录（全盘防护）。"""
        drives = []
        for d in range(65, 91):
            root = "{}:\\".format(chr(d))
            if os.path.isdir(root):
                drives.append(root)
        return drives or ["C:\\"]

    @staticmethod
    def key_dirs():
        """无 watchdog 时全盘降级为关键目录。"""
        dirs = []
        windir = os.environ.get("WINDIR", "C:\\Windows")
        temp = os.environ.get("TEMP") or os.environ.get("TMP")
        if temp and os.path.isdir(temp):
            dirs.append(temp)
        wt = os.path.join(windir, "Temp")
        if os.path.isdir(wt):
            dirs.append(wt)
        home = os.path.expanduser("~")
        for sub in ("Downloads", "下载", "Desktop", "桌面"):
            p = os.path.join(home, sub)
            if os.path.isdir(p):
                dirs.append(p)
        sf = os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup")
        if os.path.isdir(sf):
            dirs.append(sf)
        seen, out = set(), []
        for d in dirs:
            k = os.path.normcase(os.path.normpath(d))
            if k not in seen:
                seen.add(k)
                out.append(d)
        return out

    def start(self, dirs=None, scope=None):
        """启动主动防御。默认按配置 realtime_scope 计算监控范围：
        - full：全盘防护（自动枚举所有分区，事件驱动，CPU 占用低）
        - custom：使用传入/配置的目录列表
        返回 (ok, msg)。"""
        if self.running:
            return False, "监控已在运行"
        if scope is None:
            scope = str(config.get("realtime_scope", "full"))
        if dirs is None:
            dirs = list(config.get("realtime_dirs", []))
        degraded = False
        if scope == "full" or not dirs:
            dirs = self.all_drives()
            if not HAS_WATCHDOG:
                # 无 watchdog 时全盘轮询开销过大，退化为关键目录监控
                dirs = self.key_dirs()
                degraded = True
        dirs = [d for d in dirs if os.path.isdir(d)]
        if not dirs:
            return False, "监控目录无效"
        self._stop.clear()
        if HAS_WATCHDOG:
            self._start_watchdog(dirs)
        else:
            self._start_poll(dirs)
        # 辅助防御线程：自启动项 + hosts 保护
        self._aux_thread = threading.Thread(target=self._aux_loop, daemon=True)
        self._aux_thread.start()
        self.running = True
        self._dirs = dirs
        msg = "实时防护已启动（全盘）" if (scope == "full" and not degraded) else \
              ("实时防护已启动（关键目录，未安装 watchdog）" if degraded else "实时防护已启动")
        logger.info(f"实时监控已启动: {dirs}")
        return True, msg

    def stop(self):
        if not self.running:
            return
        self._stop.set()
        if self._observer:
            try:
                self._observer.stop()
                self._observer.join(timeout=3)
            except Exception:
                pass
            self._observer = None
        for t in (self._poll_thread, self._aux_thread):
            if t:
                try:
                    t.join(timeout=3)
                except Exception:
                    pass
        self._poll_thread = None
        self._aux_thread = None
        self.running = False
        logger.info("实时监控已停止")

    # ---- watchdog 模式 ----
    def _start_watchdog(self, dirs):
        class _Handler(FileSystemEventHandler):
            def on_created(self, event):
                self._parent._on_event(event)
            def on_modified(self, event):
                self._parent._on_event(event)
        h = _Handler()
        h._parent = self
        self._observer = Observer()
        for d in dirs:
            self._observer.schedule(h, d, recursive=True)
        self._observer.daemon = True
        self._observer.start()

    # ---- 轮询模式 ----
    def _start_poll(self, dirs):
        self._dirs = dirs
        self._poll_thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._poll_thread.start()

    def _poll_loop(self):
        interval = max(1.0, float(config.get("realtime_poll_interval", 2.0)))
        while not self._stop.is_set():
            for d in self._dirs:
                if self._stop.is_set():
                    break
                try:
                    self._poll_dir(d)
                except Exception:
                    pass
            self._stop.wait(interval)

    def _poll_dir(self, root):
        for dirpath, dirnames, filenames in os.walk(root):
            if self._stop.is_set():
                break
            for fn in filenames:
                full = os.path.join(dirpath, fn)
                if not fn.lower().endswith(tuple(MONITOR_EXTS)):
                    continue
                try:
                    st = os.stat(full)
                    key = (st.st_mtime_ns, st.st_size)
                    prev = self._seen.get(full)
                    if prev != key:
                        self._seen[full] = key
                        if prev is not None or len(self._seen) < 50:
                            self._scan_file(full)
                except Exception:
                    continue
            if len(self._seen) > 50000:
                self._seen.clear()

    # ---- 文件事件统一入口 ----
    def _on_event(self, event):
        try:
            if event.is_directory:
                return
            p = event.src_path
            base = os.path.basename(p).lower()
            if base.endswith((".tmp", ".temp", "~", ".lock", ".swp")):
                return
            if not base.endswith(tuple(MONITOR_EXTS)):
                return
            if os.path.isfile(p):
                self._scan_file(p)
        except Exception:
            pass

    def _scan_file(self, path):
        """扫描单个文件；命中威胁则按策略自动处置并记录事件。"""
        item = engine.scan_file(path)
        if not item:
            return
        self._handle_threat(item)

    def _handle_threat(self, item):
        action = str(config.get("realtime_auto_action", "quarantine"))
        if action == "quarantine":
            ok, res = quarantine.quarantine_file(
                item.path, threat=item.threat, detection=item.detection,
                md5=item.md5, sha256=item.sha256, size=item.size)
            act = "已自动隔离" if ok else "隔离失败"
            detail = f"{item.detection}: {item.threat[:40]}" + (f" ({res})" if not ok else "")
        elif action == "delete":
            try:
                os.remove(item.path)
                act = "已自动删除"
                detail = f"{item.detection}: {item.threat[:40]}"
            except Exception as e:
                act = "删除失败"
                detail = f"{item.detection}: {item.threat[:40]} ({e})"
        else:
            act = "仅告警"
            detail = f"{item.detection}: {item.threat[:40]}"
        self._log_event(DefenseEvent("file", item.path, act, detail, item.severity))
        logger.warning(f"[主动防御] {act}: {item.threat} @ {item.path}")
        if self.on_threat:
            try:
                self.on_threat(item)
            except Exception:
                pass

    # ---------- 辅助防御：自启动项 + hosts ----------
    def _aux_loop(self):
        self._startup_baseline = self._startup_snapshot()
        self._hosts_base = self._hosts_state()
        while not self._stop.is_set():
            if config.get("defense_startup", True):
                try:
                    self._check_startup_once()
                except Exception:
                    pass
            if config.get("defense_hosts", True):
                try:
                    self._check_hosts_once()
                except Exception:
                    pass
            self._stop.wait(8)

    # ---- 自启动项监控 ----
    def _startup_snapshot(self):
        snap = {}
        try:
            import winreg
            for hive_name, subkey in STARTUP_KEY_PATHS:
                hive = winreg.HKEY_CURRENT_USER if hive_name == "HKCU" else winreg.HKEY_LOCAL_MACHINE
                try:
                    with winreg.OpenKey(hive, subkey) as k:
                        i = 0
                        while True:
                            try:
                                name, val, _ = winreg.EnumValue(k, i)
                                snap["{}\\{}".format(hive_name, name)] = val
                                i += 1
                            except OSError:
                                break
                except OSError:
                    pass
        except Exception:
            pass
        sf = os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup")
        if os.path.isdir(sf):
            for fn in os.listdir(sf):
                full = os.path.join(sf, fn)
                try:
                    st = os.stat(full)
                    snap["STARTUP\\{}".format(fn)] = (st.st_size, int(st.st_mtime))
                except Exception:
                    pass
        return snap

    def _check_startup_once(self):
        cur = self._startup_snapshot()
        base = getattr(self, "_startup_baseline", None)
        if base is None:
            self._startup_baseline = cur
            return
        if base == cur:
            return
        self._startup_baseline = cur
        for key, val in cur.items():
            if key not in base:
                low = str(val).lower()
                suspicious = any(low.endswith(e) for e in EXEC_EXTS) or "powershell" in low or "http" in low
                if suspicious:
                    ev = DefenseEvent("startup", key, "已告警",
                                      "检测到新增自启动项: {}".format(val)[:120], "high")
                    self._log_event(ev)
                    logger.warning("[主动防御] 新增自启动项: {} = {}".format(key, val))
                    self._try_scan_startup_target(val)
                else:
                    self._log_event(DefenseEvent(
                        "startup", key, "已记录", "新增自启动项: {}".format(val)[:120], "low"))

    def _try_scan_startup_target(self, val):
        text = str(val)
        m = re.search(r'"([^"]+\.(?:exe|bat|cmd|vbs|ps1|js|hta))"', text, re.I)
        if not m:
            m = re.search(r'([A-Za-z]:\\[^"\s]+\.(?:exe|bat|cmd|vbs|ps1|js|hta))', text, re.I)
        if m and os.path.isfile(m.group(1)):
            item = engine.scan_file(m.group(1))
            if item:
                self._handle_threat(item)

    # ---- hosts 保护 ----
    def _hosts_path(self):
        return os.path.join(os.environ.get("WINDIR", r"C:\Windows"),
                            "System32", "drivers", "etc", "hosts")

    def _hosts_state(self):
        try:
            st = os.stat(self._hosts_path())
            return (st.st_size, int(st.st_mtime))
        except Exception:
            return None

    def _check_hosts_once(self):
        st = self._hosts_state()
        base = getattr(self, "_hosts_base", "unset")
        if base == "unset":
            self._hosts_base = st
            return
        if st is not None and st != base:
            self._hosts_base = st
            ev = DefenseEvent("hosts", self._hosts_path(), "已告警",
                              "hosts 文件被修改（可能被恶意篡改）", "high")
            self._log_event(ev)
            logger.warning("[主动防御] hosts 文件被修改")


# 全局单例
monitor = RealtimeMonitor()
