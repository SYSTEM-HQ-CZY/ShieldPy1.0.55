# -*- coding: utf-8 -*-
"""全局路径与配置管理。"""
import json
import os
import sys
from pathlib import Path

# ---- 项目根目录（core 的上一级），保证从任意 cwd 启动都正确 ----
BASE_DIR = Path(__file__).resolve().parent.parent
if getattr(sys, "frozen", False):          # PyInstaller 打包后
    BASE_DIR = Path(sys.executable).resolve().parent

DATA_DIR = BASE_DIR / "data"
QUARANTINE_DIR = DATA_DIR / "quarantine"
REPORTS_DIR = BASE_DIR / "reports"
LOGS_DIR = DATA_DIR / "logs"
CONFIG_FILE = DATA_DIR / "config.json"
WHITELIST_FILE = DATA_DIR / "whitelist.json"
SIGNATURE_FILE = DATA_DIR / "signatures.json"
HEURISTIC_FILE = DATA_DIR / "heuristics.json"

for _d in (DATA_DIR, QUARANTINE_DIR, REPORTS_DIR, LOGS_DIR):
    _d.mkdir(parents=True, exist_ok=True)


def _default_quick_dirs():
    """快速扫描目录：系统 Temp、用户 Temp、下载目录、桌面。"""
    dirs = []
    windir = os.environ.get("WINDIR", "C:\\Windows")
    temp_env = os.environ.get("TEMP") or os.environ.get("TMP")
    if temp_env:
        dirs.append(temp_env)
    dirs.append(str(Path(windir) / "Temp"))
    user_home = Path.home()
    for sub in ("Downloads", "下载", "Desktop", "桌面"):
        p = user_home / sub
        if p.exists():
            dirs.append(str(p))
    # 去重保序
    seen, out = set(), []
    for d in dirs:
        k = os.path.normcase(os.path.normpath(d))
        if k not in seen:
            seen.add(k)
            out.append(d)
    return out


DEFAULT_CONFIG = {
    "quick_dirs": _default_quick_dirs(),
    "realtime_monitor": True,          # v1.0.55 默认开启实时防护
    "realtime_scope": "full",          # full=全盘防护（默认）/ custom=自定义目录
    "realtime_dirs": [],
    "realtime_auto_action": "quarantine",  # 实时发现威胁自动处置: alert/quarantine/delete
    "defense_startup": True,           # 自启动项监控
    "defense_hosts": True,             # hosts 保护
    "deep_heuristic": True,            # 深度启发式（内容分析）
    "scan_archives": False,            # 是否扫描压缩包（zip）
    "scan_perf_mode": "balanced",      # 扫描性能: low/balanced/high（控制 CPU 占用）
    "max_file_mb": 100,                # 超过该大小的文件跳过内容分析（仅查 hash）
    "theme": "dark",                   # dark / light
    "auto_add_whitelist_on_trust": True,
    "last_scan_time": "",
    "stats": {"scanned": 0, "threats": 0, "cleaned": 0},
}


class Config:
    """轻量配置读写。"""

    def __init__(self, path: Path = CONFIG_FILE):
        self.path = Path(path)
        self.data = dict(DEFAULT_CONFIG)
        self.load()

    def load(self):
        if self.path.exists():
            try:
                loaded = json.loads(self.path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    self.data = {**DEFAULT_CONFIG, **loaded}
                    # v1.0.55 迁移：旧版配置（无 realtime_scope 字段）升级为
                    # 默认开启"全盘实时防护"，用户之后可手动关闭
                    if "realtime_scope" not in loaded:
                        self.data["realtime_monitor"] = True
                        self.data["realtime_scope"] = "full"
            except Exception:
                pass

    def save(self):
        try:
            self.path.write_text(
                json.dumps(self.data, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        except Exception:
            pass

    def get(self, key, default=None):
        return self.data.get(key, default)

    def set(self, key, value):
        self.data[key] = value
        self.save()

    def bump_stats(self, **kw):
        st = self.data.setdefault("stats", dict(DEFAULT_CONFIG["stats"]))
        for k, v in kw.items():
            st[k] = st.get(k, 0) + v
        self.save()


# 全局单例
config = Config()
