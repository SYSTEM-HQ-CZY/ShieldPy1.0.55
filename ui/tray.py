# -*- coding: utf-8 -*-
"""系统托盘（v1.0.55 新增）：
后台常驻 + 托盘图标 + 右键菜单（显示主界面 / 暂停-恢复实时防护 / 退出）。
"""
import os
import sys
import threading
from pathlib import Path

from core import logger

try:
    import pystray
    from PIL import Image
    HAS_TRAY = True
except Exception:
    pystray = None
    HAS_TRAY = False


def _find_icon_image():
    """按优先级查找托盘图标：_MEIPASS 内嵌 > exe 旁 > 项目目录。"""
    candidates = []
    meipass = getattr(sys, "_MEIPASS", "")
    if meipass:
        candidates.append(Path(meipass) / "icon" / "shield_icon.ico")
        candidates.append(Path(meipass) / "icon" / "shield_icon.png")
    base = Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) \
        else Path(__file__).resolve().parent.parent
    candidates.append(base / "data" / "shield_icon.ico")
    candidates.append(Path(__file__).resolve().parent.parent / "installer" / "shield_icon.ico")
    candidates.append(Path(__file__).resolve().parent.parent / "installer" / "shield_icon.png")
    for c in candidates:
        if c.exists():
            try:
                return Image.open(str(c)).convert("RGBA")
            except Exception:
                continue
    return None


class TrayIcon:
    """系统托盘封装。所有回调运行在 pystray 线程，需用 app.after 调度回主线程。"""

    def __init__(self, on_show, on_toggle, on_quit, protection_running=True):
        self._on_show = on_show
        self._on_toggle = on_toggle
        self._on_quit = on_quit
        self._running = protection_running
        self._icon = None

    def _build_menu(self):
        toggle_label = "暂停实时防护" if self._running else "恢复实时防护"
        return pystray.Menu(
            pystray.MenuItem("显示主界面", self._cb_show, default=True),
            pystray.MenuItem(toggle_label, self._cb_toggle),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("退出", self._cb_quit),
        )

    def _cb_show(self, icon, item):
        if self._on_show:
            self._on_show()

    def _cb_toggle(self, icon, item):
        self._running = not self._running
        if self._on_toggle:
            self._on_toggle(self._running)

    def _cb_quit(self, icon, item):
        if self._on_quit:
            self._on_quit()

    def start(self):
        if not HAS_TRAY:
            return False
        img = _find_icon_image()
        if img is None:
            logger.warning("托盘图标资源未找到")
            return False
        self._icon = pystray.Icon(
            "ShieldPy玄盾卫士", img, "ShieldPy 玄盾卫士",
            menu=self._build_menu())
        threading.Thread(target=self._icon.run, daemon=True).start()
        logger.info("系统托盘已启动")
        return True

    def update_menu(self, protection_running=True):
        """暂停/恢复后刷新菜单文案。"""
        self._running = protection_running
        if self._icon is not None:
            try:
                self._icon.menu = self._build_menu()
            except Exception:
                pass

    def notify(self, title, msg=""):
        if self._icon is not None:
            try:
                self._icon.notify(msg or title, title)
            except Exception:
                pass

    def stop(self):
        if self._icon is not None:
            try:
                self._icon.stop()
            except Exception:
                pass
            self._icon = None
