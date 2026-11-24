# -*- coding: utf-8 -*-
"""
ShieldPy 玄盾卫士 - 纯 Python 轻量杀毒软件
==========================================
功能：哈希特征库检测 / 启发式脚本检测 / PE 加壳检测 / 快速·全盘·自定义扫描 /
      隔离区 / 白名单 / 实时监控 / 进程体检 / 扫描报告 / 图形界面

运行:  python main.py           （源码方式）
       ShieldPy.exe             （PyInstaller 单文件打包，内置解释器）
依赖:  Python 3.6+ 标准库（可选安装 watchdog 提升实时监控体验）
"""
import os
import shutil
import sys
import traceback
from pathlib import Path


def check_tkinter():
    try:
        import tkinter
        return True
    except Exception:
        return False


def ensure_data_files():
    """
    单文件 EXE 首次运行时：把内置的初始特征库等资源，
    从临时解压目录(_MEIPASS)复制到 EXE 旁的 data 目录。
    之后用户的配置 / 自定义特征 / 白名单 / 隔离区都会持久化在 EXE 旁。
    """
    if not getattr(sys, "frozen", False):
        return
    base = Path(sys.executable).resolve().parent
    data_dir = base / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    meipass = getattr(sys, "_MEIPASS", "")
    if not meipass:
        return
    src_root = Path(meipass) / "data"
    for name in ("signatures.json",):
        target = data_dir / name
        if not target.exists():
            src = src_root / name
            if src.exists():
                try:
                    shutil.copy2(src, target)
                except Exception:
                    pass
    # 确保隔离区 / 日志目录存在
    (data_dir / "quarantine").mkdir(parents=True, exist_ok=True)
    (data_dir / "logs").mkdir(parents=True, exist_ok=True)


def parse_args(argv):
    """
    命令行参数：
      --scan "路径"   对指定路径直接启动自定义查杀（右键菜单入口）
    """
    scan_target = None
    i = 0
    while i < len(argv):
        if argv[i] == "--scan" or argv[i] == "-s":
            if i + 1 < len(argv) and argv[i + 1]:
                scan_target = argv[i + 1]
                i += 2
            else:
                i += 1
        else:
            i += 1
    return scan_target


def main():
    scan_target = parse_args(sys.argv[1:])
    if sys.version_info < (3, 6):
        print("需要 Python 3.6 及以上版本")
        return 1
    if not check_tkinter():
        print("未找到 tkinter（图形界面库）。请安装 python-tk。")
        return 1

    # 单文件 EXE 模式：先引导数据文件
    ensure_data_files()

    # 将项目根目录加入 path（兼容直接运行 main.py）
    BASE = Path(__file__).resolve().parent
    if str(BASE) not in sys.path:
        sys.path.insert(0, str(BASE))

    try:
        from ui.app import run
        run(scan_target=scan_target)
        return 0
    except Exception:
        traceback.print_exc()
        # 窗口模式下错误不可见，写入日志文件
        try:
            from core.config import DATA_DIR
            err = (Path(DATA_DIR) / "logs" / "startup_error.txt")
            err.parent.mkdir(parents=True, exist_ok=True)
            err.write_text(traceback.format_exc(), encoding="utf-8")
        except Exception:
            pass
        return 1


if __name__ == "__main__":
    sys.exit(main())
