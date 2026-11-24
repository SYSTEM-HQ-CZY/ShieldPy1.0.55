# -*- coding: utf-8 -*-
"""仪表盘：状态概览 + 快捷操作 + 统计卡片。"""
import tkinter as tk
from tkinter import ttk

from core.config import config
from core.monitor import monitor
from core.quarantine import quarantine
from core.signature import signature_db


class DashboardPage(ttk.Frame):
    def __init__(self, master, theme, app):
        super().__init__(master, style="TFrame")
        self.theme = theme
        self.app = app
        self._build()
        self.refresh()

    def _build(self):
        top = ttk.Frame(self, style="TFrame")
        top.pack(fill="x", padx=24, pady=(24, 8))
        ttk.Label(top, text="◈  ShieldPy 玄盾卫士", style="Title.TLabel").pack(side="left")
        ttk.Label(self, text="纯 Python 实现的轻量杀毒软件 · 哈希特征 + 启发式引擎",
                  style="Muted.TLabel").pack(anchor="w", padx=26)

        # 大状态卡片
        self.shield_card = ttk.Frame(self, style="Card.TFrame")
        self.shield_card.pack(fill="x", padx=24, pady=12)
        self.shield_var = tk.StringVar(value="安全")
        self.desc_var = tk.StringVar(value="欢迎使用 ShieldPy")
        ttk.Label(self.shield_card, textvariable=self.shield_var,
                  font=("Microsoft YaHei UI", 34, "bold"),
                  foreground=self.theme["success"], background=self.theme["card"]).pack(anchor="w", padx=22, pady=(18, 0))
        ttk.Label(self.shield_card, textvariable=self.desc_var,
                  style="Muted.TLabel").pack(anchor="w", padx=24, pady=(2, 18))

        # 快捷操作
        actions = ttk.Frame(self, style="TFrame")
        actions.pack(fill="x", padx=24, pady=6)
        cards = [
            ("⚡ 快速扫描", "扫描高风险位置", "quick", "Accent.TButton"),
            ("◉ 全盘扫描", "扫描所有分区", "full", "TButton"),
            ("▤ 自定义扫描", "选择目录/文件", "custom", "TButton"),
        ]
        for i, (t, d, mode, style) in enumerate(cards):
            c = ttk.Frame(actions, style="Card.TFrame")
            c.grid(row=0, column=i, padx=(0 if i == 0 else 8, 0), sticky="nsew")
            actions.columnconfigure(i, weight=1)
            ttk.Label(c, text=t, style="H2.TLabel").pack(anchor="w", padx=16, pady=(14, 0))
            ttk.Label(c, text=d, style="Muted.TLabel").pack(anchor="w", padx=16)
            ttk.Button(c, text="开始", style=style,
                       command=lambda m=mode: self.app.start_scan(m)).pack(anchor="w", padx=16, pady=(8, 14))

        # 统计卡片
        stats = ttk.Frame(self, style="TFrame")
        stats.pack(fill="x", padx=24, pady=10)
        self.stat_cards = {}
        labels = [("scanned", "累计扫描文件"), ("threats", "累计发现威胁"),
                  ("quarantine", "隔离区文件"), ("sig", "特征库条目")]
        for i, (key, name) in enumerate(labels):
            c = ttk.Frame(stats, style="Card.TFrame")
            c.grid(row=0, column=i, padx=(0 if i == 0 else 8, 0), sticky="nsew")
            stats.columnconfigure(i, weight=1)
            v = tk.StringVar(value="0")
            self.stat_cards[key] = v
            ttk.Label(c, textvariable=v, style="Accent.TLabel",
                      font=("Microsoft YaHei UI", 22, "bold"),
                      foreground=self.theme["text"],
                      background=self.theme["card"]).pack(anchor="w", padx=16, pady=(14, 0))
            ttk.Label(c, text=name, style="Muted.TLabel").pack(anchor="w", padx=16, pady=(0, 14))

        # 底部信息
        info = ttk.Frame(self, style="Card.TFrame")
        info.pack(fill="x", padx=24, pady=(10, 24))
        self.info_var = tk.StringVar()
        ttk.Label(info, textvariable=self.info_var, style="Muted.TLabel").pack(anchor="w", padx=16, pady=12)

    def refresh(self):
        st = config.get("stats", {})
        self.stat_cards["scanned"].set(str(st.get("scanned", 0)))
        self.stat_cards["threats"].set(str(st.get("threats", 0)))
        self.stat_cards["quarantine"].set(str(quarantine.count))
        self.stat_cards["sig"].set(str(signature_db.count))

        qc = quarantine.count
        if qc > 0:
            self.shield_var.set("有隔离威胁")
            self.desc_var.set(f"隔离区有 {qc} 个威胁文件待处理，请前往“隔离区”查看")
            self.shield_card.configure(style="Card.TFrame")
            for w in self.shield_card.winfo_children():
                w.configure(foreground=self.theme["warn"])
        else:
            self.shield_var.set("系统安全")
            last = config.get("last_scan_time", "")
            self.desc_var.set(f"上次扫描: {last or '尚未扫描'} · 实时监控: {'开' if config.get('realtime_monitor') else '关'}")
            for w in self.shield_card.winfo_children():
                if isinstance(w, ttk.Label):
                    w.configure(foreground=self.theme["success"])
        self.info_var.set(
            f"ShieldPy v1.0.0  |  特征库版本 {signature_db.version}（更新于 {signature_db.updated or '—'}）  |  "
            f"实时监控 {'运行中' if monitor.running else '未启动'}"
        )
