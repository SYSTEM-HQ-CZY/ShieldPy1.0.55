# -*- coding: utf-8 -*-
"""防御中心（v1.0.55 新增）：
展示实时防护状态、自动处置策略、防御项开关，以及主动防御事件日志。
"""
import tkinter as tk
from tkinter import ttk

from core.config import config
from core.monitor import monitor

KIND_CN = {"file": "文件", "startup": "自启动", "hosts": "hosts保护"}
ACTION_CN = {
    "alert": "仅告警", "quarantine": "自动隔离", "delete": "自动删除",
}


class DefensePage(ttk.Frame):
    def __init__(self, master, theme, app):
        super().__init__(master, style="TFrame")
        self.theme = theme
        self.app = app
        self._build()

    # ---------- 构建 ----------
    def _build(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)

        ttk.Label(self, text="防御中心", style="Title.TLabel").grid(
            row=0, column=0, sticky="w", padx=24, pady=(20, 4))
        ttk.Label(self, text="实时防护默认开启全盘监控，自动拦截新增/修改的可疑文件，并监控自启动项与 hosts 文件。",
                  style="Muted.TLabel").grid(row=1, column=0, sticky="w", padx=26)

        # 状态与控制卡
        card = ttk.Frame(self, style="Card.TFrame")
        card.grid(row=2, column=0, sticky="ew", padx=24, pady=(10, 8))
        self.status_var = tk.StringVar(value="● 实时防护: 运行中")
        ttk.Label(card, textvariable=self.status_var, style="H2.TLabel").grid(
            row=0, column=0, columnspan=2, sticky="w", padx=16, pady=(12, 2))
        self.scope_var = tk.StringVar(value="监控范围: -")
        ttk.Label(card, textvariable=self.scope_var, style="Muted.TLabel").grid(
            row=1, column=0, columnspan=2, sticky="w", padx=16, pady=(0, 4))

        # 自动处置
        ttk.Label(card, text="发现威胁时:", style="Card.TLabel").grid(
            row=2, column=0, sticky="w", padx=16, pady=6)
        self.action_var = tk.StringVar(value=config.get("realtime_auto_action", "quarantine"))
        cmb = ttk.Combobox(card, textvariable=self.action_var, state="readonly", width=12,
                           values=["quarantine", "delete", "alert"])
        cmb.grid(row=2, column=1, sticky="w", padx=(0, 16), pady=6)
        cmb.bind("<<ComboboxSelected>>", lambda e: self._save_action())
        ttk.Label(card, text="自动隔离(可恢复) / 自动删除 / 仅告警", style="Muted.TLabel").grid(
            row=3, column=0, columnspan=2, sticky="w", padx=16, pady=(0, 4))

        # 防御项开关
        self.startup_var = tk.BooleanVar(value=config.get("defense_startup", True))
        ttk.Checkbutton(card, text="自启动项监控（注册表 Run + 启动文件夹）",
                        variable=self.startup_var, command=self._save_switches).grid(
            row=4, column=0, columnspan=2, sticky="w", padx=16, pady=2)
        self.hosts_var = tk.BooleanVar(value=config.get("defense_hosts", True))
        ttk.Checkbutton(card, text="hosts 文件保护（防止被恶意篡改）",
                        variable=self.hosts_var, command=self._save_switches).grid(
            row=5, column=0, columnspan=2, sticky="w", padx=16, pady=2)

        # 按钮
        btn_row = ttk.Frame(card, style="Card.TFrame")
        btn_row.grid(row=6, column=0, columnspan=2, sticky="w", padx=16, pady=(10, 12))
        self.toggle_btn = ttk.Button(btn_row, text="暂停防护", style="Danger.TButton",
                                     command=self._toggle)
        self.toggle_btn.pack(side="left")
        ttk.Button(btn_row, text="清空防御日志", style="TButton",
                   command=self._clear_log).pack(side="left", padx=8)

        # 防御事件日志
        list_card = ttk.Frame(self, style="Card.TFrame")
        list_card.grid(row=3, column=0, sticky="nsew", padx=24, pady=(4, 20))
        ttk.Label(list_card, text="防御事件日志", style="H2.TLabel").pack(anchor="w", padx=16, pady=(12, 6))
        cols = ("time", "kind", "action", "detail", "target")
        self.tree = ttk.Treeview(list_card, columns=cols, show="headings", selectmode="browse")
        for cid, txt, w in (("time", "时间", 110), ("kind", "类型", 80),
                            ("action", "动作", 100), ("detail", "详情", 260),
                            ("target", "目标", 420)):
            self.tree.heading(cid, text=txt)
            self.tree.column(cid, width=w, anchor="w")
        self.tree.tag_configure("high", foreground=self.theme["danger"])
        self.tree.tag_configure("medium", foreground=self.theme["warn"])
        self.tree.tag_configure("low", foreground=self.theme["muted"])
        vsb = ttk.Scrollbar(list_card, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True, padx=(12, 0), pady=(0, 12))
        vsb.pack(side="right", fill="y", pady=(0, 12))

    # ---------- 动作 ----------
    def _save_action(self):
        config.set("realtime_auto_action", self.action_var.get())
        self.app.show_notify("自动处置策略", ACTION_CN.get(self.action_var.get(), self.action_var.get()))

    def _save_switches(self):
        config.set("defense_startup", self.startup_var.get())
        config.set("defense_hosts", self.hosts_var.get())
        self.app.show_notify("防御项", "监控开关已保存（实时生效）")

    def _toggle(self):
        if monitor.running:
            monitor.stop()
            self.app.show_notify("实时防护", "已暂停")
        else:
            monitor.on_threat = self.app.monitor_threat_cb
            ok, msg = monitor.start()
            self.app.show_notify("实时防护", msg)
        self.app.refresh_dashboard()
        self.refresh()

    def _clear_log(self):
        monitor.clear_events()
        try:
            from core.config import DATA_DIR
            p = DATA_DIR / "defense.log"
            if p.exists():
                p.unlink()
        except Exception:
            pass
        self.refresh()

    # ---------- 刷新 ----------
    def refresh(self):
        if monitor.running:
            self.status_var.set("● 实时防护: 运行中")
            self.toggle_btn.config(text="暂停防护", style="Danger.TButton")
            scope = getattr(monitor, "_dirs", [])
            self.scope_var.set("监控范围: " + ("、".join(scope) if scope else "-"))
        else:
            self.status_var.set("○ 实时防护: 已暂停")
            self.toggle_btn.config(text="恢复防护", style="Accent.TButton")
            self.scope_var.set("监控范围: -（点击恢复防护）")
        # 事件日志
        for i in self.tree.get_children():
            self.tree.delete(i)
        for ev in monitor.events:
            tag = ev.severity if ev.severity in ("high", "medium", "low") else "medium"
            self.tree.insert("", "end", tags=(tag,), values=(
                ev.time, KIND_CN.get(ev.kind, ev.kind), ev.action,
                ev.detail, ev.target))
