# -*- coding: utf-8 -*-
"""日志页：滚动显示运行日志。"""
import tkinter as tk
from tkinter import ttk

from core.logger import recent


class LogPage(ttk.Frame):
    def __init__(self, master, theme, app):
        super().__init__(master, style="TFrame")
        self.theme = theme
        self.app = app
        self._build()

    def _build(self):
        header = ttk.Frame(self, style="TFrame")
        header.pack(fill="x", padx=24, pady=(20, 6))
        ttk.Label(header, text="☰ 运行日志", style="Title.TLabel").pack(side="left")
        ttk.Button(header, text="↻ 刷新", style="TButton", command=self.refresh).pack(side="right")
        ttk.Label(self, text="ShieldPy 的运行记录。", style="Muted.TLabel").pack(anchor="w", padx=26)

        card = ttk.Frame(self, style="Card.TFrame")
        card.pack(fill="both", expand=True, padx=24, pady=(10, 20))
        self.text = tk.Text(card, bg=self.theme["entry_bg"], fg=self.theme["text"],
                            relief="flat", wrap="none", font=("Consolas", 9),
                            padx=12, pady=10, highlightthickness=0)
        vsb = ttk.Scrollbar(card, orient="vertical", command=self.text.yview)
        hsb = ttk.Scrollbar(card, orient="horizontal", command=self.text.xview)
        self.text.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.text.pack(side="left", fill="both", expand=True, padx=(12, 0), pady=12)
        vsb.pack(side="right", fill="y", pady=12)
        hsb.pack(side="bottom", fill="x", padx=12)
        self.refresh()

    def refresh(self):
        self.text.delete("1.0", "end")
        for line in recent(500):
            self.text.insert("end", line + "\n")
        self.text.see("end")
