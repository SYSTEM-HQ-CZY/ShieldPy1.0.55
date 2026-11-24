# -*- coding: utf-8 -*-
"""隔离区页：查看、恢复、彻底删除已隔离的威胁文件。"""
import tkinter as tk
from tkinter import messagebox, ttk

from core.quarantine import quarantine


class QuarantinePage(ttk.Frame):
    def __init__(self, master, theme, app):
        super().__init__(master, style="TFrame")
        self.theme = theme
        self.app = app
        self._build()

    def _build(self):
        header = ttk.Frame(self, style="TFrame")
        header.pack(fill="x", padx=24, pady=(20, 6))
        ttk.Label(header, text="◇ 隔离区", style="Title.TLabel").pack(side="left")
        ttk.Button(header, text="↻ 刷新", style="TButton", command=self.refresh).pack(side="right")

        ttk.Label(self, text="被隔离的文件已与原始位置隔离，可在此恢复或彻底删除。",
                  style="Muted.TLabel").pack(anchor="w", padx=26)

        card = ttk.Frame(self, style="Card.TFrame")
        card.pack(fill="both", expand=True, padx=24, pady=(10, 10))
        cols = ("time", "threat", "orig", "det", "size")
        self.tree = ttk.Treeview(card, columns=cols, show="headings", selectmode="extended")
        for cid, txt, w in (("time", "隔离时间", 130), ("threat", "威胁", 200),
                            ("orig", "原始路径", 460), ("det", "检测方式", 90), ("size", "大小", 70)):
            self.tree.heading(cid, text=txt)
            self.tree.column(cid, width=w, anchor="w")
        vsb = ttk.Scrollbar(card, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True, padx=(12, 0), pady=12)
        vsb.pack(side="right", fill="y", pady=12)

        actions = ttk.Frame(self, style="Card.TFrame")
        actions.pack(fill="x", padx=24, pady=(0, 20))
        ttk.Button(actions, text="↩ 恢复选中", style="Accent.TButton",
                   command=self.restore).pack(side="left", padx=12, pady=10)
        ttk.Button(actions, text="✕ 彻底删除选中", style="Danger.TButton",
                   command=self.delete_forever).pack(side="left", padx=4, pady=10)

        self.refresh()

    def refresh(self):
        for i in self.tree.get_children():
            self.tree.delete(i)
        items = quarantine.list_items()
        for it in items:
            size = f"{it.size / 1024:.1f} KB" if it.size > 1024 else f"{it.size} B"
            self.tree.insert("", "end", iid=it.id,
                             values=(it.time, it.threat[:100], it.orig_path, it.detection, size))
        self.app.refresh_dashboard()

    def _selected(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("提示", "请先选择隔离文件")
            return []
        return sel

    def restore(self):
        for qid in self._selected():
            ok, msg = quarantine.restore(qid)
            if not ok:
                messagebox.showerror("恢复失败", msg)
        self.refresh()

    def delete_forever(self):
        sel = self._selected()
        if not sel:
            return
        if not messagebox.askyesno("确认", f"确定要彻底删除选中的 {len(sel)} 个隔离文件吗？\n此操作不可恢复！"):
            return
        for qid in sel:
            quarantine.delete_forever(qid)
        self.refresh()
