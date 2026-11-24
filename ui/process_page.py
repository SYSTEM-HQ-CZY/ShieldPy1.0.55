# -*- coding: utf-8 -*-
"""进程体检页：枚举进程、识别可疑进程、结束进程。"""
import threading
import tkinter as tk
from tkinter import messagebox, ttk

from core import logger
from core.process import list_processes, scan_processes, kill_process


class ProcessPage(ttk.Frame):
    def __init__(self, master, theme, app):
        super().__init__(master, style="TFrame")
        self.theme = theme
        self.app = app
        self._scanning = False
        self._build()

    def _build(self):
        header = ttk.Frame(self, style="TFrame")
        header.pack(fill="x", padx=24, pady=(20, 6))
        ttk.Label(header, text="⚙ 进程体检", style="Title.TLabel").pack(side="left")
        self.scan_btn = ttk.Button(header, text="⇧ 扫描可疑进程", style="Accent.TButton",
                                   command=self.scan)
        self.scan_btn.pack(side="right")
        self.kill_btn = ttk.Button(header, text="⛔ 结束选中进程", style="Danger.TButton",
                                   command=self.kill, state="disabled")
        self.kill_btn.pack(side="right", padx=8)

        ttk.Label(self, text="枚举当前运行的进程，并按特征库识别已知恶意/可疑进程。",
                  style="Muted.TLabel").pack(anchor="w", padx=26)

        card = ttk.Frame(self, style="Card.TFrame")
        card.pack(fill="both", expand=True, padx=24, pady=(10, 20))
        cols = ("pid", "name", "path", "threat")
        self.tree = ttk.Treeview(card, columns=cols, show="headings", selectmode="extended")
        for cid, txt, w in (("pid", "PID", 70), ("name", "进程名", 160),
                            ("path", "路径", 460), ("threat", "标记", 220)):
            self.tree.heading(cid, text=txt)
            self.tree.column(cid, width=w, anchor="w")
        vsb = ttk.Scrollbar(card, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True, padx=(12, 0), pady=12)
        vsb.pack(side="right", fill="y", pady=12)
        self.status_var = tk.StringVar(value="尚未扫描")
        ttk.Label(self, textvariable=self.status_var, style="Muted.TLabel").pack(anchor="w", padx=26, pady=(0, 14))

    def scan(self):
        if self._scanning:
            return
        self._scanning = True
        self.scan_btn.config(state="disabled")
        self.status_var.set("正在枚举进程…")
        for i in self.tree.get_children():
            self.tree.delete(i)

        def work():
            count, threats = scan_processes()
            threat_pids = {t["pid"] for t in threats}
            procs = list_processes()
            self.after(0, lambda: self._fill(count, procs, threat_pids, threats))

        threading.Thread(target=work, daemon=True).start()

    def _fill(self, count, procs, threat_pids, threats):
        self._scanning = False
        self.scan_btn.config(state="normal")
        for pid, name, path in procs:
            tag = "threat" if pid in threat_pids else ""
            threat = ""
            for t in threats:
                if t["pid"] == pid:
                    threat = t["threat"]
            self.tree.insert("", "end",
                             values=(pid, name, path, threat),
                             tags=(tag,))
        self.tree.tag_configure("threat", foreground=self.theme["danger"])
        self.status_var.set(f"共 {count} 个进程，发现 {len(threats)} 个可疑进程")
        self.kill_btn.config(state="normal" if threats else "disabled")
        logger.info(f"进程体检完成: {count} 个进程, {len(threats)} 个可疑")

    def kill(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("提示", "请先选择进程")
            return
        pids = []
        for iid in sel:
            pid = int(self.tree.set(iid, "pid"))
            pids.append(pid)
        if not messagebox.askyesno("确认", f"确定要结束选中的 {len(pids)} 个进程吗？"):
            return
        for pid in pids:
            kill_process(pid)
        self.scan()
