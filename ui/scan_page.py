# -*- coding: utf-8 -*-
"""扫描页：路径选择、进度显示、威胁列表与处置（隔离/删除/信任/报告）。"""
import os
import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from core import logger
from core.config import config
from core.quarantine import quarantine
from core.report import generate_report
from core.scanner import engine
from core.signature import file_hashes
from core.whitelist import whitelist

SCAN_MODES = {
    "quick": ("快速扫描", "扫描系统临时目录、下载与桌面等高风险位置"),
    "full": ("全盘扫描", "扫描所有磁盘分区（耗时较长）"),
    "custom": ("自定义扫描", "选择指定目录或文件进行扫描"),
}


class ScanPage(ttk.Frame):
    def __init__(self, master, theme, app, mode="quick"):
        super().__init__(master, style="TFrame")
        self.theme = theme
        self.app = app
        self.mode = mode
        self._q = queue.Queue()
        self._scanning = False
        self._pending_threats = []
        self._build()

    # ---------- 构建 ----------
    def _build(self):
        # 用 grid 布局：结果列表占满剩余空间(weight=1)，底部处置栏固定高度，保证按钮始终可见
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(5, weight=1)

        title, desc = SCAN_MODES[self.mode]
        header = ttk.Frame(self, style="TFrame")
        header.grid(row=0, column=0, sticky="ew", padx=24, pady=(20, 4))
        ttk.Label(header, text=title, style="Title.TLabel").pack(side="left")
        ttk.Label(self, text=desc, style="Muted.TLabel").grid(row=1, column=0, sticky="w", padx=26)

        # 目标选择（自定义）
        self.target_frame = ttk.Frame(self, style="TFrame")
        if self.mode == "custom":
            self.target_frame.grid(row=2, column=0, sticky="ew", padx=24, pady=10)
            ttk.Label(self.target_frame, text="扫描目标:", style="Card.TLabel").pack(side="left")
            self.target_var = tk.StringVar(value=str(config.get("last_custom_target", "")))
            e = ttk.Entry(self.target_frame, textvariable=self.target_var, width=60)
            e.pack(side="left", padx=8, ipady=3)
            ttk.Button(self.target_frame, text="浏览…",
                       command=self._browse).pack(side="left", padx=2)
            ttk.Button(self.target_frame, text="使用测试样本目录",
                       command=self._use_sample).pack(side="left", padx=6)

        # 控制栏
        ctrl = ttk.Frame(self, style="TFrame")
        ctrl.grid(row=3, column=0, sticky="ew", padx=24, pady=8)
        self.start_btn = ttk.Button(ctrl, text="开始扫描", style="Accent.TButton",
                                    command=self.start)
        self.start_btn.pack(side="left")
        self.stop_btn = ttk.Button(ctrl, text="停止", style="Danger.TButton",
                                   command=self.stop, state="disabled")
        self.stop_btn.pack(side="left", padx=8)
        self.export_btn = ttk.Button(ctrl, text="导出报告", style="TButton",
                                     command=self.export_report, state="disabled")
        self.export_btn.pack(side="left", padx=8)

        # 进度区
        prog_card = ttk.Frame(self, style="Card.TFrame")
        prog_card.grid(row=4, column=0, sticky="ew", padx=24, pady=6)
        self.progress = ttk.Progressbar(prog_card, maximum=100)
        self.progress.pack(fill="x", padx=16, pady=(14, 6))
        self.status_var = tk.StringVar(value="就绪")
        self.stat_var = tk.StringVar(value="已扫描 0 个文件")
        ttk.Label(prog_card, textvariable=self.status_var, style="Card.TLabel").pack(anchor="w", padx=16)
        ttk.Label(prog_card, textvariable=self.stat_var, style="Muted.TLabel").pack(anchor="w", padx=16, pady=(0, 12))

        # 结果表格（占满中间剩余空间）
        list_card = ttk.Frame(self, style="Card.TFrame")
        list_card.grid(row=5, column=0, sticky="nsew", padx=24, pady=(8, 8))
        cols = ("level", "det", "threat", "path", "size", "status")
        self.tree = ttk.Treeview(list_card, columns=cols, show="headings", selectmode="extended")
        for cid, txt, w in (
                ("level", "级别", 60), ("det", "检测方式", 90), ("threat", "威胁描述", 240),
                ("path", "文件路径", 380), ("size", "大小", 70), ("status", "状态", 80)):
            self.tree.heading(cid, text=txt)
            self.tree.column(cid, width=w, anchor="w")
        self.tree.tag_configure("high", foreground=self.theme["danger"])
        self.tree.tag_configure("medium", foreground=self.theme["warn"])
        self.tree.tag_configure("low", foreground=self.theme["muted"])
        vsb = ttk.Scrollbar(list_card, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True, padx=(12, 0), pady=12)
        vsb.pack(side="right", fill="y", pady=12)

        # 处置栏（固定高度，始终可见）
        action_card = ttk.Frame(self, style="Card.TFrame")
        action_card.grid(row=6, column=0, sticky="ew", padx=24, pady=(0, 20))
        ttk.Button(action_card, text="隔离选中", style="Accent.TButton",
                   command=lambda: self._handle("quarantine")).pack(side="left", padx=12, pady=10)
        ttk.Button(action_card, text="删除选中", style="Danger.TButton",
                   command=lambda: self._handle("delete")).pack(side="left", padx=4, pady=10)
        ttk.Button(action_card, text="信任选中", style="TButton",
                   command=lambda: self._handle("trust")).pack(side="left", padx=4, pady=10)
        self.threat_count_var = tk.StringVar(value="威胁: 0  提示: 0")
        ttk.Label(action_card, textvariable=self.threat_count_var,
                  style="Accent.TLabel").pack(side="right", padx=16)

        self._poll()

    # ---------- 目标 ----------
    def _browse(self):
        d = filedialog.askdirectory(title="选择扫描目录")
        if d:
            self.target_var.set(d)
            config.set("last_custom_target", d)

    def _use_sample(self):
        from core.config import BASE_DIR
        p = os.path.join(BASE_DIR, "tests", "sample")
        if os.path.isdir(p):
            self.target_var.set(p)
        else:
            messagebox.showinfo("提示", "测试样本目录不存在，请先运行 scripts/make_samples.py")

    # ---------- 扫描控制 ----------
    def _resolve_roots(self):
        if self.mode == "quick":
            return [d for d in config.get("quick_dirs", []) if os.path.isdir(d)]
        if self.mode == "full":
            roots = []
            for drive in range(65, 91):
                d = f"{chr(drive)}:\\"
                if os.path.isdir(d):
                    roots.append(d)
            return roots or ["C:\\"]
        if self.mode == "custom":
            t = self.target_var.get().strip()
            if not t:
                messagebox.showwarning("提示", "请先选择扫描目标")
                return None
            config.set("last_custom_target", t)
            return [t]
        return []

    def start(self):
        if self._scanning:
            return
        roots = self._resolve_roots()
        if roots is None:
            return
        if not roots:
            messagebox.showwarning("提示", "没有可扫描的目录")
            return
        for item in self.tree.get_children():
            self.tree.delete(item)
        self._pending_threats = []
        self.threat_count_var.set("威胁: 0")
        self.export_btn.config(state="disabled")
        self.progress["value"] = 0
        self._last_pct = -1.0
        self.status_var.set("正在准备扫描…")
        self.stat_var.set("正在收集文件列表")
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self._scanning = True

        engine.on_progress = self._cb_progress
        engine.on_threat = self._cb_threat
        engine.on_done = self._cb_done
        engine.start_scan(roots)

    def stop(self):
        if self._scanning:
            engine.stop()
            self.status_var.set("正在停止…")
            self.stop_btn.config(state="disabled")

    # ---------- 回调（后台线程 -> 队列） ----------
    def _cb_progress(self, processed, total, path):
        self._q.put(("progress", processed, total, path))

    def _cb_threat(self, item):
        self._q.put(("threat", item))

    def _cb_done(self, stats):
        self._q.put(("done", stats))

    # ---------- GUI 轮询 ----------
    def _poll(self):
        try:
            while True:
                kind, *args = self._q.get_nowait()
                if kind == "progress":
                    processed, total, path = args
                    self._update_progress(processed, total, path)
                elif kind == "threat":
                    self._add_threat_row(args[0])
                elif kind == "done":
                    self._scan_done(args[0])
        except queue.Empty:
            pass
        self.after(120, self._poll)

    def _update_progress(self, processed, total, path):
        pct = (processed / total * 100) if total else 0
        pct = min(pct, 100.0)
        # 单调保护：进度只前进不后退，杜绝"来回跳"（v1.0.55 修复）
        last = getattr(self, "_last_pct", -1.0)
        if pct < last:
            pct = last
        self._last_pct = pct
        self.progress["value"] = pct
        self.stat_var.set(f"已扫描 {processed}/{total} 个文件")
        base = os.path.basename(path) or path
        self.status_var.set(f"正在扫描: {base}")

    def _add_threat_row(self, item):
        self._pending_threats.append(item)
        size = f"{item.size / 1024:.1f} KB" if item.size > 1024 else f"{item.size} B"
        sev_label = {"high": "恶意", "medium": "可疑", "low": "提示"}.get(item.severity, "可疑")
        tag = item.severity if item.severity in ("high", "medium", "low") else "medium"
        self.tree.insert("", "end", tags=(tag,),
                         values=(sev_label, item.detection, item.threat[:120], item.path, size, item.action))
        n_threat = sum(1 for t in self._pending_threats if t.severity in ("high", "medium"))
        n_hint = len(self._pending_threats) - n_threat
        self.threat_count_var.set(f"威胁: {n_threat}  提示: {n_hint}")

    def _scan_done(self, stats):
        self._scanning = False
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        if self._pending_threats:
            self.export_btn.config(state="normal")
        elapsed = stats.get("elapsed", 0)
        threats = stats.get("threats", 0)
        hints = stats.get("hints", 0)
        if hints:
            self.status_var.set(f"扫描完成，用时 {elapsed} 秒，发现 {threats} 项威胁 / {hints} 项低风险提示")
        else:
            self.status_var.set(f"扫描完成，用时 {elapsed} 秒，发现 {threats} 项威胁")
        self.stat_var.set(f"已扫描 {stats.get('scanned', 0)} 个文件")
        config.bump_stats(scanned=stats.get("scanned", 0), threats=stats.get("threats", 0))
        config.set("last_scan_time", __import__("time").strftime("%Y-%m-%d %H:%M:%S"))
        self.app.refresh_dashboard()

    # ---------- 处置 ----------
    def _selected_items(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("提示", "请先在结果列表中选择要处理的威胁")
            return None
        idx = [self.tree.index(i) for i in sel]
        return [self._pending_threats[i] for i in idx]

    def _handle(self, action):
        items = self._selected_items()
        if items is None:
            return
        if action == "delete":
            if not messagebox.askyesno("确认", f"确定要彻底删除选中的 {len(items)} 个文件吗？\n此操作不可恢复！"):
                return
        for item in items:
            status = self._do_action(action, item)
            self._mark_status(item, status)

    def _do_action(self, action, item):
        if action == "quarantine":
            ok, res = quarantine.quarantine_file(
                item.path, threat=item.threat, detection=item.detection,
                md5=item.md5, sha256=item.sha256, size=item.size)
            if ok:
                item.action = "已隔离"
                return "已隔离"
            return f"失败: {res}"
        if action == "delete":
            try:
                os.remove(item.path)
                item.action = "已删除"
                logger.warning(f"已删除威胁文件: {item.path}")
                return "已删除"
            except Exception as e:
                return f"失败: {e}"
        if action == "trust":
            if not item.md5:
                item.md5, _ = file_hashes(item.path)
            ok, msg = whitelist.add(item.path, item.md5, reason="用户信任")
            if ok:
                item.action = "已信任"
                return "已信任"
            return msg
        return ""

    def _mark_status(self, item, status):
        for i, ch in enumerate(self.tree.get_children()):
            if self._pending_threats[i] is item:
                self.tree.set(ch, "status", status)
                break

    def export_report(self):
        if not self._pending_threats:
            return
        roots = ",".join(self._resolve_roots() or ["-"])[:80]
        stats = {"scanned": config.get("stats", {}).get("scanned", 0),
                 "threats": len(self._pending_threats), "elapsed": 0}
        html_path, txt_path = generate_report(
            self.mode, roots, stats, self._pending_threats)
        messagebox.showinfo("报告已生成", f"HTML: {html_path}\nTXT:  {txt_path}")
