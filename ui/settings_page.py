# -*- coding: utf-8 -*-
"""设置页：实时监控、扫描选项、白名单、特征库、主题。"""
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from core import logger
from core.config import config
from core.monitor import monitor
from core.signature import file_hashes, signature_db
from core.whitelist import whitelist


class SettingsPage(ttk.Frame):
    def __init__(self, master, theme, app):
        super().__init__(master, style="TFrame")
        self.theme = theme
        self.app = app
        self._build()

    # ---------- 构建 ----------
    def _build(self):
        ttk.Label(self, text="⚙ 设置", style="Title.TLabel").pack(anchor="w", padx=24, pady=(20, 4))
        ttk.Label(self, text="实时监控、扫描行为、白名单与特征库管理。",
                  style="Muted.TLabel").pack(anchor="w", padx=26)

        container = ttk.Frame(self, style="TFrame")
        container.pack(fill="both", expand=True, padx=24, pady=10)

        # 左列
        left = ttk.Frame(container, style="TFrame")
        left.pack(side="left", fill="both", expand=True, padx=(0, 8))
        self._build_monitor(left)
        self._build_scan_opts(left)
        self._build_whitelist(left)

        # 右列
        right = ttk.Frame(container, style="TFrame")
        right.pack(side="right", fill="both", expand=True, padx=(8, 0))
        self._build_signature(right)
        self._build_general(right)

    def _card(self, parent, title):
        c = ttk.Frame(parent, style="Card.TFrame")
        c.pack(fill="x", pady=(0, 12))
        ttk.Label(c, text=title, style="H2.TLabel").pack(anchor="w", padx=16, pady=(12, 2))
        body = ttk.Frame(c, style="Card.TFrame")
        body.pack(fill="x", padx=12, pady=(0, 12))
        return body

    # ---------- 实时监控 ----------
    def _build_monitor(self, parent):
        body = self._card(parent, "实时防护")
        self.monitor_var = tk.BooleanVar(value=config.get("realtime_monitor", True))
        ttk.Checkbutton(body, text="启用实时防护（后台常驻，自动扫描新增/修改文件）",
                        variable=self.monitor_var, command=self._toggle_monitor).pack(anchor="w", pady=2)

        scope_row = ttk.Frame(body, style="Card.TFrame")
        scope_row.pack(fill="x", pady=(6, 2))
        ttk.Label(scope_row, text="监控范围:", style="Muted.TLabel").pack(side="left")
        self.scope_var = tk.StringVar(value=config.get("realtime_scope", "full"))
        for val, label in (("full", "全盘防护（推荐）"), ("custom", "自定义目录")):
            ttk.Radiobutton(scope_row, text=label, value=val, variable=self.scope_var,
                            command=self._save_scope).pack(side="left", padx=6)

        # 自定义目录（仅 custom 模式需要）
        ttk.Label(body, text="自定义监控目录（仅在上方选\"自定义目录\"时使用）:",
                  style="Muted.TLabel").pack(anchor="w", pady=(6, 2))
        row = ttk.Frame(body, style="Card.TFrame")
        row.pack(fill="x")
        self.dir_list = tk.Listbox(row, height=3, bg=self.theme["entry_bg"],
                                   fg=self.theme["text"], relief="flat",
                                   highlightthickness=1, highlightbackground=self.theme["border"])
        self.dir_list.pack(side="left", fill="x", expand=True)
        btn_col = ttk.Frame(row, style="Card.TFrame")
        btn_col.pack(side="left", padx=6)
        ttk.Button(btn_col, text="添加", style="TButton", command=self._add_dir).pack(pady=1)
        ttk.Button(btn_col, text="移除", style="TButton", command=self._remove_dir).pack(pady=1)
        for d in config.get("realtime_dirs", []):
            self.dir_list.insert("end", d)
        ttk.Label(body, text="提示：全盘防护基于文件系统事件驱动，空闲时几乎不占用 CPU。",
                  style="Muted.TLabel").pack(anchor="w", pady=(4, 0))

    def _save_scope(self):
        config.set("realtime_scope", self.scope_var.get())
        # 切换范围后若监控运行中，自动以新范围重启
        if monitor.running:
            monitor.stop()
            monitor.on_threat = self.app.monitor_threat_cb
            ok, msg = monitor.start()
            self.app.show_notify("实时防护", msg)
        self.app.show_notify("监控范围", "全盘防护" if self.scope_var.get() == "full" else "自定义目录")

    def _toggle_monitor(self):
        on = self.monitor_var.get()
        if on:
            dirs = None
            if config.get("realtime_scope", "full") == "custom":
                dirs = list(self.dir_list.get(0, "end"))
                if not dirs:
                    messagebox.showinfo("提示", "请先添加要监控的目录，或改用全盘防护")
                    self.monitor_var.set(False)
                    return
                config.set("realtime_dirs", dirs)
            monitor.on_threat = self.app.monitor_threat_cb
            ok, msg = monitor.start(dirs=dirs)
            if not ok:
                messagebox.showerror("启动失败", msg)
                self.monitor_var.set(False)
                return
            config.set("realtime_monitor", True)
            self.app.show_notify("实时防护已启动", msg)
        else:
            monitor.stop()
            config.set("realtime_monitor", False)
            self.app.show_notify("实时防护已关闭", "")
        self.app.refresh_dashboard()

    def _add_dir(self):
        d = filedialog.askdirectory(title="选择监控目录")
        if d and d not in list(self.dir_list.get(0, "end")):
            self.dir_list.insert("end", d)

    def _remove_dir(self):
        sel = self.dir_list.curselection()
        for i in reversed(sel):
            self.dir_list.delete(i)

    # ---------- 扫描选项 ----------
    def _build_scan_opts(self, parent):
        body = self._card(parent, "扫描选项")
        self.heur_var = tk.BooleanVar(value=config.get("deep_heuristic", True))
        ttk.Checkbutton(body, text="深度启发式扫描（分析脚本内容，识别恶意行为）",
                        variable=self.heur_var, command=self._save_opts).pack(anchor="w", pady=2)
        self.arch_var = tk.BooleanVar(value=config.get("scan_archives", False))
        ttk.Checkbutton(body, text="扫描压缩包内的可执行文件（zip）",
                        variable=self.arch_var, command=self._save_opts).pack(anchor="w", pady=2)

        perf_row = ttk.Frame(body, style="Card.TFrame")
        perf_row.pack(fill="x", pady=(8, 2))
        ttk.Label(perf_row, text="扫描性能(CPU占用):", style="Muted.TLabel").pack(side="left")
        self.perf_var = tk.StringVar(value=config.get("scan_perf_mode", "balanced"))
        for val, label in (("low", "低占用"), ("balanced", "均衡"), ("high", "高速")):
            ttk.Radiobutton(perf_row, text=label, value=val, variable=self.perf_var,
                            command=self._save_perf).pack(side="left", padx=6)
        ttk.Label(body, text="低占用=单线程+节流(CPU约24%)；均衡=2线程(默认,CPU约43%)；高速=2线程(CPU约110%,最快)",
                  style="Muted.TLabel").pack(anchor="w", pady=(0, 2))

        size_row = ttk.Frame(body, style="Card.TFrame")
        size_row.pack(fill="x", pady=(8, 2))
        ttk.Label(size_row, text="跳过内容分析的文件大小上限 (MB):", style="Muted.TLabel").pack(side="left")
        self.size_var = tk.StringVar(value=str(config.get("max_file_mb", 100)))
        e = ttk.Entry(size_row, textvariable=self.size_var, width=8)
        e.pack(side="left", padx=8)
        ttk.Button(size_row, text="保存", style="TButton", command=self._save_size).pack(side="left")

    def _save_perf(self):
        config.set("scan_perf_mode", self.perf_var.get())
        self.app.show_notify("已应用", f"扫描性能: {self.perf_var.get()}")

    def _save_opts(self):
        config.set("deep_heuristic", self.heur_var.get())
        config.set("scan_archives", self.arch_var.get())

    def _save_size(self):
        try:
            v = max(1, int(self.size_var.get()))
            config.set("max_file_mb", v)
            self.app.show_notify("设置已保存", f"文件大小上限 {v} MB")
        except ValueError:
            messagebox.showwarning("无效输入", "请输入整数")

    # ---------- 白名单 ----------
    def _build_whitelist(self, parent):
        body = self._card(parent, "白名单（信任列表）")
        self.wl_list = tk.Listbox(body, height=5, bg=self.theme["entry_bg"],
                                  fg=self.theme["text"], relief="flat",
                                  highlightthickness=1, highlightbackground=self.theme["border"])
        self.wl_list.pack(fill="x")
        row = ttk.Frame(body, style="Card.TFrame")
        row.pack(fill="x", pady=(6, 0))
        ttk.Button(row, text="添加信任文件", style="TButton", command=self._add_whitelist).pack(side="left")
        ttk.Button(row, text="移除选中", style="TButton", command=self._remove_whitelist).pack(side="left", padx=6)
        self._refresh_whitelist()

    def _refresh_whitelist(self):
        self.wl_list.delete(0, "end")
        for it in whitelist.items:
            self.wl_list.insert("end", it.get("path", ""))

    def _add_whitelist(self):
        f = filedialog.askopenfilename(title="选择要信任的文件")
        if f:
            md5, _ = file_hashes(f)
            ok, msg = whitelist.add(f, md5, reason="手动添加")
            self._refresh_whitelist()
            self.app.show_notify("白名单", msg)

    def _remove_whitelist(self):
        sel = self.wl_list.curselection()
        for i in reversed(sel):
            path = self.wl_list.get(i)
            whitelist.remove(path)
        self._refresh_whitelist()

    # ---------- 特征库 ----------
    def _build_signature(self, parent):
        body = self._card(parent, "特征库")
        self.sig_info = tk.StringVar(value=f"共 {signature_db.count} 条 · 版本 {signature_db.version}")
        ttk.Label(body, textvariable=self.sig_info, style="Muted.TLabel").pack(anchor="w", pady=2)
        ttk.Label(body, text="手动添加文件哈希为特征（用于标记已知恶意文件）:",
                  style="Muted.TLabel").pack(anchor="w", pady=(6, 2))
        row = ttk.Frame(body, style="Card.TFrame")
        row.pack(fill="x")
        self.hash_file_var = tk.StringVar()
        ttk.Entry(row, textvariable=self.hash_file_var, width=30).pack(side="left")
        ttk.Button(row, text="选择文件", style="TButton", command=self._pick_hash_file).pack(side="left", padx=4)
        ttk.Button(row, text="添加特征", style="Accent.TButton", command=self._add_signature).pack(side="left", padx=4)

    def _pick_hash_file(self):
        f = filedialog.askopenfilename(title="选择要标记为恶意特征的文件")
        if f:
            self.hash_file_var.set(f)

    def _add_signature(self):
        f = self.hash_file_var.get().strip()
        if not f:
            messagebox.showinfo("提示", "请先选择文件")
            return
        md5, sha = file_hashes(f)
        name = __import__("os").path.basename(f)
        ok, msg = signature_db.add(name, md5=md5, sha256=sha, vtype="user", desc="用户手动添加")
        self.app.show_notify("特征库", msg)
        if ok:
            self.sig_info.set(f"共 {signature_db.count} 条 · 版本 {signature_db.version}")
            logger.info(f"用户添加特征: {name} ({md5})")

    # ---------- 通用 ----------
    def _build_general(self, parent):
        body = self._card(parent, "外观")
        ttk.Label(body, text="界面主题:", style="Muted.TLabel").pack(anchor="w")
        self.theme_var = tk.StringVar(value=config.get("theme", "dark"))
        row = ttk.Frame(body, style="Card.TFrame")
        row.pack(fill="x", pady=4)
        for name, label in (("dark", "深色"), ("light", "浅色")):
            ttk.Radiobutton(row, text=label, value=name, variable=self.theme_var,
                            command=self._apply_theme).pack(side="left", padx=8)
        ttk.Label(body, text="扫描统计", style="H2.TLabel").pack(anchor="w", pady=(14, 2))
        st = config.get("stats", {})
        ttk.Label(body, text=f"累计扫描 {st.get('scanned', 0)} 个文件 · 发现威胁 {st.get('threats', 0)} 个",
                  style="Muted.TLabel").pack(anchor="w")

    def _apply_theme(self):
        config.set("theme", self.theme_var.get())
        # v1.0.55：不再热切换主题（旧版热切换会导致界面卡死），改为提示重启生效
        messagebox.showinfo(
            "主题切换",
            f"已保存为「{'深色' if self.theme_var.get() == 'dark' else '浅色'}」主题。\n\n"
            "主题需要在重启应用后生效，请关闭并重新打开玄盾卫士。")
