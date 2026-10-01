#!/usr/bin/env python3
"""
gui.py — Tkinter front-end (modern dark theme). Auto-discovers attack modules
from modules/ and builds the list from them. GUI never freezes (worker thread +
queue). Full raw logs + JSON/TXT/CSV go to evidence/run_<ts>/.

Run:  python3 gui.py
"""

import os
import queue
import subprocess
import threading
import tkinter as tk
from tkinter import ttk, messagebox

import core
import loader

_EGRESS_PROBE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "additional", "mygovnet_egress_probe.py")

# module ids unticked by default on startup (still selectable) — everything
# else is pre-selected so a run only needs "confirm ROE" + "RUN". PetitPotam
# needs root + Responder running; Kerberoast/noPac are the two most likely to
# want a deliberate opt-in (noisier/slower AD exploitation chains).
NOT_SELECTED_BY_DEFAULT = {"petitpotam", "kerberoast", "nopac"}

# ---- palette (modern dark) ------------------------------------------------
BG     = "#181a24"   # window
PANEL  = "#20222f"   # cards / panels
SURF   = "#2a2d3d"   # inputs
SURF2  = "#343850"   # hover / borders
FG     = "#e8e9f0"   # primary text
MUTED  = "#8b90a6"   # secondary text
ACCENT = "#7c6cf0"   # brand
OKC    = "#3fb950"   # success
BLUEC  = "#4aa3ff"   # blocked
WARNC  = "#e3a008"   # prereq / auth-failed
ERRC   = "#f85149"   # error / no-result
INFOC  = "#39c5cf"   # headers / info
NEWC   = "#c86bff"   # "NEW" badge

MONO = ("TkFixedFont", 10)

# Purple-team semantics: a result that means the attack GOT THROUGH the SD-WAN is
# a FINDING -> red; a result that means the control STOPPED it is good -> green.
DETC = "#db6d28"               # orange — passed but detected (partial win)
STATUS_COLORS = {
    "SUCCESS":        ERRC,    # attack passed undetected -> FINDING (red)
    "PASSED":         ERRC,    # (dual-path) same
    "DETECTED":       DETC,    # passed the boundary but the SOC alerted (orange)
    "BLOCKED":        OKC,     # control stopped it (filtered/dropped) -> good (green)
    "NO-SERVICE":     BLUEC,   # port closed/refused — service absent, NOT a block
    "AUTH-FAILED":    WARNC,   # bad creds, not a control result
    "NO-RESULT":      WARNC,   # inconclusive — review
    "SKIPPED":        MUTED,   # module did nothing (n/a or unconfigured) — not a result
    "PREREQ-MISSING": MUTED,   # skipped (tooling/priv)
}


def _apply_theme(root):
    """Best-effort modern dark theme; never breaks the app if unavailable."""
    try:
        root.configure(bg=BG)
        st = ttk.Style(root)
        try:
            st.theme_use("clam")
        except tk.TclError:
            pass
        st.configure(".", background=BG, foreground=FG, fieldbackground=SURF,
                     bordercolor=SURF2, lightcolor=SURF2, darkcolor=BG,
                     focuscolor=ACCENT, insertcolor=FG)
        st.configure("TFrame", background=BG)
        st.configure("Card.TFrame", background=PANEL)
        st.configure("TLabel", background=BG, foreground=FG)
        st.configure("Card.TLabel", background=PANEL, foreground=FG)
        st.configure("Muted.TLabel", background=BG, foreground=MUTED)
        st.configure("CardMuted.TLabel", background=PANEL, foreground=MUTED)
        st.configure("Warn.TLabel", background=BG, foreground=WARNC)
        st.configure("Err.TLabel", background=BG, foreground=ERRC)
        st.configure("H1.TLabel", background=BG, foreground=FG,
                     font=("TkDefaultFont", 15, "bold"))
        st.configure("Sub.TLabel", background=BG, foreground=MUTED,
                     font=("TkDefaultFont", 9))
        st.configure("Cat.TLabel", background=PANEL, foreground=INFOC,
                     font=("TkDefaultFont", 9, "bold"))
        st.configure("TLabelframe", background=BG, bordercolor=SURF2)
        st.configure("TLabelframe.Label", background=BG, foreground=ACCENT,
                     font=("TkDefaultFont", 10, "bold"))
        st.configure("TButton", background=SURF, foreground=FG, borderwidth=0, padding=7)
        st.map("TButton", background=[("active", SURF2), ("pressed", ACCENT)])
        st.configure("Accent.TButton", background=ACCENT, foreground="#ffffff",
                     font=("TkDefaultFont", 10, "bold"), padding=8)
        st.map("Accent.TButton", background=[("active", "#9385f4"), ("pressed", "#6a5be0")])
        st.configure("Stop.TButton", background="#4a2532", foreground=FG, padding=8)
        st.map("Stop.TButton", background=[("active", ERRC)])
        st.configure("TEntry", fieldbackground=SURF, foreground=FG, insertcolor=FG,
                     bordercolor=SURF2, padding=3)
        st.configure("TSpinbox", fieldbackground=SURF, foreground=FG, arrowcolor=FG, padding=3)
        st.configure("Card.TCheckbutton", background=PANEL, foreground=FG)
        st.map("Card.TCheckbutton", background=[("active", PANEL)])
        st.configure("TCheckbutton", background=BG, foreground=FG)
        st.map("TCheckbutton", background=[("active", BG)])
        st.configure("Treeview", background=PANEL, fieldbackground=PANEL, foreground=FG,
                     rowheight=24, borderwidth=0)
        st.configure("Treeview.Heading", background=BG, foreground=ACCENT,
                     font=("TkDefaultFont", 9, "bold"))
        st.map("Treeview", background=[("selected", SURF2)])
        st.configure("TProgressbar", background=ACCENT, troughcolor=SURF, borderwidth=0)
    except Exception:
        pass


class HarnessGUI:
    def __init__(self, root):
        self.root = root
        root.title("Control Validation Harness")
        root.geometry("1240x860")
        root.minsize(980, 680)
        _apply_theme(root)

        self.modules = loader.discover()
        self.q = queue.Queue()
        self.runner = None
        self.vars = {}          # id -> (BooleanVar, module)
        self.port_vars = {}     # id -> StringVar (port_customizable modules)

        self._build_header()
        self._build_main_split()
        self.root.after(100, self._drain)

    # ----- header ------------------------------------------------------
    def _build_header(self):
        h = ttk.Frame(self.root); h.pack(fill="x", padx=14, pady=(12, 2))
        ttk.Label(h, text="Control Validation Harness", style="H1.TLabel").pack(anchor="w")
        ttk.Label(h, text="Breach & Attack Simulation · MITRE ATT&CK-mapped · "
                          f"{len(self.modules)} modules discovered",
                  style="Sub.TLabel").pack(anchor="w")

    # ----- config ------------------------------------------------------
    def _build_config(self, parent):
        f = ttk.LabelFrame(parent, text="Target & run")
        f.pack(fill="x", padx=12, pady=8)
        pad = dict(padx=6, pady=6)

        # one short row of inputs; everything with its own hint/long label
        # gets its own row below — this panel now lives in a ~70%-width
        # column (not the full window), so packing long hints onto the same
        # row as a field used to clip them off the edge.
        ttk.Label(f, text="Target IP / host").grid(row=0, column=0, sticky="w", **pad)
        self.target = ttk.Entry(f, width=20)
        self.target.grid(row=0, column=1, sticky="w", **pad)

        ttk.Label(f, text="Iterations").grid(row=0, column=2, sticky="e", **pad)
        self.iterations = ttk.Spinbox(f, from_=1, to=20, width=5)
        self.iterations.set(1)
        self.iterations.grid(row=0, column=3, sticky="w", **pad)

        ttk.Label(f, text="Workers").grid(row=1, column=0, sticky="w", **pad)
        self.workers = ttk.Spinbox(f, from_=1, to=16, width=5)
        self.workers.set(core.RECOMMENDED_WORKERS)
        self.workers.grid(row=1, column=1, sticky="w", **pad)
        ttk.Label(f, text=f"(recommended {core.RECOMMENDED_WORKERS}; DoS/brute always serial)",
                  style="Muted.TLabel").grid(row=1, column=2, columnspan=2, sticky="w", **pad)

        # black-box vs white-box posture (both run everything; recorded + announced)
        ttk.Label(f, text="Mode").grid(row=2, column=0, sticky="w", **pad)
        self.mode_var = tk.StringVar(value="blackbox")
        mf = ttk.Frame(f); mf.grid(row=2, column=1, columnspan=3, sticky="w", padx=6)
        ttk.Radiobutton(mf, text="Black-box (not whitelisted)", value="blackbox",
                        variable=self.mode_var).pack(side="left")
        ttk.Radiobutton(mf, text="White-box (whitelisted)", value="whitebox",
                        variable=self.mode_var).pack(side="left", padx=(12, 0))
        ttk.Label(f, text="run both, then compare: PASSED in white-box but BLOCKED "
                          "in black-box = control working",
                  style="Muted.TLabel").grid(row=3, column=0, columnspan=4, sticky="w",
                                             padx=6, pady=(0, 2))

        # USS runtime options: active establishment + egress source binding
        # (its own row — the checkbox label alone is long enough to clip
        # whatever followed it on a 70%-width panel)
        self.active_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(f, text="Active establishment (build real tunnels/pivots/exfil — needs config.json)",
                        variable=self.active_var).grid(row=4, column=0, columnspan=4, sticky="w",
                                                       padx=6, pady=(4, 2))
        sf = ttk.Frame(f); sf.grid(row=5, column=0, columnspan=4, sticky="w", padx=6, pady=(0, 2))
        ttk.Label(sf, text="Source IP").pack(side="left")
        self.source_entry = ttk.Entry(sf, width=16)
        self.source_entry.pack(side="left", padx=(4, 6))
        ttk.Label(sf, text="(bind egress — DC foothold / VRF)",
                  style="Muted.TLabel").pack(side="left")

        # Cloud target: SMB/RPC are DNAT'd to alternate high ports (ISPs block
        # outbound 445). Ticking this maps 445->SMB and 135->RPC for the entered
        # target so the impacket modules (dcsync/psexec/wmiexec/nopac/sama/petit)
        # reach the forwarded ports (same as modules/_portpatch.py, but per-run).
        cf = ttk.Frame(f); cf.grid(row=6, column=0, columnspan=4, sticky="w", padx=6, pady=(2, 2))
        self.cloud_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(cf, text="Cloud target (NAT'd SMB/RPC)", variable=self.cloud_var,
                        command=self._toggle_cloud_ports).pack(side="left")
        ttk.Label(cf, text="SMB").pack(side="left", padx=(8, 2))
        self.smb_port = tk.StringVar(value="4445")
        self._smb_entry = ttk.Entry(cf, textvariable=self.smb_port, width=6, state="disabled")
        self._smb_entry.pack(side="left")
        ttk.Label(cf, text="RPC").pack(side="left", padx=(8, 2))
        self.rpc_port = tk.StringVar(value="1135")
        self._rpc_entry = ttk.Entry(cf, textvariable=self.rpc_port, width=6, state="disabled")
        self._rpc_entry.pack(side="left")
        ttk.Label(cf, text="(445→SMB, 135→RPC for AD modules)",
                  style="Muted.TLabel").pack(side="left", padx=(6, 0))

        self._priv_frame = f
        self._priv_label = ttk.Label(f, text="", style="Muted.TLabel")
        self._priv_label.grid(row=7, column=0, columnspan=4, sticky="w", padx=6, pady=(4, 2))
        self._unlock_btn = ttk.Button(f, text="Unlock sudo", command=self._unlock_sudo)
        self._unlock_btn.grid(row=8, column=0, columnspan=2, sticky="w", padx=6, pady=(0, 6))
        self._refresh_privilege()

    def _refresh_privilege(self):
        ps = core.privilege_status(self.modules)
        if not ps["needs_root_modules"]:
            self._priv_label.grid_remove(); self._unlock_btn.grid_remove(); return
        icon = "✓" if (ps["root"] or ps["sudo_nopasswd"]) else ("⚠" if not ps["sudo_present"] else "ℹ")
        style = ("Muted.TLabel" if (ps["root"] or ps["sudo_nopasswd"])
                 else "Err.TLabel" if not ps["sudo_present"] else "Warn.TLabel")
        self._priv_label.configure(text=f"{icon} Privilege: {ps['how']}", style=style)
        self._priv_label.grid()
        if ps["can_unlock"]:
            self._unlock_btn.grid()
        else:
            self._unlock_btn.grid_remove()

    def _unlock_sudo(self):
        from tkinter import simpledialog
        pw = simpledialog.askstring("Unlock sudo",
                                    "Enter your sudo password (cached ~15 min, not stored):",
                                    show="*", parent=self.root)
        if pw is None:
            return
        ok, msg = core.sudo_unlock(pw)
        del pw
        (messagebox.showinfo if ok else messagebox.showerror)("Unlock sudo", msg)
        self._refresh_privilege()

    # ----- attacks (aligned grid table) --------------------------------
    def _build_attacks(self, parent):
        outer = ttk.LabelFrame(parent, text="Attacks")
        outer.pack(fill="both", expand=True)
        canvas = tk.Canvas(outer, bg=PANEL, highlightthickness=0)
        vsb = ttk.Scrollbar(outer, orient="vertical", command=canvas.yview)
        hsb = ttk.Scrollbar(outer, orient="horizontal", command=canvas.xview)
        inner = ttk.Frame(canvas, style="Card.TFrame")
        inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        win = canvas.create_window((0, 0), window=inner, anchor="nw")
        # Only ever GROW the inner frame to fill extra canvas width — never
        # shrink it below what its columns actually need. Forcing it down to
        # canvas width unconditionally (the old behaviour) squeezed the
        # checkbox+name column (minsize=0, the only flexible one) to ~0
        # width whenever this panel got narrower than the fixed columns'
        # combined width — the checkboxes visually vanished. Now a narrow
        # panel scrolls horizontally instead of hiding them.
        def _resize_inner(e):
            canvas.itemconfigure(win, width=max(e.width, inner.winfo_reqwidth()))
        canvas.bind("<Configure>", _resize_inner)
        canvas.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        canvas.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        outer.rowconfigure(0, weight=1); outer.columnconfigure(0, weight=1)

        # mouse-wheel scrolling over the attacks list (45+ modules) — cross-platform
        def _wheel(e):
            delta = 1 if getattr(e, "num", None) == 5 else -1 if getattr(e, "num", None) == 4 \
                else (-1 if e.delta > 0 else 1)
            canvas.yview_scroll(delta, "units")
        for seq in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
            canvas.bind_all(seq, lambda e: _wheel(e) if self._over(canvas, e) else None)

        # fixed grid columns so every row lines up: attack | badge | MITRE | tactic | port | fix
        # column 0 (checkbox+name) gets a real floor (not 0) so it can't be
        # squeezed invisible when this panel is narrow — see _resize_inner.
        for col, w in ((0, 220), (1, 46), (2, 130), (3, 130), (4, 78), (5, 90)):
            inner.grid_columnconfigure(col, minsize=w, weight=(1 if col == 0 else 0))

        def hcell(text, c, r):
            tk.Label(inner, text=text, bg=PANEL, fg=MUTED,
                     font=("TkDefaultFont", 8, "bold")).grid(row=r, column=c, sticky="w",
                                                             padx=8, pady=(2, 4))
        # header
        hcell("ATTACK", 0, 0); hcell("", 1, 0); hcell("MITRE", 2, 0)
        hcell("TACTIC", 3, 0); hcell("PORT", 4, 0); hcell("FIX", 5, 0)

        r = 1
        current_cat = None
        for m in self.modules:
            meta = m.META
            if meta["category"] != current_cat:
                current_cat = meta["category"]
                tk.Label(inner, text=f"  {current_cat}", bg=PANEL, fg=INFOC,
                         font=("TkDefaultFont", 9, "bold")).grid(
                             row=r, column=0, columnspan=6, sticky="w", padx=4, pady=(9, 2))
                r += 1
            var = tk.BooleanVar(value=meta["id"] not in NOT_SELECTED_BY_DEFAULT)
            self.vars[meta["id"]] = (var, m)
            ttk.Checkbutton(inner, text=meta["name"], variable=var,
                            style="Card.TCheckbutton").grid(row=r, column=0, sticky="w", padx=(10, 6))
            if meta.get("added"):
                tk.Label(inner, text="NEW", bg=NEWC, fg="#fff",
                         font=("TkDefaultFont", 7, "bold"), padx=4).grid(row=r, column=1, sticky="w")
            tk.Label(inner, text=", ".join(meta.get("mitre", [])), bg=PANEL, fg=INFOC,
                     font=("TkDefaultFont", 8)).grid(row=r, column=2, sticky="w", padx=6)
            tk.Label(inner, text=meta.get("tactic", ""), bg=PANEL, fg=MUTED,
                     font=("TkDefaultFont", 8)).grid(row=r, column=3, sticky="w", padx=6)
            if meta.get("port_customizable"):
                default = next((p for pr, p in
                                ((s if isinstance(s, (list, tuple)) else ("tcp", s))
                                 for s in meta.get("ports", [])) if pr in ("tcp", "udp")), "")
                pv = tk.StringVar(value=str(default))
                self.port_vars[meta["id"]] = pv
                ttk.Entry(inner, textvariable=pv, width=6).grid(row=r, column=4, sticky="w", padx=6)
            tk.Label(inner, text=meta.get("fix", ""), bg=PANEL, fg=MUTED,
                     font=("TkDefaultFont", 8)).grid(row=r, column=5, sticky="w", padx=6)
            r += 1

    # ----- controls (two rows so nothing crowds/truncates) -------------
    def _build_controls(self, parent):
        # row 1 — selection & tools
        f1 = ttk.Frame(parent); f1.pack(fill="x", padx=12, pady=(4, 0))
        for txt, cmd in (("Select all", lambda: self._all(True)),
                         ("Clear", lambda: self._all(False)),
                         ("Original set", lambda: self._select_group(False)),
                         ("Added set", lambda: self._select_group(True)),
                         ("Preflight + recon", self._preflight),
                         ("Egress probe", self._egress_probe)):
            ttk.Button(f1, text=txt, command=cmd).pack(side="left", padx=(0, 6))
        # row 2 — RoE gate + RUN/STOP
        f2 = ttk.Frame(parent); f2.pack(fill="x", padx=12, pady=(4, 2))
        self.roe = tk.BooleanVar(value=False)
        ttk.Checkbutton(f2, text="Rules-of-engagement confirmed (written authorisation on file)",
                        variable=self.roe).pack(side="left")
        self.run_btn = ttk.Button(f2, text="▶ RUN", style="Accent.TButton", command=self._start)
        self.run_btn.pack(side="right")
        self.stop_btn = ttk.Button(f2, text="■ STOP", style="Stop.TButton",
                                   command=self._stop, state="disabled")
        self.stop_btn.pack(side="right", padx=6)
        self.progress = ttk.Progressbar(parent, mode="determinate")
        self.progress.pack(fill="x", padx=12, pady=(2, 6))

    def _build_main_split(self):
        # left column (plain stack, top to bottom): Target & run, the
        # RUN/STOP controls, then Attacks filling the rest. Right column
        # (resizable via a draggable sash): Live output on top, Status
        # below it — both columns start at the very top of the window, side
        # by side, so Live output/Status aren't squeezed below the config
        # panel the way they used to be.
        outer = ttk.PanedWindow(self.root, orient="horizontal")
        outer.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        left = ttk.Frame(outer)
        outer.add(left, weight=1)
        self._build_config(left)
        self._build_controls(left)
        attacks_frame = ttk.Frame(left)
        attacks_frame.pack(fill="both", expand=True, padx=0, pady=(4, 0))
        self._build_attacks(attacks_frame)

        right = ttk.PanedWindow(outer, orient="vertical")
        outer.add(right, weight=1)

        live_frame = ttk.Frame(right)
        right.add(live_frame, weight=2)
        self._build_live_output(live_frame)

        status_frame = ttk.Frame(right)
        right.add(status_frame, weight=1)
        self._build_status(status_frame)

        # PanedWindow `weight` only governs how resize *deltas* are shared —
        # it does not set the initial sash position, so without this the
        # first pane added (Live output) can render at ~0 height. Force a
        # sensible starting split once real geometry is known.
        def _set_initial_sashes():
            self.root.update_idletasks()
            outer.sashpos(0, int(self.root.winfo_width() * 0.70))   # left 70% / right 30%
            right.sashpos(0, int(right.winfo_height() * 0.62))
        self.root.after(50, _set_initial_sashes)

    def _build_status(self, parent):
        left = ttk.LabelFrame(parent, text="Status")
        left.pack(fill="both", expand=True)

        # legend (stacked so it never truncates) — colour semantics
        leg = ttk.Frame(left, style="Card.TFrame"); leg.pack(fill="x", padx=6, pady=(4, 4))
        for dot, col, txt in ((("●"), ERRC, "PASSED — got through undetected (finding)"),
                              (("●"), DETC, "DETECTED — passed but SOC alerted"),
                              (("●"), OKC, "BLOCKED — filtered/dropped by control (good)"),
                              (("●"), BLUEC, "NO-SERVICE — port closed, not a block"),
                              (("●"), WARNC, "NO-RESULT / AUTH — review"),
                              (("●"), MUTED, "SKIPPED / PREREQ-MISSING — not run")):
            rowf = ttk.Frame(leg, style="Card.TFrame"); rowf.pack(anchor="w", fill="x")
            tk.Label(rowf, text=dot, fg=col, bg=PANEL).pack(side="left")
            tk.Label(rowf, text=txt, fg=MUTED, bg=PANEL,
                     font=("TkDefaultFont", 8)).pack(side="left")

        # tree + BOTH scrollbars in a grid frame (packing the scrollbar after an
        # expanding tree squeezes it to zero width — the old "can't scroll" bug).
        tf = ttk.Frame(left); tf.pack(fill="both", expand=True, padx=2, pady=2)
        cols = ("no", "mode", "dir", "cat", "attack", "iter", "result", "mitre", "cwe")
        self.status_tree = ttk.Treeview(tf, columns=cols, show="headings", height=18)
        self._sort_state = {}   # col -> last sort was descending
        # click any heading to sort by that column (toggles asc/desc)
        for c, t, w, a in (("no", "#", 34, "center"), ("mode", "M", 30, "center"),
                           ("dir", "Dir", 38, "center"), ("cat", "Category", 118, "w"),
                           ("attack", "Attack", 150, "w"), ("iter", "It", 26, "center"),
                           ("result", "Result", 96, "center"), ("mitre", "MITRE", 110, "w"),
                           ("cwe", "CWE", 80, "w")):
            self.status_tree.heading(c, text=t, command=lambda cc=c: self._sort_tree(cc))
            self.status_tree.column(c, width=w, anchor=a, stretch=False)
        vsb = ttk.Scrollbar(tf, orient="vertical", command=self.status_tree.yview)
        hsb = ttk.Scrollbar(tf, orient="horizontal", command=self.status_tree.xview)
        self.status_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.status_tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        tf.rowconfigure(0, weight=1); tf.columnconfigure(0, weight=1)
        # red = passed undetected (finding); orange = detected; green = blocked (good)
        for tag, col in STATUS_COLORS.items():
            self.status_tree.tag_configure(tag, foreground=col)
        # clicking a row jumps the Live output panel straight to that
        # attack+iteration's section instead of having to scroll/hunt for it.
        self.status_tree.bind("<<TreeviewSelect>>", self._jump_to_output)
        self._status_row_keys = {}   # tree item id -> (attack_id, iteration)
        self._output_marks = {}      # (attack_id, iteration) -> Text mark name

    def _build_live_output(self, parent):
        right = ttk.LabelFrame(parent, text="Live output — click a Status row to jump to it")
        right.pack(fill="both", expand=True)
        self.log = tk.Text(right, height=14, wrap="word", bg="#12131b", fg=FG,
                           insertbackground=FG, borderwidth=0, font=MONO, padx=8, pady=6)
        self.log.pack(side="left", fill="both", expand=True)
        sb2 = ttk.Scrollbar(right, command=self.log.yview); sb2.pack(side="right", fill="y")
        self.log.configure(yscrollcommand=sb2.set)
        # finding=red (passed), good=green (blocked), info=blue (no-service),
        # warn=amber, hdr=cyan
        for tag, col in (("finding", ERRC), ("good", OKC), ("info", BLUEC),
                         ("warn", WARNC), ("hdr", INFOC), ("muted", MUTED)):
            self.log.tag_configure(tag, foreground=col)

    # ----- helpers -----------------------------------------------------
    def _over(self, widget, e):
        """True if the pointer is over `widget` or one of its descendants (so a
        bind_all wheel event only scrolls the list the cursor is actually on)."""
        try:
            w = widget.winfo_containing(e.x_root, e.y_root)
        except Exception:
            return False
        while w is not None:
            if w == widget:
                return True
            w = getattr(w, "master", None)
        return False

    def _all(self, v):
        for var, _ in self.vars.values():
            var.set(v)

    def _select_group(self, added):
        for _id, (var, m) in self.vars.items():
            var.set(bool(m.META.get("added")) == added)

    def _collect_port_overrides(self):
        out = {}
        for mid, pv in self.port_vars.items():
            v = pv.get().strip()
            if v.isdigit():
                out[mid] = int(v)
        return out

    def _toggle_cloud_ports(self):
        state = "normal" if self.cloud_var.get() else "disabled"
        self._smb_entry.configure(state=state)
        self._rpc_entry.configure(state=state)

    def _apply_cloud_ports(self, target_ip):
        """When 'Cloud target' is ticked, register the target's NAT'd SMB/RPC
        ports so the impacket modules reach the forwarded alternates (same
        mechanism as modules/_portpatch.py, applied per run for this target)."""
        if not self.cloud_var.get():
            return
        try:
            from modules import _portpatch
            smb = int((self.smb_port.get() or "4445").strip())
            rpc = int((self.rpc_port.get() or "1135").strip())
            _portpatch.CUSTOM_PORT_TARGETS[target_ip] = {445: smb, 135: rpc}
            self._log(f"Cloud target: SMB 445->{smb}, RPC 135->{rpc} for {target_ip} "
                      "(AD modules will use the alternates).")
        except Exception as e:
            self._log(f"[WARN] could not apply cloud SMB/RPC ports: {e}")

    def _preflight(self):
        selected = [m for (var, m) in self.vars.values() if var.get()] or self.modules
        try:
            report = core.format_preflight_report(core.preflight(selected))
        except Exception as e:
            messagebox.showerror("Preflight failed", str(e)); return
        # also probe the target's ports/services if a valid target is entered
        tgt = self.target.get().strip()
        recon = ""
        if tgt:
            ok, why = core.validate_target(tgt)
            if ok:
                try:
                    recon = "\n\n" + core.format_reachability_report(
                        core.reachability(tgt, selected))
                except Exception as e:
                    recon = f"\n\n[recon error: {e}]"
            else:
                recon = f"\n\n[recon skipped: invalid target — {why}]"
        else:
            recon = "\n\n[recon skipped: enter a Target to also probe its ports/services]"

        win = tk.Toplevel(self.root)
        win.title("Preflight + recon")
        win.geometry("860x600"); win.configure(bg=BG)
        txt = tk.Text(win, wrap="none", bg="#12131b", fg=FG, borderwidth=0,
                      font=MONO, padx=8, pady=6)
        for tag, col in (("ready", OKC), ("notready", ERRC), ("hdr", ACCENT),
                         ("exposed", ERRC), ("held", OKC), ("amber", WARNC),
                         ("muted", MUTED)):
            txt.tag_configure(tag, foreground=col)
        for line in (report + recon).splitlines():
            s = line.strip()
            tag = ""
            # tool-readiness (green=present / red=missing)
            if s.startswith("[OK]"):
                tag = "ready"
            elif s.startswith("[XX]") or "MISSING" in line:
                tag = "notready"
            elif set(s) == {"="} or s.startswith(("PREFLIGHT", "RECON", "Modules ready", "Probes")):
                tag = "hdr"
            # recon EXPOSURE semantics: reachable/open = exposed (red);
            # filtered/closed / not-reachable = segmentation holding (green)
            elif s.startswith("Suggested") or (" open" in f" {s}"):
                tag = "exposed"
            elif s.startswith("Not reachable") or "filtered" in s or "closed" in s:
                tag = "held"
            elif s.startswith("Indeterminate"):
                tag = "amber"
            elif line.startswith("  #") or s.startswith("#"):
                tag = "muted"
            txt.insert("end", line + "\n", tag)
        txt.configure(state="disabled")
        txt.pack(side="left", fill="both", expand=True)
        sb = ttk.Scrollbar(win, command=txt.yview); sb.pack(side="right", fill="y")
        txt.configure(yscrollcommand=sb.set)

    def _egress_probe(self):
        """Run the standalone non-destructive egress/segmentation probe against the
        target and stream its output into the live log."""
        tgt = self.target.get().strip()
        ok, why = core.validate_target(tgt) if tgt else (False, "no target")
        if not ok:
            messagebox.showwarning("Egress probe", f"Enter a valid target first ({why})."); return
        allowed, areason = core.target_allowed(tgt)
        if not allowed:
            messagebox.showerror("Target not allowed", areason); return
        if not os.path.exists(_EGRESS_PROBE):
            messagebox.showerror("Egress probe", "additional/mygovnet_egress_probe.py not found."); return
        self.q.put(("log", f"\n=== Egress probe -> {tgt} ==="))

        def work():
            try:
                p = subprocess.Popen(["python3", _EGRESS_PROBE, "-d", tgt, "--no-color"],
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                for line in p.stdout:
                    self.q.put(("log", line.rstrip("\n")))
                p.wait()
                self.q.put(("log", "=== Egress probe done ==="))
            except Exception as e:
                self.q.put(("log", f"[ERROR] egress probe: {e}"))

        threading.Thread(target=work, daemon=True).start()

    def _log(self, m):
        for line in str(m).split("\n"):
            low = line.lower()
            tag = ""
            # attack PASSED / GAP = got through = finding (red)
            if "success" in low or "-> gap" in low or "passed the appliance" in low:
                tag = "finding"
            # NO-SERVICE = port closed / not a control block (blue) — check before "blocked"
            elif "no-service" in low or "not an sd-wan block" in low or "service isn't" in low:
                tag = "info"
            # BLOCKED / OK = stopped = good (green)
            elif "blocked" in low or "-> ok" in low or "control working" in low:
                tag = "good"
            elif "prereq-missing" in low or "auth-failed" in low or "[warn]" in low \
                    or "not reachable" in low or "[error]" in low or "no-result" in low:
                tag = "warn"
            elif line.startswith(("===", "────", "Recon", "Platform", "Preflight", "Target")):
                tag = "hdr"
            self.log.insert("end", line + "\n", tag)
        self.log.see("end")

    def _show_output(self, aid, name, it, raw):
        lines = raw.strip("\n").splitlines()
        TAIL = 40
        tail = lines[-TAIL:] if len(lines) > TAIL else lines
        header = f"──── {name} — iteration {it} — end output "
        if len(lines) > TAIL:
            header += f"(last {TAIL} of {len(lines)} lines — full output in evidence/) "
        header += "────"

        # a named mark at this section's start is what makes "click a Status
        # row -> jump here" possible; re-running the same attack+iteration
        # just moves the mark to the new section instead of accumulating
        # stale ones.
        mark = f"out_{aid}_{it}"
        self.log.insert("end", "\n")
        self.log.mark_set(mark, "end - 1c")
        self.log.mark_gravity(mark, "left")
        self._output_marks[(aid, it)] = mark

        self.log.insert("end", header + "\n", "hdr")
        self.log.insert("end", "\n".join(tail) + "\n")
        self.log.see("end")

    def _add_status(self, aid, name, it, result, direction="", mitre="", cwe="", category=""):
        m = "WB" if getattr(self, "_run_mode", "blackbox") == "whitebox" else "BB"
        self._status_seq = getattr(self, "_status_seq", 0) + 1
        iid = self.status_tree.insert(
            "", "end",
            values=(self._status_seq, m, direction, category, name, it, result, mitre, cwe),
            tags=(result,))
        self._status_row_keys[iid] = (aid, it)
        kids = self.status_tree.get_children()
        if kids:
            self.status_tree.see(kids[-1])

    def _sort_tree(self, col):
        """Sort the status table by a clicked column heading (toggles asc/desc).
        '#'/'It' sort numerically; everything else case-insensitively."""
        rows = [(self.status_tree.set(k, col), k) for k in self.status_tree.get_children("")]
        numeric = col in ("no", "iter")

        def key(item):
            v = item[0]
            if numeric:
                try:
                    return (0, float(v))
                except ValueError:
                    return (1, 0.0)
            return (0, str(v).lower())

        reverse = self._sort_state.get(col, False)
        rows.sort(key=key, reverse=reverse)
        for idx, (_, k) in enumerate(rows):
            self.status_tree.move(k, "", idx)
        self._sort_state[col] = not reverse
        # show a direction arrow on the active column only
        for c in self.status_tree["columns"]:
            base = self.status_tree.heading(c, "text").rstrip(" ▲▼")
            arrow = (" ▼" if reverse else " ▲") if c == col else ""
            self.status_tree.heading(c, text=base + arrow)

    def _jump_to_output(self, _event=None):
        sel = self.status_tree.selection()
        if not sel:
            return
        key = self._status_row_keys.get(sel[0])
        if key is None:
            return
        mark = self._output_marks.get(key)
        if mark is None:
            return  # that attack's output hasn't streamed in yet
        self.log.see(mark)

    def _drain(self):
        try:
            while True:
                kind, p = self.q.get_nowait()
                if kind == "log":
                    self._log(p)
                elif kind == "output":
                    aid, name, it, raw = p; self._show_output(aid, name, it, raw)
                elif kind == "status":
                    aid, name, it, result, _v = p
                    mod = self.vars.get(aid, (None, None))[1]
                    meta = getattr(mod, "META", {}) if mod else {}
                    self._add_status(
                        aid, name, it, result,
                        direction=meta.get("direction", "a2b"),
                        mitre=", ".join(meta.get("mitre", [])),
                        cwe=", ".join(meta.get("cwe", [])),
                        category=meta.get("category", ""))
                elif kind == "progress":
                    self.progress["maximum"] = p[1]; self.progress["value"] = p[0]
                elif kind == "done":
                    self._finish(p)
                elif kind == "error":
                    messagebox.showerror("Error", p); self._finish(None)
        except queue.Empty:
            pass
        self.root.after(100, self._drain)

    # ----- run ---------------------------------------------------------
    def _start(self):
        if not self.roe.get():
            messagebox.showwarning("Blocked", "Tick 'Rules-of-engagement confirmed' first."); return
        selected = [m for (var, m) in self.vars.values() if var.get()]
        if not selected:
            messagebox.showwarning("Nothing selected", "Select at least one attack."); return
        target_ip = self.target.get().strip()
        if not target_ip:
            messagebox.showwarning("No target", "Enter the target IP."); return
        ok, why = core.validate_target(target_ip)
        if not ok:
            messagebox.showwarning("Invalid target", f"{target_ip}: {why}"); return
        allowed, areason = core.target_allowed(target_ip)
        if not allowed:
            messagebox.showerror("Target not allowed", areason); return
        try:
            iters = max(1, int(self.iterations.get()))
        except (ValueError, TypeError):
            messagebox.showwarning("Bad iterations", "Iterations must be a whole number."); return
        try:
            workers = max(1, int(self.workers.get()))
        except (ValueError, TypeError):
            workers = 1
        port_overrides = self._collect_port_overrides()
        self._apply_cloud_ports(target_ip)
        self._run_mode = self.mode_var.get()

        self.run_btn["state"] = "disabled"; self.stop_btn["state"] = "normal"
        self.progress["value"] = 0
        for row in self.status_tree.get_children():
            self.status_tree.delete(row)
        self._status_seq = 0
        self.log.delete("1.0", "end")
        self._status_row_keys.clear()
        self._output_marks.clear()
        self._log("Starting run...")

        self.runner = core.Runner(
            target_ip, None,
            on_log=lambda m: self.q.put(("log", m)),
            on_progress=lambda c, t: self.q.put(("progress", (c, t))),
            on_output=lambda aid, name, it, raw: self.q.put(("output", (aid, name, it, raw))),
            on_status=lambda aid, name, it, b, v: self.q.put(("status", (aid, name, it, b, v))))
        self.runner.concurrency = workers
        if port_overrides:
            self.runner.ctx.port_overrides = port_overrides
        self.runner.ctx.allow_active = bool(self.active_var.get())
        src = self.source_entry.get().strip()
        if src:
            self.runner.ctx.source_ip = src
        if self.active_var.get():
            self._log("ACTIVE establishment ENABLED — live modules may build real "
                      "tunnels/pivots/exfil to your configured infra.")

        mode = self._run_mode

        def work():
            try:
                ev = core.Evidence()
                root = self.runner.run(selected, iters, ev, mode=mode)
                self.q.put(("done", root))
            except Exception as e:
                self.q.put(("error", str(e)))

        threading.Thread(target=work, daemon=True).start()

    def _stop(self):
        if self.runner:
            self.runner.stop(); self._log("Stop requested — finishing current step...")

    def _finish(self, root):
        self.run_btn["state"] = "normal"; self.stop_btn["state"] = "disabled"
        if root:
            self._log(f"\nDONE. Evidence: {root}")
            self._log("  summary.json / summary.csv / report.txt (+ ATT&CK coverage) "
                      "+ per-attack raw logs")
            messagebox.showinfo("Complete", f"Evidence saved to:\n{root}")


def main():
    try:
        root = tk.Tk()
    except tk.TclError as e:
        import sys
        sys.stderr.write(
            f"\n[GUI] no display available ({e}).\n"
            "This is a headless machine (e.g. a server over SSH). Use the CLI instead:\n"
            "    python3 cli.py --list\n"
            "    python3 cli.py --target 127.0.0.1 --mode whitebox --confirm-roe\n"
            "Or forward X over SSH:  ssh -X user@host   then  python3 gui.py\n")
        sys.exit(1)
    HarnessGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
