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
    "INCONCLUSIVE":   "#a371f7",  # purple — source in IPS quarantine, attack not tested
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
        root.title(f"Control Validation Harness v{core.VERSION}")
        root.geometry("1240x920")
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
        ttk.Label(h, text=f"Control Validation Harness  ·  v{core.VERSION}",
                  style="H1.TLabel").pack(anchor="w")
        ttk.Label(h, text="Breach & Attack Simulation · MITRE ATT&CK-mapped · "
                          f"{len(self.modules)} modules discovered",
                  style="Sub.TLabel").pack(anchor="w")

    # ----- config ------------------------------------------------------
    def _build_config(self, parent):
        # Vertically STACKED, section-by-section layout (pack, not one wide grid):
        # this panel lives in a ~70%-width left column, so every field + its hint
        # sits on its OWN line and can't overflow/clip off the right edge (the old
        # grid packed entries and long hints on the same row, which pushed the
        # password box, eye toggle and NAT port boxes past the visible edge -- they
        # looked "missing"). Section separators keep it readable.
        f = ttk.LabelFrame(parent, text="Target & run")
        f.pack(fill="x", padx=12, pady=8)

        def _sep():
            ttk.Separator(f, orient="horizontal").pack(fill="x", padx=10, pady=(3, 2))

        def _hint(text):
            ttk.Label(f, text=text, style="Muted.TLabel", wraplength=720,
                      justify="left").pack(anchor="w", padx=10, pady=(0, 1))

        # ---------- TARGETS (dynamic, top-to-bottom rows) ----------
        trow = ttk.Frame(f); trow.pack(fill="x", padx=10, pady=(8, 0))
        ttk.Label(trow, text="TARGETS", style="Sub.TLabel").pack(side="left")
        ttk.Button(trow, text="+ add", width=7,
                   command=self._add_target_row).pack(side="left", padx=(8, 6))
        ttk.Label(trow, text="tick a row = whitebox (allow-all) baseline",
                  style="Muted.TLabel").pack(side="left")
        # Each row = an IP/host + a per-target WHITEBOX tick. Row 1 uses the
        # on-screen creds/cloud/source below; added rows use their OWN remembered
        # cfg. "+ add" appends a row (unlimited N, like CLI --target A,B,C).
        self._rows_frame = ttk.Frame(f); self._rows_frame.pack(fill="x", padx=10, pady=(2, 2))
        self.target_rows = []          # [(entry, whitebox_var, row_frame)]
        self._add_target_row(primary=True)

        # ---------- iterations / workers ----------
        rw = ttk.Frame(f); rw.pack(fill="x", padx=10, pady=(2, 4))
        ttk.Label(rw, text="Iterations").pack(side="left")
        self.iterations = ttk.Spinbox(rw, from_=1, to=20, width=4); self.iterations.set(1)
        self.iterations.pack(side="left", padx=(4, 14))
        ttk.Label(rw, text="Workers").pack(side="left")
        self.workers = ttk.Spinbox(rw, from_=1, to=16, width=4)
        self.workers.set(core.RECOMMENDED_WORKERS)
        self.workers.pack(side="left", padx=(4, 8))
        ttk.Label(rw, text=f"(rec. {core.RECOMMENDED_WORKERS}; DoS/brute always serial)",
                  style="Muted.TLabel").pack(side="left")

        # ---------- CREDENTIALS (aligned grid, always visible) ----------
        _sep()
        ttk.Label(f, text="CREDENTIALS", style="Sub.TLabel").pack(anchor="w", padx=10)
        cg = ttk.Frame(f); cg.pack(fill="x", padx=10, pady=(2, 0))
        ttk.Label(cg, text="Domain").grid(row=0, column=0, sticky="w", pady=2)
        self.domain_entry = ttk.Entry(cg, width=16)
        self.domain_entry.grid(row=0, column=1, sticky="w", padx=(4, 16), pady=2)
        ttk.Label(cg, text="DC user").grid(row=0, column=2, sticky="w", pady=2)
        self.user_entry = ttk.Entry(cg, width=18)
        self.user_entry.grid(row=0, column=3, sticky="w", padx=(4, 0), pady=2)
        ttk.Label(cg, text="DC pass").grid(row=1, column=0, sticky="w", pady=2)
        pcell = ttk.Frame(cg); pcell.grid(row=1, column=1, columnspan=3, sticky="w", padx=(4, 0), pady=2)
        self.pass_entry = ttk.Entry(pcell, width=18, show="•"); self.pass_entry.pack(side="left")
        self._eye(pcell, self.pass_entry)
        ttk.Label(cg, text="SSH user").grid(row=2, column=0, sticky="w", pady=2)
        self.ssh_user_entry = ttk.Entry(cg, width=16)
        self.ssh_user_entry.grid(row=2, column=1, sticky="w", padx=(4, 16), pady=2)
        ttk.Label(cg, text="SSH pass").grid(row=2, column=2, sticky="w", pady=2)
        scell = ttk.Frame(cg); scell.grid(row=2, column=3, sticky="w", padx=(4, 0), pady=2)
        self.ssh_pass_entry = ttk.Entry(scell, width=18, show="•"); self.ssh_pass_entry.pack(side="left")
        self._eye(scell, self.ssh_pass_entry)
        _hint("Blank = credentials.env / env. SSH creds separate; blank -> DC creds. "
              "Passwords redacted (***) in evidence.")

        # ---------- CLOUD / NAT ports (always editable) ----------
        _sep()
        cf = ttk.Frame(f); cf.pack(fill="x", padx=10, pady=(2, 0))
        self.cloud_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(cf, text="Cloud target (NAT'd ports)", variable=self.cloud_var,
                        command=self._toggle_cloud_ports).pack(side="left")
        ttk.Label(cf, text="SMB").pack(side="left", padx=(12, 2))
        self.smb_port = tk.StringVar(value="4445")
        self._smb_entry = ttk.Entry(cf, textvariable=self.smb_port, width=6)
        self._smb_entry.pack(side="left")
        ttk.Label(cf, text="RPC").pack(side="left", padx=(10, 2))
        self.rpc_port = tk.StringVar(value="1135")
        self._rpc_entry = ttk.Entry(cf, textvariable=self.rpc_port, width=6)
        self._rpc_entry.pack(side="left")
        ttk.Label(cf, text="SSH").pack(side="left", padx=(10, 2))
        self.ssh_port = tk.StringVar(value="22")
        self._ssh_port_entry = ttk.Entry(cf, textvariable=self.ssh_port, width=6)
        self._ssh_port_entry.pack(side="left")
        _hint("Tick to apply the 445->SMB / 135->RPC / 22->SSH NAT mapping (impacket + "
              "ssh_brute reach the forwarded ports). Boxes stay editable either way.")

        # ---------- OPTIONS ----------
        _sep()
        self.active_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(f, text="Active establishment (build real tunnels/pivots/exfil -- needs config.json)",
                        variable=self.active_var).pack(anchor="w", padx=10, pady=(0, 2))
        og = ttk.Frame(f); og.pack(fill="x", padx=10, pady=(0, 2))
        ttk.Label(og, text="Source IP").pack(side="left")
        self.source_entry = ttk.Entry(og, width=15)
        self.source_entry.pack(side="left", padx=(4, 14))
        # Wait for an IPS quarantine / source blacklist to clear before marking the
        # rest INCONCLUSIVE (--wait-unblock; 0 = default max(30s, cooldown)).
        ttk.Label(og, text="Wait-unblock(s)").pack(side="left")
        self.wait_unblock = ttk.Entry(og, width=5); self.wait_unblock.insert(0, "0")
        self.wait_unblock.pack(side="left", padx=(4, 14))
        ttk.Label(og, text="Site ID").pack(side="left")
        self.site_entry = ttk.Entry(og, width=14)
        self.site_entry.pack(side="left", padx=(4, 12))
        import os as _os
        if _os.environ.get("HARNESS_SITE_ID"):
            self.site_entry.insert(0, _os.environ["HARNESS_SITE_ID"])
        self.debug_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(og, text="Debug", variable=self.debug_var).pack(side="left")

        # Pre-fill from the RESOLVED defaults (env > credentials.env > the
        # non-secret built-ins: lab.local / Administrator). Domain + DC user are
        # populated out of the box; the password shows ONLY if the operator
        # configured one via HARNESS_DC_PASS / credentials.env -- we never bake a
        # secret into source. A remembered per-target value (.target_memory.json)
        # overrides these in _recall_target().
        try:
            dflt = core.load_credentials()
            for ent, k in ((self.domain_entry, "domain"), (self.user_entry, "dc_user"),
                           (self.pass_entry, "dc_pass"), (self.ssh_user_entry, "ssh_user"),
                           (self.ssh_pass_entry, "ssh_pass")):
                if dflt.get(k):
                    ent.insert(0, dflt[k])
        except Exception:
            pass

        # ---------- privilege + a visible "what loaded" line ----------
        _sep()
        self._priv_frame = ttk.Frame(f); self._priv_frame.pack(fill="x", padx=10, pady=(0, 2))
        self._priv_label = ttk.Label(self._priv_frame, text="", style="Muted.TLabel")
        self._priv_label.pack(side="left")
        self._unlock_btn = ttk.Button(self._priv_frame, text="Unlock sudo", command=self._unlock_sudo)
        # (_unlock_btn is packed/unpacked by _refresh_privilege)
        # One-line status so "did my password load?" is answered at a glance --
        # a check means a value is in the field, a dash means empty (SSH blank
        # falls back to the DC creds).
        self._prefill_note = ttk.Label(f, text="", style="Muted.TLabel",
                                        wraplength=720, justify="left")
        self._prefill_note.pack(anchor="w", padx=10, pady=(0, 4))

        self._refresh_privilege()
        self._prefill_last_target()
        self._update_prefill_note()

    def _update_prefill_note(self):
        """Refresh the one-line 'what loaded' indicator under the credentials."""
        if not hasattr(self, "_prefill_note"):
            return
        def mk(entry):
            return "✓" if entry.get().strip() else "—"
        self._prefill_note.configure(
            text=(f"Loaded:  domain {mk(self.domain_entry)}   DC user {mk(self.user_entry)}   "
                  f"DC pass {mk(self.pass_entry)}   |   SSH user {mk(self.ssh_user_entry)}   "
                  f"SSH pass {mk(self.ssh_pass_entry)}     (dash = empty; SSH blank -> DC creds)"))

    def _refresh_privilege(self):
        ps = core.privilege_status(self.modules)
        if not ps["needs_root_modules"]:
            self._priv_frame.pack_forget(); return
        icon = "✓" if (ps["root"] or ps["sudo_nopasswd"]) else ("⚠" if not ps["sudo_present"] else "ℹ")
        style = ("Muted.TLabel" if (ps["root"] or ps["sudo_nopasswd"])
                 else "Err.TLabel" if not ps["sudo_present"] else "Warn.TLabel")
        self._priv_label.configure(text=f"{icon} Privilege: {ps['how']}", style=style)
        if ps["can_unlock"]:
            self._unlock_btn.pack(side="left", padx=(8, 0))
        else:
            self._unlock_btn.pack_forget()

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
            # default selection = the ORIGINAL baseline set (added:false); the
            # opt-in/USS modules (added:true) start unticked. Use the "Added" /
            # "All" buttons to widen.
            var = tk.BooleanVar(value=not meta.get("added"))
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
                         ("Egress probe", self._egress_probe),
                         ("Appliance log…", self._appliance_log),
                         ("Infra config…", self._infra_config)):
            ttk.Button(f1, text=txt, command=cmd).pack(side="left", padx=(0, 6))
        # row 2 — RoE gate + RUN/STOP
        f2 = ttk.Frame(parent); f2.pack(fill="x", padx=12, pady=(4, 2))
        # pre-ticked when a durable ROE opt-in is on file (--accept-roe /
        # HARNESS_CONFIRM_ROE=1) so you don't re-tick every launch.
        self.roe = tk.BooleanVar(value=core.roe_accepted())
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
                              (("●"), "#a371f7", "INCONCLUSIVE — source in IPS quarantine, not tested"),
                              (("●"), MUTED, "SKIPPED / PREREQ-MISSING — not run")):
            rowf = ttk.Frame(leg, style="Card.TFrame"); rowf.pack(anchor="w", fill="x")
            tk.Label(rowf, text=dot, fg=col, bg=PANEL).pack(side="left")
            tk.Label(rowf, text=txt, fg=MUTED, bg=PANEL,
                     font=("TkDefaultFont", 8)).pack(side="left")

        # tree + BOTH scrollbars in a grid frame (packing the scrollbar after an
        # expanding tree squeezes it to zero width — the old "can't scroll" bug).
        tf = ttk.Frame(left); tf.pack(fill="both", expand=True, padx=2, pady=2)
        cols = ("no", "time", "tgt", "ports", "dir", "cat", "attack", "iter", "result", "mitre", "cwe")
        self.status_tree = ttk.Treeview(tf, columns=cols, show="headings", height=18)
        self._sort_state = {}   # col -> last sort was descending
        # click any heading to sort by that column (toggles asc/desc)
        for c, t, w, a in (("no", "#", 34, "center"), ("time", "Time", 64, "center"),
                           ("tgt", "Target", 104, "w"), ("ports", "Ports", 72, "w"),
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

    def _add_target_row(self, primary=False):
        """Append a target row: IP/host entry + a per-target whitebox tick (and a
        remove button on non-primary rows). The primary row's widgets are also
        exposed as self.target / self.whitebox_var so recall/save/prefill work."""
        rf = ttk.Frame(self._rows_frame); rf.pack(anchor="w", pady=1)
        entry = ttk.Entry(rf, width=18); entry.pack(side="left")
        wb = tk.BooleanVar(value=False)
        ttk.Checkbutton(rf, text="whitebox", variable=wb).pack(side="left", padx=(6, 0))
        if primary:
            self.target = entry
            self.whitebox_var = wb
            entry.bind("<FocusOut>", lambda e: self._recall_target())
            entry.bind("<Return>", lambda e: self._recall_target())
        else:
            ttk.Button(rf, text="−", width=2,
                       command=lambda: self._remove_target_row(rf)).pack(side="left", padx=(6, 0))
        self.target_rows.append((entry, wb, rf))

    def _remove_target_row(self, rf):
        self.target_rows = [(e, w, f) for (e, w, f) in self.target_rows if f is not rf]
        rf.destroy()

    def _eye(self, parent, entry):
        """Add a small show/hide (eye) toggle next to a masked password Entry."""
        var = tk.BooleanVar(value=False)
        # plain "show" text — the 👁 emoji isn't in the default Tk font and rendered
        # as a tofu box.
        ttk.Checkbutton(parent, text="show", variable=var,
                        command=lambda: entry.config(show="" if var.get() else "•"),
                        style="TCheckbutton").pack(side="left", padx=(4, 4))

    def _toggle_cloud_ports(self):
        # The SMB/RPC/SSH port boxes stay ALWAYS editable/visible now (a disabled,
        # greyed-out box read as "missing input"). The Cloud tick only decides
        # whether the NAT map is APPLIED for the run — see _cfg_from_screen /
        # _apply_cloud_ports, which both gate on self.cloud_var. Kept as a method
        # because the checkbutton command and _recall_target still call it.
        return

    def _prefill_last_target(self):
        """On launch, resume the most-recently-used target: set the Target field
        and pull its saved source/cloud/creds (incl. password) from
        .target_memory.json, so you don't re-type them each session. Reads only
        your own 0600 memory file — nothing is baked into source. Clear the field
        if you want a different target."""
        try:
            mem = core.load_target_memory()
        except Exception:
            mem = {}
        if not mem or self.target.get().strip():
            return

        def _ts(kv):
            rec = kv[1]
            return rec.get("last_used", "") if isinstance(rec, dict) else ""
        try:
            ip = max(mem.items(), key=_ts)[0]
        except (ValueError, TypeError):
            return
        if not ip:
            return
        self.target.delete(0, "end")
        self.target.insert(0, ip)
        self._recall_target()   # fills source/cloud/creds for this target

    def _recall_target(self):
        """Populate source/cloud/ports from the last run against this target."""
        try:
            rec = core.recall_target(self.target.get().strip())
        except Exception:
            rec = {}
        if not rec:
            return
        if rec.get("source") and not self.source_entry.get().strip():
            self.source_entry.insert(0, rec["source"])
        if rec.get("mode"):
            self.whitebox_var.set(rec["mode"] == "whitebox")
        if "cloud" in rec:
            self.cloud_var.set(bool(rec["cloud"]))
            if rec.get("smb_port"):
                self.smb_port.set(str(rec["smb_port"]))
            if rec.get("rpc_port"):
                self.rpc_port.set(str(rec["rpc_port"]))
            if rec.get("ssh_port"):
                self.ssh_port.set(str(rec["ssh_port"]))
            self._toggle_cloud_ports()
        # per-target credentials (DC/AD + separate SSH) + Site ID — a remembered
        # per-target value WINS over the default prefill, so switching to a known
        # target loads that target's creds (incl. its password). Targets with
        # nothing remembered keep whatever is in the field (the resolved defaults).
        for key, entry in (("domain", self.domain_entry), ("dc_user", self.user_entry),
                           ("dc_pass", self.pass_entry),
                           ("ssh_user", self.ssh_user_entry), ("ssh_pass", self.ssh_pass_entry),
                           ("site_id", self.site_entry)):
            if rec.get(key):
                entry.delete(0, "end")
                entry.insert(0, rec[key])
        self._update_prefill_note()   # reflect this target's loaded creds

    def _save_target(self, target):
        """Remember this target's source/cloud/creds options for next time."""
        try:
            core.remember_target(
                target,
                source=self.source_entry.get().strip() or None,
                cloud=bool(self.cloud_var.get()),
                smb_port=(self.smb_port.get().strip() or None) if self.cloud_var.get() else None,
                rpc_port=(self.rpc_port.get().strip() or None) if self.cloud_var.get() else None,
                ssh_port=(self.ssh_port.get().strip() or None) if self.cloud_var.get() else None,
                domain=self.domain_entry.get().strip() or None,
                dc_user=self.user_entry.get().strip() or None,
                dc_pass=self.pass_entry.get().strip() or None,
                ssh_user=self.ssh_user_entry.get().strip() or None,
                ssh_pass=self.ssh_pass_entry.get().strip() or None,
                site_id=self.site_entry.get().strip() or None,
                mode=("whitebox" if self.whitebox_var.get() else "blackbox"))
        except Exception:
            pass

    def _apply_target_creds(self):
        """Apply the per-target DC + SSH credential fields to the runner's creds
        (blank fields keep whatever credentials.env/env already loaded). SSH creds
        are separate so ssh_brute can log into a dual-role target's Linux SSH
        while the AD modules use the DC login."""
        for key, entry in (("domain", self.domain_entry), ("dc_user", self.user_entry),
                           ("dc_pass", self.pass_entry),
                           ("ssh_user", self.ssh_user_entry), ("ssh_pass", self.ssh_pass_entry)):
            v = entry.get().strip()
            if v:
                self.runner.ctx.creds[key] = v

    def _cfg_from_screen(self):
        """Snapshot the on-screen creds/source/cloud as plain data (MAIN thread) so
        the worker can apply it without touching Tk widgets. For target 1."""
        creds = {}
        for key, entry in (("domain", self.domain_entry), ("dc_user", self.user_entry),
                           ("dc_pass", self.pass_entry),
                           ("ssh_user", self.ssh_user_entry), ("ssh_pass", self.ssh_pass_entry)):
            v = entry.get().strip()
            if v:
                creds[key] = v
        cloud_map = None
        if self.cloud_var.get():
            try:
                cloud_map = {445: int((self.smb_port.get() or "4445").strip()),
                             135: int((self.rpc_port.get() or "1135").strip()),
                             22: int((self.ssh_port.get() or "22").strip())}
            except ValueError:
                cloud_map = {445: 4445, 135: 1135, 22: 22}
        return {"creds": creds, "source": self.source_entry.get().strip() or None,
                "cloud_map": cloud_map,
                "mode": "whitebox" if self.whitebox_var.get() else "blackbox"}

    def _cfg_recalled(self, target):
        """Build a target's config from its remembered .target_memory.json entry
        (for the 2nd target, which uses its OWN saved cloud/creds, not the screen)."""
        try:
            rec = core.recall_target(target) or {}
        except Exception:
            rec = {}
        creds = {k: rec[k] for k in ("domain", "dc_user", "dc_pass", "ssh_user", "ssh_pass")
                 if rec.get(k)}
        cloud_map = None
        if rec.get("cloud"):
            cloud_map = {445: int(rec.get("smb_port") or 4445),
                         135: int(rec.get("rpc_port") or 1135),
                         22: int(rec.get("ssh_port") or 22)}
        return {"creds": creds, "source": rec.get("source") or None, "cloud_map": cloud_map,
                "mode": rec.get("mode") or "blackbox"}   # 2nd target: its OWN saved posture

    @staticmethod
    def _apply_cfg(runner, target, cfg):
        """Apply a plain config dict to a runner (worker thread; no Tk access)."""
        try:
            from modules import _portpatch
            if cfg.get("cloud_map"):
                _portpatch.CUSTOM_PORT_TARGETS[target] = cfg["cloud_map"]
            else:
                _portpatch.CUSTOM_PORT_TARGETS.pop(target, None)
        except Exception:
            pass
        for k, v in cfg.get("creds", {}).items():
            runner.ctx.creds[k] = v
        if cfg.get("source"):
            runner.ctx.source_ip = cfg["source"]

    def _apply_cloud_ports(self, target_ip):
        """When 'Cloud target' is ticked, register the target's NAT'd SMB/RPC
        ports so the impacket modules reach the forwarded alternates (same
        mechanism as modules/_portpatch.py, applied per run for this target)."""
        try:
            from modules import _portpatch
        except Exception as e:
            self._log(f"[WARN] could not apply cloud SMB/RPC ports: {e}")
            return
        if not self.cloud_var.get():
            # Cloud OFF: clear any remap this long-lived GUI left for this target
            # from an earlier cloud run, or a direct (non-NAT) run would keep
            # redirecting SMB/RPC to the stale alternate ports.
            _portpatch.CUSTOM_PORT_TARGETS.pop(target_ip, None)
            return
        try:
            smb = int((self.smb_port.get() or "4445").strip())
            rpc = int((self.rpc_port.get() or "1135").strip())
            ssh = int((self.ssh_port.get() or "22").strip())
            _portpatch.CUSTOM_PORT_TARGETS[target_ip] = {445: smb, 135: rpc, 22: ssh}
            self._log(f"Cloud target: SMB 445->{smb}, RPC 135->{rpc}, SSH 22->{ssh} for "
                      f"{target_ip} (AD modules + ssh_brute use the alternates).")
        except Exception as e:
            self._log(f"[WARN] could not apply cloud SMB/RPC ports: {e}")

    def _infra_config(self):
        """Edit config.json (the attacker infra the egress/C2/exfil modules aim at)
        from the GUI — prefilled from the current resolved config — so those
        modules stop SKIPping without hand-editing JSON. Saved to the git-ignored
        config.json (env HARNESS_CFG_* still overrides per the same precedence)."""
        import json as _json
        cfg = core.load_config()                 # env > config.json > defaults
        defaults = getattr(core, "_CFG_DEFAULTS", {})
        path = os.path.join(os.path.dirname(os.path.abspath(core.__file__)), "config.json")
        keys = sorted(set(list(defaults) + list(cfg)))
        win = tk.Toplevel(self.root); win.title("Infra config (config.json)")
        win.geometry("680x560"); win.configure(bg=BG)
        ttk.Label(win, style="Muted.TLabel", wraplength=640,
                  text="Attacker infra the egress/C2/exfil modules aim at. Blank = that module "
                       "stays [SKIP] (never points anywhere real). Lists are comma-separated. "
                       "Saved to config.json (git-ignored).").pack(anchor="w", padx=10, pady=(8, 4))
        canvas = tk.Canvas(win, bg=BG, highlightthickness=0)
        inner = ttk.Frame(canvas)
        vsb = ttk.Scrollbar(win, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y"); canvas.pack(side="top", fill="both", expand=True, padx=8)
        canvas.create_window((0, 0), window=inner, anchor="nw")
        inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        entries = {}
        for i, k in enumerate(keys):
            ttk.Label(inner, text=k, width=22).grid(row=i, column=0, sticky="w", padx=4, pady=2)
            e = ttk.Entry(inner, width=52)
            v = cfg.get(k, defaults.get(k, ""))
            e.insert(0, ", ".join(map(str, v)) if isinstance(v, list) else ("" if v is None else str(v)))
            e.grid(row=i, column=1, sticky="w", padx=4, pady=2)
            entries[k] = e

        def _save():
            out = {}
            for k, e in entries.items():
                raw = e.get().strip()
                dflt = defaults.get(k)
                if isinstance(dflt, list):
                    out[k] = [x.strip() for x in raw.split(",") if x.strip()]
                elif isinstance(dflt, int) and not isinstance(dflt, bool):
                    try: out[k] = int(raw)
                    except ValueError: out[k] = dflt
                else:
                    out[k] = raw
            try:
                with open(path, "w") as f:
                    _json.dump(out, f, indent=2)
                messagebox.showinfo("Saved", f"config.json written:\n{path}")
                win.destroy()
            except Exception as ex:
                messagebox.showerror("Save failed", str(ex))
        ttk.Button(win, text="Save config.json", style="Accent.TButton",
                   command=_save).pack(side="bottom", pady=8)

    def _appliance_log(self):
        """Pick an SD-WAN/firewall log (Sangfor/Forcepoint, .xlsx/.csv) and show the
        per-module Allow/Deny + signature correlation for the current target (runs
        additional/sangfor_ingest.py; dry-run — apply with --write via the CLI)."""
        from tkinter import filedialog
        import subprocess as _sp, sys as _sys
        path = filedialog.askopenfilename(
            title="Select SD-WAN / firewall log (xlsx or csv)",
            filetypes=[("Appliance logs", "*.xlsx *.csv"), ("All files", "*.*")])
        if not path:
            return
        script = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              "additional", "sangfor_ingest.py")
        cmd = [_sys.executable, script, "--log", path, "--ips", path, "--model", "appliance (GUI)"]
        tgt = self.target.get().strip()
        if tgt:
            cmd += ["--target", tgt]
        # Run the ingest subprocess OFF the Tk main thread (up to 120s) so the GUI
        # doesn't freeze/"not responding"; marshal the result back via root.after.
        self._log(f"Correlating appliance log {os.path.basename(path)} … (background)")

        def work():
            try:
                p = _sp.run(cmd, capture_output=True, text=True, timeout=120)
                out = (p.stdout or "") + (("\n[stderr]\n" + p.stderr) if p.stderr else "")
            except Exception as e:
                self.root.after(0, lambda e=e: messagebox.showerror("Ingest failed", str(e)))
                return
            self.root.after(0, lambda: self._show_appliance_result(path, tgt, out))
        threading.Thread(target=work, daemon=True).start()

    def _show_appliance_result(self, path, tgt, out):
        win = tk.Toplevel(self.root)
        win.title(f"Appliance-log correlation — {os.path.basename(path)}")
        win.geometry("900x620"); win.configure(bg=BG)
        hint = ttk.Label(win, style="Muted.TLabel",
                         text="Dry-run. To score SEEN-but-allowed attacks as DETECTED, apply via CLI:  "
                              f"python3 additional/sangfor_ingest.py --log <f> --ips <f> --target {tgt or '<ip>'} --write")
        hint.pack(anchor="w", padx=8, pady=(6, 0))
        txt = tk.Text(win, wrap="none", bg="#12131b", fg=FG, borderwidth=0, font=MONO, padx=8, pady=6)
        txt.insert("1.0", out or "(no output)")
        txt.configure(state="disabled")
        txt.pack(fill="both", expand=True, padx=6, pady=6)

    def _preflight(self):
        selected = [m for (var, m) in self.vars.values() if var.get()] or self.modules
        # Read the Tk widgets + apply per-target cloud port maps on the MAIN thread
        # (Tk access must not happen off-thread); the blocking preflight + recon
        # (socket probes) then run in a worker so the GUI never freezes.
        tgts = [(e.get().strip(), (i == 0)) for i, (e, _w, _f) in enumerate(self.target_rows)]
        tgts = [(t, scr) for t, scr in tgts if t]
        prepared = []
        for tgt, from_screen in tgts:
            ok, why = core.validate_target(tgt)
            if not ok:
                prepared.append((tgt, False, f"invalid target — {why}")); continue
            try:
                from modules import _portpatch
                if from_screen:
                    self._apply_cloud_ports(tgt)   # honour the on-screen Cloud tick
                else:
                    cfg = self._cfg_recalled(tgt)  # 2nd target: its own saved cloud map
                    if cfg.get("cloud_map"):
                        _portpatch.CUSTOM_PORT_TARGETS[tgt] = cfg["cloud_map"]
                    else:
                        _portpatch.CUSTOM_PORT_TARGETS.pop(tgt, None)
                prepared.append((tgt, True, None))
            except Exception as e:
                prepared.append((tgt, False, str(e)))
        self._log("Running preflight + recon … (background)")

        def work():
            try:
                report = core.format_preflight_report(core.preflight(selected))
            except Exception as e:
                self.root.after(0, lambda e=e: messagebox.showerror("Preflight failed", str(e)))
                return
            recon = ""
            if not prepared:
                recon = "\n\n[recon skipped: enter a Target to also probe its ports/services]"
            for tgt, okq, info in prepared:
                if not okq:
                    recon += f"\n\n[recon skipped for {tgt}: {info}]"
                    continue
                try:
                    recon += (f"\n\n───── recon: {tgt} ─────\n" if len(prepared) > 1 else "\n\n")
                    recon += core.format_reachability_report(core.reachability(tgt, selected))
                except Exception as e:
                    recon += f"\n\n[recon error for {tgt}: {e}]"
            self.root.after(0, lambda: self._show_preflight_result(report, recon))
        threading.Thread(target=work, daemon=True).start()

    def _show_preflight_result(self, report, recon):
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

    def _add_status(self, aid, name, it, result, direction="", mitre="", cwe="",
                    category="", target="", ports=""):
        self._status_seq = getattr(self, "_status_seq", 0) + 1
        import time as _t
        ts = _t.strftime("%H:%M:%S")   # when this result landed (completion time)
        iid = self.status_tree.insert(
            "", "end",
            values=(self._status_seq, ts, target, ports, direction, category, name, it, result, mitre, cwe),
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
                    aid, name, it, result, _v = p[:5]
                    tgt = p[5] if len(p) > 5 else ""
                    mod = self.vars.get(aid, (None, None))[1]
                    meta = getattr(mod, "META", {}) if mod else {}
                    # the target port(s) this module probes/attacks (icmp/egress have none)
                    ports = ", ".join(
                        (f"{pp}/{pr}" if pp is not None else pr)
                        for (pr, pp) in (meta.get("ports") or [])) or "—"
                    self._add_status(
                        aid, name, it, result,
                        direction=meta.get("direction", "a2b"),
                        mitre=", ".join(meta.get("mitre", [])),
                        cwe=", ".join(meta.get("cwe", [])),
                        category=meta.get("category", ""), target=tgt, ports=ports)
                elif kind == "progress":
                    self.progress["maximum"] = p[1]; self.progress["value"] = p[0]
                elif kind == "new_target":
                    ti, n, tgt = p
                    if n > 1:
                        self._log(f"\n{'═' * 40}\n  TARGET {ti}/{n}:  {tgt}\n{'═' * 40}")
                elif kind == "done":
                    self._finish(p)
                elif kind == "done_multi":
                    self._finish_multi(p)
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
        # Build the target list: target 1 (uses the on-screen config) + an optional
        # target 2 (uses its OWN remembered config) so one scan hits A->B and A->C.
        jobs = []   # (target, cfg)

        def _ok_target(tip):
            ok, why = core.validate_target(tip)
            if not ok:
                messagebox.showwarning("Invalid target", f"{tip}: {why}"); return False
            allowed, areason = core.target_allowed(tip)
            if not allowed:
                messagebox.showerror("Target not allowed", f"{tip}: {areason}"); return False
            return True
        # Each Target ROW: row 1 uses the on-screen config, added rows use their own
        # remembered cfg; posture comes from THAT row's whitebox tick.
        for i, (entry, wb, _rf) in enumerate(self.target_rows):
            tip = entry.get().strip()
            if not tip:
                continue
            if not _ok_target(tip):
                return
            cfg = self._cfg_from_screen() if i == 0 else self._cfg_recalled(tip)
            cfg["mode"] = "whitebox" if wb.get() else "blackbox"   # per-ROW posture
            if i > 0:
                core.remember_target(tip, mode=cfg["mode"])        # persist added row's posture
            jobs.append((tip, cfg))
        if not jobs:
            messagebox.showwarning("No target", "Enter at least one target."); return
        try:
            iters = max(1, int(self.iterations.get()))
        except (ValueError, TypeError):
            messagebox.showwarning("Bad iterations", "Iterations must be a whole number."); return
        try:
            workers = max(1, int(self.workers.get()))
        except (ValueError, TypeError):
            workers = 1
        try:
            wait_unblock = max(0.0, float(self.wait_unblock.get() or 0))
        except (ValueError, TypeError):
            wait_unblock = 0.0
        port_overrides = self._collect_port_overrides()
        self._save_target(jobs[0][0])   # remember target 1's on-screen cfg
        # assessment posture from the Whitebox tick (per target, remembered + in evidence).
        self._run_mode = "whitebox" if self.whitebox_var.get() else "blackbox"
        self._run_targets = [t for t, _c in jobs]   # cleared from _portpatch at run-end

        self.run_btn["state"] = "disabled"; self.stop_btn["state"] = "normal"
        self.progress["value"] = 0
        for row in self.status_tree.get_children():
            self.status_tree.delete(row)
        self._status_seq = 0
        self.log.delete("1.0", "end")
        self._status_row_keys.clear()
        self._output_marks.clear()
        self._log(f"Starting run... ({len(jobs)} target(s))")
        active = bool(self.active_var.get()); debug = bool(self.debug_var.get())
        if active:
            self._log("ACTIVE establishment ENABLED — live modules may build real "
                      "tunnels/pivots/exfil to your configured infra.")
        if debug:
            self._log("DEBUG mode ON — tools run verbose (curl -v / ldapsearch -v / "
                      "hydra -d / impacket -debug); full raw output + timing in evidence.")

        mode = self._run_mode
        site_id = self.site_entry.get().strip() or None

        def work():
            roots = []
            try:
                for ti, (tgt, cfg) in enumerate(jobs, 1):
                    self.q.put(("new_target", (ti, len(jobs), tgt)))
                    runner = core.Runner(
                        tgt, None,
                        on_log=lambda m: self.q.put(("log", m)),
                        on_progress=lambda c, t: self.q.put(("progress", (c, t))),
                        on_output=lambda aid, name, it, raw: self.q.put(("output", (aid, name, it, raw))),
                        on_status=lambda aid, name, it, b, v, _t=tgt: self.q.put(("status", (aid, name, it, b, v, _t))))
                    self.runner = runner
                    runner.concurrency = workers
                    if wait_unblock > 0:
                        runner.wait_unblock = wait_unblock
                    if port_overrides:
                        runner.ctx.port_overrides = port_overrides
                    runner.ctx.allow_active = active
                    runner.ctx.debug = debug
                    self._apply_cfg(runner, tgt, cfg)
                    ev = core.Evidence(label=(tgt if len(jobs) > 1 else None))
                    # posture is PER TARGET: target 1 from the Whitebox tick, the
                    # 2nd target from its own remembered mode (via _cfg_recalled).
                    root = runner.run(selected, iters, ev,
                                      mode=cfg.get("mode", mode), site_id=site_id)
                    roots.append((tgt, root))
                    if self.runner._stop:
                        break
                self.q.put(("done_multi", roots))
            except Exception as e:
                self.q.put(("error", str(e)))

        threading.Thread(target=work, daemon=True).start()

    def _stop(self):
        if self.runner:
            self.runner.stop(); self._log("Stop requested — finishing current step...")

    def _clear_cloud_remaps(self):
        # Clear this run's cloud SMB/RPC remaps so a long-lived GUI session can't
        # carry a stale port redirect into a later run against the same IP.
        try:
            from modules import _portpatch
            for tip in getattr(self, "_run_targets", []) or []:
                _portpatch.CUSTOM_PORT_TARGETS.pop(tip, None)
        except Exception:
            pass

    def _finish(self, root):
        self.run_btn["state"] = "normal"; self.stop_btn["state"] = "disabled"
        self._clear_cloud_remaps()
        if root:
            self._log(f"\nDONE. Evidence: {root}")
            self._log("  summary.json / summary.csv / report.txt (+ ATT&CK coverage) "
                      "+ per-attack raw logs")
            messagebox.showinfo("Complete", f"Evidence saved to:\n{root}")

    def _finish_multi(self, roots):
        self.run_btn["state"] = "normal"; self.stop_btn["state"] = "disabled"
        self._clear_cloud_remaps()
        if not roots:
            return
        self._log("\nDONE. Evidence:")
        for tgt, root in roots:
            self._log(f"  {tgt}  →  {root}")
        self._log("  summary.json / summary.csv / report.txt (+ ATT&CK coverage) "
                  "+ per-attack raw logs")
        lines = "\n".join(f"{tgt}:\n  {root}" for tgt, root in roots)
        messagebox.showinfo("Complete", f"Scanned {len(roots)} target(s):\n\n{lines}")


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
