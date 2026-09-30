#!/usr/bin/env python3
"""
gui.py — Tkinter front-end (modern dark theme). Auto-discovers attack modules
from modules/ and builds the list from them. GUI never freezes (worker thread +
queue). Full raw logs + JSON/TXT/CSV go to evidence/run_<ts>/.

Run:  python3 gui.py
"""

import queue
import threading
import tkinter as tk
from tkinter import ttk, messagebox

import core
import loader

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
        self._build_config()
        self._build_attacks()
        self._build_controls()
        self._build_log()
        self.root.after(100, self._drain)

    # ----- header ------------------------------------------------------
    def _build_header(self):
        h = ttk.Frame(self.root); h.pack(fill="x", padx=14, pady=(12, 2))
        ttk.Label(h, text="Control Validation Harness", style="H1.TLabel").pack(anchor="w")
        ttk.Label(h, text="Breach & Attack Simulation · MITRE ATT&CK-mapped · "
                          f"{len(self.modules)} modules discovered",
                  style="Sub.TLabel").pack(anchor="w")

    # ----- config ------------------------------------------------------
    def _build_config(self):
        f = ttk.LabelFrame(self.root, text="Target & run")
        f.pack(fill="x", padx=12, pady=8)
        pad = dict(padx=6, pady=6)

        ttk.Label(f, text="Target IP / host").grid(row=0, column=0, sticky="w", **pad)
        self.target = ttk.Entry(f, width=20)
        self.target.grid(row=0, column=1, sticky="w", **pad)

        ttk.Label(f, text="Iterations").grid(row=0, column=2, sticky="e", **pad)
        self.iterations = ttk.Spinbox(f, from_=1, to=20, width=5)
        self.iterations.set(1)
        self.iterations.grid(row=0, column=3, sticky="w", **pad)

        ttk.Label(f, text="Workers").grid(row=0, column=4, sticky="e", **pad)
        self.workers = ttk.Spinbox(f, from_=1, to=16, width=5)
        self.workers.set(core.RECOMMENDED_WORKERS)
        self.workers.grid(row=0, column=5, sticky="w", **pad)
        ttk.Label(f, text=f"(recommended {core.RECOMMENDED_WORKERS}; DoS/brute always serial)",
                  style="Muted.TLabel").grid(row=0, column=6, sticky="w", **pad)

        ps = core.privilege_status(self.modules)
        if ps["needs_root_modules"]:
            if ps["root"] or ps["sudo_nopasswd"]:
                icon, style = "✓", "Muted.TLabel"
            elif not ps["sudo_present"]:
                icon, style = "⚠", "Err.TLabel"
            else:
                icon, style = "ℹ", "Warn.TLabel"
            ttk.Label(f, text=f"{icon} Privilege: {ps['how']}", style=style).grid(
                row=1, column=0, columnspan=7, sticky="w", padx=6, pady=(0, 6))

    # ----- attacks -----------------------------------------------------
    def _build_attacks(self):
        outer = ttk.LabelFrame(self.root, text="Attacks — tick to include; edit port where shown")
        outer.pack(fill="both", expand=False, padx=12, pady=8)
        canvas = tk.Canvas(outer, height=250, bg=PANEL, highlightthickness=0)
        sb = ttk.Scrollbar(outer, orient="vertical", command=canvas.yview)
        inner = ttk.Frame(canvas, style="Card.TFrame")
        inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        win = canvas.create_window((0, 0), window=inner, anchor="nw")
        canvas.bind("<Configure>", lambda e: canvas.itemconfigure(win, width=e.width))
        canvas.configure(yscrollcommand=sb.set)
        canvas.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        current_cat = None
        for m in self.modules:
            meta = m.META
            if meta["category"] != current_cat:
                current_cat = meta["category"]
                ttk.Label(inner, text=f"  {current_cat}", style="Cat.TLabel").pack(
                    anchor="w", pady=(10, 3), fill="x")
            row = ttk.Frame(inner, style="Card.TFrame"); row.pack(anchor="w", fill="x", padx=6)
            var = tk.BooleanVar(value=True)
            self.vars[meta["id"]] = (var, m)
            ttk.Checkbutton(row, text=meta["name"], variable=var,
                            style="Card.TCheckbutton", width=34).pack(side="left")
            if meta.get("added"):
                tk.Label(row, text="NEW", bg=NEWC, fg="#fff",
                         font=("TkDefaultFont", 7, "bold"), padx=4).pack(side="left", padx=(0, 6))
            # MITRE + tactic chip
            mitre = ", ".join(meta.get("mitre", []))
            tk.Label(row, text=f"{mitre}", bg=PANEL, fg=INFOC,
                     font=("TkDefaultFont", 8)).pack(side="left", padx=4)
            # per-attack port entry (only where honoured)
            if meta.get("port_customizable"):
                default = next((p for pr, p in
                                ((s if isinstance(s, (list, tuple)) else ("tcp", s))
                                 for s in meta.get("ports", [])) if pr in ("tcp", "udp")), "")
                pv = tk.StringVar(value=str(default))
                self.port_vars[meta["id"]] = pv
                tk.Label(row, text="port", bg=PANEL, fg=MUTED,
                         font=("TkDefaultFont", 8)).pack(side="right", padx=(0, 2))
                ttk.Entry(row, textvariable=pv, width=6).pack(side="right", padx=2)
            tk.Label(row, text=f"fix:{meta.get('fix','')}", bg=PANEL, fg=MUTED,
                     font=("TkDefaultFont", 8)).pack(side="right", padx=8)

    # ----- controls ----------------------------------------------------
    def _build_controls(self):
        f = ttk.Frame(self.root); f.pack(fill="x", padx=12, pady=4)
        for txt, cmd in (("Select all", lambda: self._all(True)),
                         ("Clear", lambda: self._all(False)),
                         ("Original set", lambda: self._select_group(False)),
                         ("Added set", lambda: self._select_group(True)),
                         ("Preflight + recon", self._preflight)):
            ttk.Button(f, text=txt, command=cmd).pack(side="left", padx=(0, 6))
        self.roe = tk.BooleanVar(value=False)
        ttk.Checkbutton(f, text="Rules-of-engagement confirmed (written authorisation on file)",
                        variable=self.roe).pack(side="left", padx=16)
        self.run_btn = ttk.Button(f, text="▶ RUN", style="Accent.TButton", command=self._start)
        self.run_btn.pack(side="right")
        self.stop_btn = ttk.Button(f, text="■ STOP", style="Stop.TButton",
                                   command=self._stop, state="disabled")
        self.stop_btn.pack(side="right", padx=6)
        self.progress = ttk.Progressbar(self.root, mode="determinate")
        self.progress.pack(fill="x", padx=12, pady=(2, 6))

    def _build_log(self):
        outer = ttk.Frame(self.root); outer.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        left = ttk.LabelFrame(outer, text="Status")
        left.pack(side="left", fill="y", padx=(0, 6))
        left.pack_propagate(False); left.configure(width=340)
        self.status_tree = ttk.Treeview(left, columns=("attack", "iter", "result"),
                                        show="headings", height=20)
        for c, t, w, a in (("attack", "Attack", 195, "w"), ("iter", "#", 30, "center"),
                           ("result", "Result", 100, "center")):
            self.status_tree.heading(c, text=t); self.status_tree.column(c, width=w, anchor=a)
        self.status_tree.pack(side="left", fill="both", expand=True)
        sb1 = ttk.Scrollbar(left, command=self.status_tree.yview); sb1.pack(side="right", fill="y")
        self.status_tree.configure(yscrollcommand=sb1.set)
        for tag, col in (("SUCCESS", OKC), ("BLOCKED", BLUEC), ("AUTH-FAILED", WARNC),
                         ("NO-RESULT", ERRC), ("PREREQ-MISSING", WARNC)):
            self.status_tree.tag_configure(tag, foreground=col)

        right = ttk.LabelFrame(outer, text="Live output")
        right.pack(side="left", fill="both", expand=True)
        self.log = tk.Text(right, height=14, wrap="word", bg="#12131b", fg=FG,
                           insertbackground=FG, borderwidth=0, font=MONO, padx=8, pady=6)
        self.log.pack(side="left", fill="both", expand=True)
        sb2 = ttk.Scrollbar(right, command=self.log.yview); sb2.pack(side="right", fill="y")
        self.log.configure(yscrollcommand=sb2.set)
        for tag, col in (("ok", OKC), ("blocked", BLUEC), ("warn", WARNC),
                         ("err", ERRC), ("hdr", INFOC), ("muted", MUTED)):
            self.log.tag_configure(tag, foreground=col)

    # ----- helpers -----------------------------------------------------
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
        for tag, col in (("ok", OKC), ("bad", ERRC), ("hdr", ACCENT), ("blue", BLUEC),
                         ("muted", MUTED)):
            txt.tag_configure(tag, foreground=col)
        for line in (report + recon).splitlines():
            s = line.strip()
            tag = ""
            if s.startswith("[OK]") or s.startswith("Suggested"):
                tag = "ok"
            elif s.startswith("[XX]") or "MISSING" in line or s.startswith("Not reachable"):
                tag = "bad"
            elif set(s) == {"="} or s.startswith("PREFLIGHT") or s.startswith("RECON") \
                    or s.startswith("Modules ready") or s.startswith("Probes"):
                tag = "hdr"
            elif "open" in s or s.startswith("Indeterminate"):
                tag = "blue"
            elif line.startswith("  #") or s.startswith("#"):
                tag = "muted"
            txt.insert("end", line + "\n", tag)
        txt.configure(state="disabled")
        txt.pack(side="left", fill="both", expand=True)
        sb = ttk.Scrollbar(win, command=txt.yview); sb.pack(side="right", fill="y")
        txt.configure(yscrollcommand=sb.set)

    def _log(self, m):
        for line in str(m).split("\n"):
            low = line.lower()
            tag = ""
            if "success" in low or "-> gap" in low:
                tag = "ok"
            elif "blocked" in low or "-> ok" in low:
                tag = "blocked"
            elif "prereq-missing" in low or "auth-failed" in low or "[warn]" in low \
                    or "not reachable" in low:
                tag = "warn"
            elif "[error]" in low or "no-result" in low:
                tag = "err"
            elif line.startswith(("===", "────", "Recon", "Platform", "Preflight", "Target")):
                tag = "hdr"
            self.log.insert("end", line + "\n", tag)
        self.log.see("end")

    def _show_output(self, name, raw):
        lines = raw.strip("\n").splitlines()
        TAIL = 40
        tail = lines[-TAIL:] if len(lines) > TAIL else lines
        header = f"\n──── {name} — end output "
        if len(lines) > TAIL:
            header += f"(last {TAIL} of {len(lines)} lines — full output in evidence/) "
        header += "────"
        self.log.insert("end", header + "\n", "hdr")
        self.log.insert("end", "\n".join(tail) + "\n")
        self.log.see("end")

    def _add_status(self, name, it, result):
        self.status_tree.insert("", "end", values=(name, it, result), tags=(result,))
        kids = self.status_tree.get_children()
        if kids:
            self.status_tree.see(kids[-1])

    def _drain(self):
        try:
            while True:
                kind, p = self.q.get_nowait()
                if kind == "log":
                    self._log(p)
                elif kind == "output":
                    _aid, name, raw = p; self._show_output(name, raw)
                elif kind == "status":
                    _aid, name, it, result, _v = p; self._add_status(name, it, result)
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

        self.run_btn["state"] = "disabled"; self.stop_btn["state"] = "normal"
        self.progress["value"] = 0
        for row in self.status_tree.get_children():
            self.status_tree.delete(row)
        self.log.delete("1.0", "end")
        self._log("Starting run...")

        self.runner = core.Runner(
            target_ip, None,
            on_log=lambda m: self.q.put(("log", m)),
            on_progress=lambda c, t: self.q.put(("progress", (c, t))),
            on_output=lambda aid, name, raw: self.q.put(("output", (aid, name, raw))),
            on_status=lambda aid, name, it, b, v: self.q.put(("status", (aid, name, it, b, v))))
        self.runner.concurrency = workers
        if port_overrides:
            self.runner.ctx.port_overrides = port_overrides

        def work():
            try:
                ev = core.Evidence()
                root = self.runner.run(selected, iters, ev)
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
    root = tk.Tk()
    HarnessGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
