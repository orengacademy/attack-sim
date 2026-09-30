#!/usr/bin/env python3
"""
gui.py — Tkinter front-end (modern dark theme). Auto-discovers attack modules
from modules/ and builds the checkbox list from them. GUI never freezes (worker
thread + queue). Full raw logs + JSON/TXT/CSV go to evidence/run_<ts>/.

Run:  python3 gui.py   (from inside the harness/ folder)
"""

import queue
import threading
import tkinter as tk
from tkinter import ttk, messagebox

import core
import loader

# ---- palette (modern dark) ------------------------------------------------
BG      = "#1e1f2b"   # window background
SURF    = "#282a3a"   # inputs / panels
SURF2   = "#31344a"   # hover / alt rows
FG      = "#e6e6ef"   # primary text
MUTED   = "#9aa0b4"   # secondary text
ACCENT  = "#7c6cf0"   # brand / headings
OKC     = "#3fb950"   # success
BLUEC   = "#4aa3ff"   # blocked
WARNC   = "#e3a008"   # prereq / auth-failed
ERRC    = "#f85149"   # no-result / error
INFOC   = "#39c5cf"   # headers / info


def _apply_theme(root):
    """Best-effort modern dark theme; degrades gracefully if unavailable."""
    try:
        root.configure(bg=BG)
        st = ttk.Style(root)
        try:
            st.theme_use("clam")
        except tk.TclError:
            pass
        st.configure(".", background=BG, foreground=FG, fieldbackground=SURF,
                     bordercolor=SURF2, focuscolor=ACCENT)
        st.configure("TFrame", background=BG)
        st.configure("TLabel", background=BG, foreground=FG)
        st.configure("Muted.TLabel", background=BG, foreground=MUTED)
        st.configure("Warn.TLabel", background=BG, foreground=WARNC)
        st.configure("Err.TLabel", background=BG, foreground=ERRC)
        st.configure("Head.TLabel", background=BG, foreground=ACCENT,
                     font=("TkDefaultFont", 13, "bold"))
        st.configure("TLabelframe", background=BG, bordercolor=SURF2)
        st.configure("TLabelframe.Label", background=BG, foreground=ACCENT,
                     font=("TkDefaultFont", 10, "bold"))
        st.configure("TCheckbutton", background=BG, foreground=FG)
        st.map("TCheckbutton", background=[("active", BG)], foreground=[("active", FG)])
        st.configure("TButton", background=SURF, foreground=FG, borderwidth=0, padding=6)
        st.map("TButton", background=[("active", SURF2), ("pressed", ACCENT)])
        st.configure("Accent.TButton", background=ACCENT, foreground="#ffffff",
                     font=("TkDefaultFont", 10, "bold"))
        st.map("Accent.TButton", background=[("active", "#9385f4"), ("pressed", "#6a5be0")])
        st.configure("Stop.TButton", background="#5a2a2a", foreground=FG)
        st.map("Stop.TButton", background=[("active", ERRC)])
        st.configure("TEntry", fieldbackground=SURF, foreground=FG, insertcolor=FG)
        st.configure("TSpinbox", fieldbackground=SURF, foreground=FG, arrowcolor=FG)
        st.configure("Treeview", background=SURF, fieldbackground=SURF, foreground=FG,
                     rowheight=22, borderwidth=0)
        st.configure("Treeview.Heading", background=BG, foreground=ACCENT,
                     font=("TkDefaultFont", 9, "bold"))
        st.map("Treeview", background=[("selected", ACCENT)])
        st.configure("TProgressbar", background=ACCENT, troughcolor=SURF)
    except Exception:
        pass  # theming is cosmetic — never let it break the app


class HarnessGUI:
    def __init__(self, root):
        self.root = root
        root.title("Control Validation Harness")
        root.geometry("1200x820")
        _apply_theme(root)

        self.modules = loader.discover()            # auto-discovered
        self.q = queue.Queue()
        self.runner = None
        self.vars = {}                              # id -> (BooleanVar, module)

        self._build_top()
        self._build_attacks()
        self._build_controls()
        self._build_log()
        self.root.after(100, self._drain)

    # ----- top ---------------------------------------------------------
    def _build_top(self):
        ttk.Label(self.root, text="Control Validation Harness",
                  style="Head.TLabel").pack(anchor="w", padx=10, pady=(8, 0))

        f = ttk.LabelFrame(self.root, text="Target & run")
        f.pack(fill="x", padx=8, pady=6)

        ttk.Label(f, text="Target IP/host:").grid(row=0, column=0, sticky="w", padx=4, pady=4)
        self.target = ttk.Entry(f, width=18)
        self.target.grid(row=0, column=1, padx=4)

        ttk.Label(f, text="Iterations:").grid(row=0, column=2, sticky="w", padx=4)
        self.iterations = ttk.Spinbox(f, from_=1, to=20, width=5)
        self.iterations.set(1)                       # default 1
        self.iterations.grid(row=0, column=3, padx=4)

        ttk.Label(f, text="Workers:").grid(row=0, column=4, sticky="w", padx=4)
        self.workers = ttk.Spinbox(f, from_=1, to=16, width=5)
        self.workers.set(core.RECOMMENDED_WORKERS)   # safe default (4)
        self.workers.grid(row=0, column=5, padx=4)

        ttk.Label(f, text="Custom ports:").grid(row=1, column=0, sticky="w", padx=4, pady=(0, 4))
        self.ports = ttk.Entry(f, width=40)
        self.ports.grid(row=1, column=1, columnspan=3, sticky="w", padx=4, pady=(0, 4))
        ttk.Label(f, text="e.g. log4shell=8983, syn=443", style="Muted.TLabel").grid(
            row=1, column=4, columnspan=2, sticky="w", padx=4)

        ttk.Label(f, text=f"{len(self.modules)} modules discovered · Workers>1 runs "
                          f"parallel-safe modules concurrently (DoS/brute stay serial). "
                          f"Recommended workers: {core.RECOMMENDED_WORKERS}.",
                  style="Muted.TLabel").grid(row=2, column=0, columnspan=6, sticky="w",
                                             padx=4, pady=2)

        # privilege banner
        ps = core.privilege_status(self.modules)
        if ps["needs_root_modules"]:
            style = "Warn.TLabel"
            if ps["root"] or ps["sudo_nopasswd"]:
                icon = "✓"
            elif not ps["sudo_present"]:
                icon, style = "⚠", "Err.TLabel"
            else:
                icon = "ℹ"
            ttk.Label(f, text=f"{icon} Privilege: {ps['how']}", style=style).grid(
                row=3, column=0, columnspan=6, sticky="w", padx=4, pady=(2, 4))

    # ----- attacks (from discovered modules, grouped) ------------------
    def _build_attacks(self):
        outer = ttk.LabelFrame(self.root, text="Attacks (auto-discovered)")
        outer.pack(fill="both", expand=False, padx=8, pady=6)
        canvas = tk.Canvas(outer, height=260, bg=BG, highlightthickness=0)
        sb = ttk.Scrollbar(outer, orient="vertical", command=canvas.yview)
        inner = ttk.Frame(canvas)
        inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=inner, anchor="nw")
        canvas.configure(yscrollcommand=sb.set)
        canvas.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        current_cat = None
        for m in self.modules:
            meta = m.META
            if meta["category"] != current_cat:
                current_cat = meta["category"]
                ttk.Label(inner, text=f"— {current_cat} —",
                          foreground=INFOC, background=BG,
                          font=("TkDefaultFont", 9, "bold")).pack(anchor="w", pady=(8, 2))
            var = tk.BooleanVar(value=True)
            self.vars[meta["id"]] = (var, m)
            row = ttk.Frame(inner); row.pack(anchor="w", fill="x")
            ttk.Checkbutton(row, text=meta["name"], variable=var).pack(side="left")
            if meta.get("added"):
                tk.Label(row, text="NEW", bg=ACCENT, fg="#fff",
                         font=("TkDefaultFont", 7, "bold"), padx=4).pack(side="left", padx=6)
            tag = f"[{meta.get('control','')} · fix:{meta.get('fix','')}]"
            ttk.Label(row, text=tag, style="Muted.TLabel").pack(side="left", padx=8)

    # ----- controls ----------------------------------------------------
    def _build_controls(self):
        f = ttk.Frame(self.root); f.pack(fill="x", padx=8, pady=4)
        ttk.Button(f, text="Select all", command=lambda: self._all(True)).pack(side="left")
        ttk.Button(f, text="Clear", command=lambda: self._all(False)).pack(side="left", padx=4)
        ttk.Button(f, text="Original set", command=lambda: self._select_group(added=False)
                   ).pack(side="left", padx=4)
        ttk.Button(f, text="Added set", command=lambda: self._select_group(added=True)
                   ).pack(side="left", padx=4)
        ttk.Button(f, text="Preflight", command=self._preflight).pack(side="left", padx=4)
        self.roe = tk.BooleanVar(value=False)
        ttk.Checkbutton(f, text="Rules-of-engagement confirmed (written authorisation on file)",
                        variable=self.roe).pack(side="left", padx=16)
        self.run_btn = ttk.Button(f, text="RUN", style="Accent.TButton", command=self._start)
        self.run_btn.pack(side="right")
        self.stop_btn = ttk.Button(f, text="STOP", style="Stop.TButton",
                                   command=self._stop, state="disabled")
        self.stop_btn.pack(side="right", padx=4)
        self.progress = ttk.Progressbar(self.root, mode="determinate")
        self.progress.pack(fill="x", padx=8, pady=2)

    def _build_log(self):
        outer = ttk.Frame(self.root)
        outer.pack(fill="both", expand=True, padx=8, pady=6)

        left = ttk.LabelFrame(outer, text="Status")
        left.pack(side="left", fill="y", padx=(0, 4))
        left.pack_propagate(False)
        left.configure(width=320)

        cols = ("attack", "iter", "result")
        self.status_tree = ttk.Treeview(left, columns=cols, show="headings", height=20)
        for c, t, w, a in (("attack", "Attack", 185, "w"), ("iter", "#", 30, "center"),
                           ("result", "Result", 95, "center")):
            self.status_tree.heading(c, text=t)
            self.status_tree.column(c, width=w, anchor=a)
        self.status_tree.pack(side="left", fill="both", expand=True)
        sb1 = ttk.Scrollbar(left, command=self.status_tree.yview); sb1.pack(side="right", fill="y")
        self.status_tree.configure(yscrollcommand=sb1.set)
        self.status_tree.tag_configure("SUCCESS", foreground=OKC)
        self.status_tree.tag_configure("BLOCKED", foreground=BLUEC)
        self.status_tree.tag_configure("AUTH-FAILED", foreground=WARNC)
        self.status_tree.tag_configure("NO-RESULT", foreground=ERRC)
        self.status_tree.tag_configure("PREREQ-MISSING", foreground=WARNC)

        right = ttk.LabelFrame(outer, text="Live output")
        right.pack(side="left", fill="both", expand=True)
        self.log = tk.Text(right, height=14, wrap="word", bg="#14151f", fg=FG,
                           insertbackground=FG, borderwidth=0,
                           font=("TkFixedFont", 10))
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
        """Tick only the original set (added=False) or only the newly-added
        modules (added=True); untick the rest."""
        for _id, (var, m) in self.vars.items():
            var.set(bool(m.META.get("added")) == added)

    def _parse_ports(self):
        """Parse the Custom ports entry ('name=port, name=port') into a dict."""
        out = {}
        raw = self.ports.get().strip()
        for part in raw.replace(";", ",").split(","):
            part = part.strip()
            if not part or "=" not in part:
                continue
            k, v = part.split("=", 1)
            k, v = k.strip(), v.strip()
            if k and v.isdigit():
                out[k] = int(v)
        return out

    def _preflight(self):
        selected = [m for (var, m) in self.vars.values() if var.get()] or self.modules
        try:
            pf = core.preflight(selected)
            report = core.format_preflight_report(pf)
        except Exception as e:
            messagebox.showerror("Preflight failed", str(e))
            return
        win = tk.Toplevel(self.root)
        win.title("Preflight — tool & privilege check")
        win.geometry("820x560")
        win.configure(bg=BG)
        txt = tk.Text(win, wrap="none", bg="#14151f", fg=FG, borderwidth=0,
                      font=("TkFixedFont", 10))
        for tag, col in (("ok", OKC), ("bad", ERRC), ("hdr", ACCENT), ("muted", MUTED)):
            txt.tag_configure(tag, foreground=col)
        for line in report.splitlines():
            tag = ""
            s = line.strip()
            if s.startswith("[OK]"):
                tag = "ok"
            elif s.startswith("[XX]"):
                tag = "bad"
            elif set(s) == {"="} or s.startswith("PREFLIGHT") or s.startswith("Modules ready"):
                tag = "hdr"
            elif s.startswith("#") or line.startswith("  #") or "MISSING" in line:
                tag = "muted" if not s.startswith("[XX]") else "bad"
            txt.insert("end", line + "\n", tag)
        txt.configure(state="disabled")
        txt.pack(side="left", fill="both", expand=True)
        sb = ttk.Scrollbar(win, command=txt.yview); sb.pack(side="right", fill="y")
        txt.configure(yscrollcommand=sb.set)

    def _log(self, m):
        # colorize per line by keyword
        for line in str(m).split("\n"):
            tag = ""
            low = line.lower()
            if "[success]" in low or "-> success" in low or " [success]" in low or "SUCCESS" in line:
                tag = "ok"
            elif "blocked" in low:
                tag = "blocked"
            elif "prereq-missing" in low or "auth-failed" in low or "[warn]" in low or "not reachable" in low:
                tag = "warn"
            elif "[error]" in low or "no-result" in low:
                tag = "err"
            elif line.startswith("===") or line.startswith("────") or line.startswith("Recon") or line.startswith("Platform") or line.startswith("Preflight"):
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
        children = self.status_tree.get_children()
        if children:
            self.status_tree.see(children[-1])

    def _drain(self):
        try:
            while True:
                kind, p = self.q.get_nowait()
                if kind == "log":
                    self._log(p)
                elif kind == "output":
                    _aid, name, raw = p
                    self._show_output(name, raw)
                elif kind == "status":
                    _aid, name, it, result, _verdict = p
                    self._add_status(name, it, result)
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
            messagebox.showwarning("Blocked", "Tick 'Rules-of-engagement confirmed' first.")
            return
        selected = [m for (var, m) in self.vars.values() if var.get()]
        if not selected:
            messagebox.showwarning("Nothing selected", "Select at least one attack.")
            return
        target_ip = self.target.get().strip()
        if not target_ip:
            messagebox.showwarning("No target", "Enter the target IP.")
            return
        ok, why = core.validate_target(target_ip)
        if not ok:
            messagebox.showwarning("Invalid target", f"{target_ip}: {why}")
            return
        allowed, areason = core.target_allowed(target_ip)
        if not allowed:
            messagebox.showerror("Target not allowed", areason)
            return
        try:
            iters = max(1, int(self.iterations.get()))
        except (ValueError, TypeError):
            messagebox.showwarning("Bad iterations", "Iterations must be a whole number.")
            return
        try:
            workers = max(1, int(self.workers.get()))
        except (ValueError, TypeError):
            workers = 1
        port_overrides = self._parse_ports()

        self.run_btn["state"] = "disabled"; self.stop_btn["state"] = "normal"
        self.progress["value"] = 0
        for row in self.status_tree.get_children():
            self.status_tree.delete(row)
        self.log.delete("1.0", "end")
        self._log("Starting run...")

        self.runner = core.Runner(
            target_ip, None,          # single-target mode
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
            self._log("  summary.json / summary.csv / report.txt + per-attack raw logs")
            messagebox.showinfo("Complete", f"Evidence saved to:\n{root}")


def main():
    root = tk.Tk()
    HarnessGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
