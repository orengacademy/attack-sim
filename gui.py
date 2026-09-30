#!/usr/bin/env python3
"""
gui.py — Tkinter front-end. Auto-discovers attack modules from modules/
and builds the checkbox list from them. GUI never freezes (worker thread
+ queue). Full raw logs + JSON/TXT/CSV go to evidence/run_<ts>/.

Run:  python3 gui.py   (from inside the harness/ folder)
"""

import os
import queue
import threading
import tkinter as tk
from tkinter import ttk, messagebox

import core
import loader


class HarnessGUI:
    def __init__(self, root):
        self.root = root
        root.title("Control Validation Harness")
        root.geometry("1150x800")

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
        f = ttk.LabelFrame(self.root, text="Target")
        f.pack(fill="x", padx=8, pady=6)

        ttk.Label(f, text="Target IP:").grid(row=0, column=0, sticky="w", padx=4, pady=3)
        self.target = ttk.Entry(f, width=17)
        self.target.grid(row=0, column=1, padx=4)
        ttk.Label(f, text="Iterations:").grid(row=0, column=2, sticky="w", padx=4)
        self.iterations = ttk.Spinbox(f, from_=1, to=20, width=5)
        self.iterations.set(3)
        self.iterations.grid(row=0, column=3, padx=4)

        ttk.Label(f, text=f"{len(self.modules)} attack modules discovered.",
                  foreground="#666").grid(row=1, column=0, columnspan=4, sticky="w", padx=4, pady=2)

        # portable privilege check (os.geteuid() doesn't exist on Windows);
        # root-needing modules declare needs_root in their own META.
        if not core.is_privileged():
            needed = [m.META["name"] for m in self.modules if m.META.get("needs_root")]
            if needed:
                ttk.Label(
                    f, text=f"⚠ Not running as root/admin — {', '.join(needed)} will be "
                            f"skipped (PREREQ-MISSING). Restart elevated (e.g. sudo python3 gui.py).",
                    foreground="#b00").grid(row=2, column=0, columnspan=4, sticky="w", padx=4, pady=2)

    # ----- attacks (from discovered modules, grouped) ------------------
    def _build_attacks(self):
        outer = ttk.LabelFrame(self.root, text="Attacks (auto-discovered from modules/)")
        outer.pack(fill="both", expand=False, padx=8, pady=6)
        canvas = tk.Canvas(outer, height=250)
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
                          font=("TkDefaultFont", 9, "bold")).pack(anchor="w", pady=(8, 2))
            var = tk.BooleanVar(value=True)
            self.vars[meta["id"]] = (var, m)
            row = ttk.Frame(inner); row.pack(anchor="w", fill="x")
            ttk.Checkbutton(row, text=meta["name"], variable=var).pack(side="left")
            tag = f"[{meta.get('control','')} · fix:{meta.get('fix','')}]"
            ttk.Label(row, text=tag, foreground="#888").pack(side="left", padx=8)

    # ----- controls ----------------------------------------------------
    def _build_controls(self):
        f = ttk.Frame(self.root); f.pack(fill="x", padx=8, pady=4)
        ttk.Button(f, text="Select all", command=lambda: self._all(True)).pack(side="left")
        ttk.Button(f, text="Clear", command=lambda: self._all(False)).pack(side="left", padx=4)
        ttk.Button(f, text="Preflight", command=self._preflight).pack(side="left", padx=4)
        self.roe = tk.BooleanVar(value=False)
        ttk.Checkbutton(f, text="Rules-of-engagement confirmed (written authorisation on file)",
                        variable=self.roe).pack(side="left", padx=16)
        self.run_btn = ttk.Button(f, text="RUN", command=self._start); self.run_btn.pack(side="right")
        self.stop_btn = ttk.Button(f, text="STOP", command=self._stop, state="disabled")
        self.stop_btn.pack(side="right", padx=4)
        self.progress = ttk.Progressbar(self.root, mode="determinate")
        self.progress.pack(fill="x", padx=8, pady=2)

    def _build_log(self):
        outer = ttk.Frame(self.root)
        outer.pack(fill="both", expand=True, padx=8, pady=6)

        # ----- left: per-attack pass/fail status, updated live -----
        left = ttk.LabelFrame(outer, text="Status")
        left.pack(side="left", fill="y", padx=(0, 4))
        left.pack_propagate(False)
        left.configure(width=300)

        cols = ("attack", "iter", "result")
        self.status_tree = ttk.Treeview(left, columns=cols, show="headings", height=20)
        self.status_tree.heading("attack", text="Attack")
        self.status_tree.heading("iter", text="#")
        self.status_tree.heading("result", text="Result")
        self.status_tree.column("attack", width=170, anchor="w")
        self.status_tree.column("iter", width=25, anchor="center")
        self.status_tree.column("result", width=80, anchor="center")
        self.status_tree.pack(side="left", fill="both", expand=True)
        sb1 = ttk.Scrollbar(left, command=self.status_tree.yview); sb1.pack(side="right", fill="y")
        self.status_tree.configure(yscrollcommand=sb1.set)

        self.status_tree.tag_configure("SUCCESS", foreground="#0a0")
        self.status_tree.tag_configure("BLOCKED", foreground="#06c")
        self.status_tree.tag_configure("AUTH-FAILED", foreground="#e80")
        self.status_tree.tag_configure("NO-RESULT", foreground="#c00")
        self.status_tree.tag_configure("PREREQ-MISSING", foreground="#a60")

        # ----- right: live tool output (the raw evidence, tailed) -----
        right = ttk.LabelFrame(outer, text="Live output (tool's own end output)")
        right.pack(side="left", fill="both", expand=True)
        self.log = tk.Text(right, height=14, wrap="word", bg="#111", fg="#ddd")
        self.log.pack(side="left", fill="both", expand=True)
        sb2 = ttk.Scrollbar(right, command=self.log.yview); sb2.pack(side="right", fill="y")
        self.log.configure(yscrollcommand=sb2.set)

    # ----- helpers -----------------------------------------------------
    def _all(self, v):
        for var, _ in self.vars.values():
            var.set(v)

    def _preflight(self):
        """Check tools/privileges for the currently-ticked attacks (or all, if
        none ticked) and show the report in a scrollable window. This is the
        same check Runner.run performs automatically before executing."""
        selected = [m for (var, m) in self.vars.values() if var.get()] or self.modules
        report = core.format_preflight_report(core.preflight(selected))
        win = tk.Toplevel(self.root)
        win.title("Preflight — tool & privilege check")
        win.geometry("780x520")
        txt = tk.Text(win, wrap="none", bg="#111", fg="#ddd",
                      font=("TkFixedFont", 10))
        txt.insert("1.0", report)
        txt.configure(state="disabled")
        txt.pack(side="left", fill="both", expand=True)
        sb = ttk.Scrollbar(win, command=txt.yview); sb.pack(side="right", fill="y")
        txt.configure(yscrollcommand=sb.set)

    def _log(self, m):
        self.log.insert("end", m + "\n"); self.log.see("end")

    def _show_output(self, name, raw):
        lines = raw.strip("\n").splitlines()
        TAIL = 40
        tail = lines[-TAIL:] if len(lines) > TAIL else lines
        header = f"\n──── {name} — end output "
        if len(lines) > TAIL:
            header += f"(last {TAIL} of {len(lines)} lines — full output in evidence/) "
        header += "────"
        self.log.insert("end", header + "\n" + "\n".join(tail) + "\n")
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

        iters = int(self.iterations.get())

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
