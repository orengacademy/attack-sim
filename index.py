#!/usr/bin/env python3
"""
index.py — a rebuildable SQLite index over the evidence/ tree.

Why: each run's evidence files stay the AUTHORITATIVE record (CLAUDE.md: the raw
.log files are ground truth). This builds a *derived* index on top of them so you
can query ACROSS runs/targets/fleet — "every SUCCESS on 159 this week", per-MITRE
rollups, trend lines — without that query layer becoming a second source of truth.
It is pure stdlib (sqlite3), so the engine keeps its no-dependency guarantee, and
it can be dropped and rebuilt from evidence/ at any time (nothing lives only here).

Usage:
    python3 index.py --rebuild                 # (re)build evidence_index.db from evidence/
    python3 index.py --stats                    # quick rollup (verdicts x targets)
    python3 index.py --query "SELECT ..."       # ad-hoc read-only SQL
    python3 index.py --verdict SUCCESS --target 159.223.35.108 --limit 20
The web app (app.py) builds/queries the same DB via /api/query + /api/reindex.
"""
import argparse
import glob
import json
import os
import sqlite3
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
EVID = os.path.join(HERE, "evidence")
DB_DEFAULT = os.path.join(HERE, "evidence_index.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
  run_id TEXT PRIMARY KEY,         -- evidence dir name (run_<ts>[__target] / fleet .../src__tgt)
  ts TEXT, started TEXT, mode TEXT, target_ip TEXT, appliance_ip TEXT,
  site_id TEXT, module_count INTEGER, harness_version TEXT, engine_version TEXT,
  source_ip TEXT, path TEXT
);
CREATE TABLE IF NOT EXISTS results (
  run_id TEXT, iteration INTEGER, attack_id TEXT, attack TEXT, category TEXT,
  verdict TEXT,                    -- unified short label (appliance leg if dual, else baseline)
  baseline_result TEXT, appliance_result TEXT, detail TEXT,
  target_ip TEXT, mode TEXT, site_id TEXT, test_type TEXT, family TEXT, direction TEXT,
  mitre TEXT, cwe TEXT, cve TEXT, duration_s REAL, ts TEXT,
  PRIMARY KEY (run_id, target_ip, attack_id, iteration)
);
CREATE INDEX IF NOT EXISTS ix_results_verdict ON results(verdict);
CREATE INDEX IF NOT EXISTS ix_results_target  ON results(target_ip);
CREATE INDEX IF NOT EXISTS ix_results_site    ON results(site_id);
CREATE INDEX IF NOT EXISTS ix_results_attack  ON results(attack_id);
"""

# columns a caller may filter on via the web /api/query (whitelist — never
# interpolate user text into SQL; everything else goes through ? placeholders).
FILTER_COLS = {"verdict", "target_ip", "site_id", "category", "attack_id",
               "test_type", "family", "mode", "run_id"}


def connect(db_path=DB_DEFAULT):
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    con.executescript(SCHEMA)
    return con


def _short_verdict(meta, r):
    """The unified short label: the appliance leg when this was a dual-path run,
    else the baseline leg — mirrors Evidence.finalize()/the reports."""
    if r.get("appliance_ip") is not None:
        return r.get("appliance_result") or "?"
    return r.get("baseline_result") or "?"


def _iter_summaries(evidence_dir=EVID):
    """Yield (run_id, path, summary_dict) for every summary.json under evidence/."""
    for sp in sorted(glob.glob(os.path.join(evidence_dir, "**", "summary.json"),
                               recursive=True)):
        d = os.path.dirname(sp)
        # the per-run fleet_summary.json lives at the fleet root — skip the
        # aggregate, we only want per-(source,target) run summaries.
        if os.path.basename(sp) != "summary.json":
            continue
        run_id = os.path.relpath(d, evidence_dir)
        try:
            with open(sp) as f:
                yield run_id, os.path.relpath(d, HERE), json.load(f)
        except Exception as e:
            sys.stderr.write(f"[index] skip {run_id}: {e}\n")


def rebuild(db_path=DB_DEFAULT, evidence_dir=EVID):
    """Drop and rebuild the index from scratch (idempotent, safe to re-run)."""
    if os.path.exists(db_path):
        os.remove(db_path)
    con = connect(db_path)
    nruns = nres = 0
    with con:
        for run_id, path, s in _iter_summaries(evidence_dir):
            m = s.get("meta", {}) or {}
            rows = s.get("results", []) or []
            con.execute(
                "INSERT OR REPLACE INTO runs VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (run_id, m.get("run", ""), m.get("started", ""), m.get("mode", ""),
                 m.get("target_ip", ""),
                 (rows[0].get("appliance_ip") if rows else None),
                 m.get("site_id", "") or (rows[0].get("site_id", "") if rows else ""),
                 m.get("module_count", len(rows)), m.get("harness_version", ""),
                 m.get("engine_version", ""), m.get("source_ip", ""), path))
            nruns += 1
            for r in rows:
                con.execute(
                    "INSERT OR REPLACE INTO results VALUES "
                    "(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (run_id, r.get("iteration", 1), r.get("attack_id", ""),
                     r.get("attack", ""), r.get("category", ""),
                     _short_verdict(m, r), r.get("baseline_result", ""),
                     r.get("appliance_result", ""), r.get("verdict", ""),
                     r.get("target_ip", "") or m.get("target_ip", ""),
                     r.get("mode", "") or m.get("mode", ""), r.get("site_id", ""),
                     r.get("test_type", ""), r.get("family", ""), r.get("direction", ""),
                     ", ".join(r.get("mitre", []) or []), ", ".join(r.get("cwe", []) or []),
                     r.get("cve", ""), r.get("duration_s", 0.0), r.get("timestamp", "")))
                nres += 1
    con.close()
    return nruns, nres


def query(db_path=DB_DEFAULT, filters=None, q=None, limit=500):
    """Parameterised cross-run query. `filters` is a {column: value} dict limited
    to FILTER_COLS; `q` is a free-text LIKE over attack/detail/mitre/cwe. Read-only."""
    con = connect(db_path)
    where, params = [], []
    for col, val in (filters or {}).items():
        if col in FILTER_COLS and val:
            where.append(f"{col} = ?")
            params.append(val)
    if q:
        where.append("(attack LIKE ? OR detail LIKE ? OR mitre LIKE ? OR cwe LIKE ? "
                     "OR attack_id LIKE ? OR category LIKE ?)")
        params += ["%" + q + "%"] * 6
    sql = "SELECT * FROM results"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY ts DESC, run_id DESC LIMIT ?"
    params.append(max(1, min(int(limit or 500), 5000)))
    rows = [dict(r) for r in con.execute(sql, params).fetchall()]
    con.close()
    return rows


def stats(db_path=DB_DEFAULT):
    """Rollup: verdict counts overall, and a verdict x target matrix."""
    con = connect(db_path)
    overall = {r["verdict"]: r["n"] for r in con.execute(
        "SELECT verdict, COUNT(*) n FROM results GROUP BY verdict ORDER BY n DESC")}
    by_target = [dict(r) for r in con.execute(
        "SELECT target_ip, verdict, COUNT(*) n FROM results "
        "GROUP BY target_ip, verdict ORDER BY target_ip, n DESC")]
    nruns = con.execute("SELECT COUNT(*) n FROM runs").fetchone()["n"]
    con.close()
    return {"runs": nruns, "overall": overall, "by_target": by_target}


def main():
    ap = argparse.ArgumentParser(description="SQLite index over the evidence/ tree.")
    ap.add_argument("--db", default=DB_DEFAULT, help="index db path")
    ap.add_argument("--evidence", default=EVID, help="evidence dir to index")
    ap.add_argument("--rebuild", action="store_true", help="(re)build the index from evidence/")
    ap.add_argument("--stats", action="store_true", help="print a verdict rollup")
    ap.add_argument("--query", help="ad-hoc read-only SQL (SELECT only)")
    ap.add_argument("--verdict"), ap.add_argument("--target"), ap.add_argument("--site")
    ap.add_argument("--limit", type=int, default=50)
    args = ap.parse_args()

    if args.rebuild or not os.path.exists(args.db):
        nr, nres = rebuild(args.db, args.evidence)
        print(f"[index] built {args.db}: {nr} runs, {nres} results")
    if args.query:
        if not args.query.lstrip().lower().startswith("select"):
            print("[index] only SELECT is allowed via --query", file=sys.stderr)
            return 2
        con = connect(args.db)
        for row in con.execute(args.query).fetchall():
            print(dict(row))
        con.close()
    if args.verdict or args.target or args.site:
        f = {"verdict": args.verdict, "target_ip": args.target, "site_id": args.site}
        for r in query(args.db, {k: v for k, v in f.items() if v}, limit=args.limit):
            print(f"{r['ts']:<20} {r['verdict']:<14} {r['target_ip']:<16} "
                  f"{r['attack_id']:<22} {r['run_id']}")
    if args.stats:
        st = stats(args.db)
        print(f"runs indexed: {st['runs']}")
        print("overall:", st["overall"])
        print("by target:")
        for row in st["by_target"]:
            print(f"  {row['target_ip']:<16} {row['verdict']:<14} {row['n']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
