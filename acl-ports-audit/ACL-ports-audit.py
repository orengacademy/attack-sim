#!/usr/bin/python3
"""Egress ACL audit: probe outbound TCP ports against an all-ports-open target
and compare the results with the expected policy.

Usage:
  ./ACL-ports-audit.py                                  # plain scan, as before
  ./ACL-ports-audit.py -p ACL-policy.csv                # scan + flag violations
  ./ACL-ports-audit.py -p ACL-policy.csv -b ACL-ports-audit.no-sdwan.out
  ./ACL-ports-audit.py -p ACL-policy.csv --csv               # auto-named CSV report
  ./ACL-ports-audit.py -p ACL-policy.csv --issues            # hide compliant rows
  ./ACL-ports-audit.py -p ACL-policy.csv -i ACL-ports-audit.with-sdwan.out   # check a saved scan

Policy file (CSV, '#' comments allowed):
  port,expected,service
  22,allow,SSH
  23,deny,Telnet
  445,vulnerable,SMB      (must be blocked; reported as CRITICAL if open)
  "default" sets the expectation for unlisted ports:  default,deny,

Terminal output uses 'rich' when available and stdout is a terminal. Redirected
output (> file.out) stays in the plain '<port> - OPEN|BLOCKED' format that
-i/-b read back.
"""

import argparse
import csv
import errno
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

try:
    from rich import box
    from rich.console import Console, Group
    from rich.panel import Panel
    from rich.progress import BarColumn, MofNCompleteColumn, Progress, TextColumn, TimeElapsedColumn
    from rich.table import Table
    from rich.text import Text
except ImportError:  # plain output fallback
    Console = None

PORTS = [20, 21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 123, 135, 137, 139, 143, 389, 443, 445, 464, 465, 587, 593, 636, 853, 873, 989, 990, 993, 995, 1025, 1080, 1194, 1337, 1433, 1521, 1723, 1883, 1935, 2048, 2049, 2065, 2082, 2083, 2086, 2087, 2095, 2096, 2222, 2375, 2376, 2525, 3128, 3268, 3269, 3306, 3333, 3389, 3478, 4443, 4444, 4445, 4899, 5004, 5060, 5061, 5222, 5223, 5228, 5432, 5554, 5555, 5672, 5800, 5900, 5901, 5902, 5938, 5984, 5985, 5986, 6000, 6379, 6443, 6568, 6667, 6697, 6881, 6882, 6883, 6884, 6885, 6886, 6887, 6888, 6889, 7070, 7777, 7778, 8000, 8008, 8009, 8080, 8081, 8082, 8118, 8181, 8291, 8383, 8443, 8801, 8802, 8883, 8888, 9000, 9001, 9030, 9050, 9090, 9150, 9200, 9418, 9443, 9995, 9996, 10000, 10250, 11211, 14444, 27017, 31337, 45700, 50050]

# target = 'portquiz.net'
TARGET = '143.198.95.35'

ALLOW_WORDS = {'allow', 'allowed', 'open', 'permit', 'permitted', 'yes', 'y', '1'}
DENY_WORDS = {'deny', 'denied', 'block', 'blocked', 'drop', 'closed', 'no', 'n', '0'}


def check_port(host, port, timeout):
    """Return (state, reason): state is OPEN or BLOCKED; reason says how it was blocked."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return 'OPEN', 'connected'
    except socket.timeout:
        return 'BLOCKED', 'timeout (dropped)'
    except ConnectionRefusedError:
        return 'BLOCKED', 'refused (RST)'
    except OSError as e:
        return 'BLOCKED', errno.errorcode.get(e.errno, str(e))


def service_name(port):
    try:
        return socket.getservbyport(port, 'tcp')
    except OSError:
        return ''


def load_policy(path):
    """Return ({port: (expected, service, vulnerable)}, default_expected_or_None)."""
    policy, default = {}, None
    with open(path, newline='') as f:
        rows = csv.reader(line for line in f if line.strip() and not line.lstrip().startswith('#'))
        for lineno, row in enumerate(rows, 1):
            row = [c.strip() for c in row] + ['', '']
            key, exp, svc = row[0].lower(), row[1].lower(), row[2]
            if key == 'port':
                continue  # header
            vulnerable = exp == 'vulnerable'
            if exp in ALLOW_WORDS:
                exp = 'OPEN'
            elif exp in DENY_WORDS or vulnerable:
                exp = 'BLOCKED'
            else:
                sys.exit(f'{path}: row {lineno}: unknown expectation {row[1]!r}')
            if key == 'default':
                default = exp
                continue
            # allow ranges like 5900-5902
            lo, _, hi = key.partition('-')
            for port in range(int(lo), int(hi or lo) + 1):
                policy[port] = (exp, svc, vulnerable)
    return policy, default


def load_baseline(path):
    """Parse a previous plain-scan output ('<port> - OPEN|BLOCKED') into {port: state}."""
    baseline = {}
    with open(path) as f:
        for line in f:
            parts = line.split(' - ')
            if len(parts) >= 2 and parts[0].strip().isdigit():
                baseline[int(parts[0])] = parts[1].split()[0].strip()
    return baseline


# verdict: (rank, severity, rich style, icon, section title, CSV finding)
VERDICTS = {
    'CRITICAL':     (1, 'critical', 'bold white on red', '✖', 'Vulnerable ports reachable',
                     'Vulnerable port is reachable - block immediately'),
    'LEAK':         (2, 'high', 'bold red', '▲', 'Should be BLOCKED but are OPEN',
                     'Policy denies this port but it is open'),
    'OVERBLOCK':    (3, 'medium', 'bold yellow', '▼', 'Should be OPEN but are BLOCKED',
                     'Policy allows this port but it is blocked'),
    'INCONCLUSIVE': (4, 'info', 'cyan', '?', 'Blocked in baseline too (not the ACL)',
                     'Blocked, but also blocked in baseline - likely ISP/target, not the ACL'),
    'UNDEFINED':    (5, 'info', 'magenta', '·', 'Not covered by policy',
                     'Port not covered by policy'),
    'OK':           (6, 'none', 'green', '✔', 'Compliant', ''),
}


def scan(target, ports, timeout, workers, advance=lambda: None):
    results = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(check_port, target, p, timeout): p for p in ports}
        for fut in as_completed(futures):
            results[futures[fut]] = fut.result()
            advance()
    return results


def evaluate(ports, results, policy, default, baseline, has_policy):
    rows = []
    for port in ports:
        actual, detail = results[port]
        expected, svc, vulnerable = policy.get(port, (default, '', False))
        verdict = None
        if has_policy:
            if expected is None:
                verdict = 'UNDEFINED'
            elif actual == expected:
                verdict = 'OK'
            elif actual == 'OPEN':
                verdict = 'CRITICAL' if vulnerable else 'LEAK'
            elif baseline.get(port) == 'BLOCKED':
                verdict = 'INCONCLUSIVE'
            else:
                verdict = 'OVERBLOCK'
        rows.append({
            'port': port,
            'service': svc or service_name(port),
            'expected': {'OPEN': 'ALLOW', 'BLOCKED': 'DENY'}.get(expected, '-') + (' (vuln)' if vulnerable else ''),
            'actual': actual,
            'detail': detail,
            'baseline': baseline.get(port, ''),
            'verdict': verdict,
        })
    return rows


def label(row):
    return f"{row['port']}/{row['service']}" if row['service'] else str(row['port'])


def render_rich(console, meta, rows, counts, show_ok):
    info = Table.grid(padding=(0, 2))
    info.add_column(style='bold cyan', justify='right')
    info.add_column()
    for k, v in meta.items():
        if v:
            info.add_row(k, str(v))
    console.print(Panel(info, title='[bold]Egress ACL Audit[/]', title_align='left',
                        border_style='blue', box=box.ROUNDED, expand=False))

    has_policy = counts is not None
    table = Table(box=box.SIMPLE_HEAD, header_style='bold', pad_edge=False, show_edge=False)
    table.add_column('Port', justify='right', style='bold')
    table.add_column('Service')
    if has_policy:
        table.add_column('Expected')
    table.add_column('Actual')
    table.add_column('Detail', style='dim')
    if has_policy:
        table.add_column('Verdict')
    hidden = 0
    for r in rows:
        if has_policy and r['verdict'] == 'OK' and not show_ok:
            hidden += 1
            continue
        actual = Text(r['actual'], style='bold green' if r['actual'] == 'OPEN' else 'red')
        cells = [str(r['port']), r['service']]
        if has_policy:
            exp_style = 'red' if 'vuln' in r['expected'] else ''
            cells.append(Text(r['expected'], style=exp_style))
        cells += [actual, r['detail']]
        style = None
        if has_policy:
            _, _, vstyle, icon, _, _ = VERDICTS[r['verdict']]
            cells.append(Text(f' {icon} {r["verdict"]} ', style=vstyle))
            style = 'dim' if r['verdict'] == 'OK' else None
        table.add_row(*cells, style=style)
    if hidden:
        table.caption = f'{hidden} compliant ports hidden (drop --issues to show)'
    console.print(table)

    if not has_policy:
        open_n = sum(r['actual'] == 'OPEN' for r in rows)
        console.print(f'[bold green]{open_n} open[/]  [red]{len(rows) - open_n} blocked[/]  of {len(rows)} ports')
        return

    for verdict, (_, _, vstyle, icon, title, _) in VERDICTS.items():
        hits = [r for r in rows if r['verdict'] == verdict]
        if verdict == 'OK' or not hits:
            continue
        color = vstyle.split()[-1]
        body = Text(', ').join(Text(label(r)) for r in hits)
        console.print(Panel(body, title=f'[{vstyle}] {icon} {verdict} [/] {title} ({len(hits)})',
                            title_align='left', border_style=color, box=box.ROUNDED, expand=False))

    badges = Text('  ').join(
        Text(f' {VERDICTS[v][3]} {v} {n} ', style=VERDICTS[v][2] if n else 'dim')
        for v, n in counts.items())
    failed = counts['CRITICAL'] + counts['LEAK'] + counts['OVERBLOCK']
    status = (Text(' FAIL ', style='bold white on red') + Text(f'  {failed} violation(s)', style='bold red')
              if failed else Text(' PASS ', style='bold white on green') + Text('  matches policy', style='green'))
    console.print(Panel(Group(badges, Text(), status), title='[bold]Summary[/]', title_align='left',
                        border_style='red' if failed else 'green', box=box.ROUNDED, expand=False))


def render_plain(meta, rows, counts):
    if counts is None:  # same format -i/-b parse
        for r in rows:
            print(f"{r['port']} - {r['actual']}")
        return
    for k, v in meta.items():
        if v:
            print(f'{k}: {v}')
    print(f'\n{"PORT":>6}  {"SERVICE":<16}{"EXPECTED":<14}{"ACTUAL":<9}{"DETAIL":<20}VERDICT')
    for r in rows:
        mark = '' if r['verdict'] == 'OK' else '  <--'
        print(f"{r['port']:>6}  {r['service'][:15]:<16}{r['expected']:<14}{r['actual']:<9}"
              f"{r['detail']:<20}{r['verdict']}{mark}")
    for verdict, (_, _, _, _, title, _) in VERDICTS.items():
        hits = [label(r) for r in rows if r['verdict'] == verdict]
        if verdict != 'OK' and hits:
            print(f'\n{verdict} - {title} ({len(hits)}):\n  ' + ', '.join(hits))
    print('\nSummary: ' + ', '.join(f'{k}={v}' for k, v in counts.items()))


def write_csv(path, meta, rows):
    fields = ['scan_time', 'source', 'policy', 'port', 'protocol', 'service', 'expected', 'actual',
              'detail', 'baseline', 'verdict', 'severity', 'finding']
    ordered = sorted(rows, key=lambda r: (VERDICTS[r['verdict']][0] if r['verdict'] else 0, r['port']))
    with open(path, 'w', newline='', encoding='utf-8-sig') as f:  # BOM so Excel detects UTF-8
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in ordered:
            v = VERDICTS.get(r['verdict'])
            w.writerow({
                'scan_time': meta['Time'],
                'source': meta.get('Target') or meta.get('Input'),
                'policy': meta.get('Policy') or '',
                'port': r['port'],
                'protocol': 'tcp',
                'service': r['service'],
                'expected': r['expected'],
                'actual': r['actual'],
                'detail': r['detail'],
                'baseline': r['baseline'],
                'verdict': r['verdict'] or '',
                'severity': v[1] if v else '',
                'finding': v[5] if v else '',
            })


def main():
    ap = argparse.ArgumentParser(description='Egress ACL port audit')
    ap.add_argument('-t', '--target', default=TARGET, help='IPv4/IPv6 address or hostname (default: %(default)s)')
    ap.add_argument('-p', '--policy', help='CSV of port,expected(allow/deny/vulnerable),service')
    ap.add_argument('-i', '--input', help='check a saved scan output instead of scanning live')
    ap.add_argument('-b', '--baseline', help='scan output taken without the ACL (e.g. no-sdwan run)')
    ap.add_argument('--timeout', type=float, default=2)
    ap.add_argument('--workers', type=int, default=32)
    ap.add_argument('--csv', nargs='?', const='', metavar='FILE',
                    help='write a CSV report (auto-named acl-audit-<time>.csv if FILE omitted)')
    ap.add_argument('--issues', action='store_true', help='hide compliant rows in the table')
    ap.add_argument('--plain', action='store_true', help='plain text output, no colours/tables')
    args = ap.parse_args()

    console = Console(highlight=False) if Console and not args.plain and sys.stdout.isatty() else None
    policy, default = load_policy(args.policy) if args.policy else ({}, None)
    baseline = load_baseline(args.baseline) if args.baseline else {}
    started = datetime.now()

    if args.input:
        saved = load_baseline(args.input)
        ports = sorted(saved)
        results = {p: (state, 'saved scan') for p, state in saved.items()}
    else:
        ports = sorted(set(PORTS) | set(policy))
        t0 = time.monotonic()
        if console:
            with Progress(TextColumn('[cyan]Scanning {task.description}'), BarColumn(), MofNCompleteColumn(),
                          TimeElapsedColumn(), console=console, transient=True) as prog:
                task = prog.add_task(args.target, total=len(ports))
                results = scan(args.target, ports, args.timeout, args.workers, lambda: prog.advance(task))
        else:
            results = scan(args.target, ports, args.timeout, args.workers)
        elapsed = time.monotonic() - t0

    meta = {
        'Target': None if args.input else args.target,
        'Input': args.input,
        'Policy': args.policy,
        'Baseline': args.baseline,
        'Ports': len(ports),
        'Time': started.strftime('%Y-%m-%d %H:%M:%S'),
        'Duration': None if args.input else f'{elapsed:.1f}s',
    }
    rows = evaluate(ports, results, policy, default, baseline, bool(args.policy))
    counts = None
    if args.policy:
        counts = {v: 0 for v in VERDICTS}
        for r in rows:
            counts[r['verdict']] += 1

    if console:
        render_rich(console, meta, rows, counts, show_ok=not args.issues)
    else:
        render_plain(meta, rows, counts)

    if args.csv is not None:
        path = args.csv or f"acl-audit-{started.strftime('%Y%m%d-%H%M%S')}.csv"
        write_csv(path, meta, rows)
        msg = f'CSV report written to {path}'
        console.print(f'[dim]{msg}[/]') if console else print(msg, file=sys.stderr)

    if counts and (counts['CRITICAL'] or counts['LEAK'] or counts['OVERBLOCK']):
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
