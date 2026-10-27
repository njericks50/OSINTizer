"""OSINTizer command line.

  osintizer                       start the dashboard (http://127.0.0.1:8787)
  osintizer doctor                show which Kali tools are installed
  osintizer case new NAME -t acme.com [-s "acme.com,acme.io"]
  osintizer case list
  osintizer run COLLECTOR TARGET [-c CASE] [--args "..."]
  osintizer ingest [FILE|-] [-c CASE] [--tool sherlock]   (e.g. sherlock jdoe | osintizer ingest --tool sherlock)
  osintizer findings [-c CASE] [--group emails]
  osintizer export [-c CASE] [-f md|csv|json] [-o FILE]
  osintizer import FILE.json
"""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from . import collectors as C
from .categories import CATEGORIES, CATEGORY_IDS, LABELS
from .reports import to_csv, to_json, to_markdown
from .runner import Runner
from .store import Store

BLUE, GREEN, YELLOW, RED, DIM, BOLD, RESET = (
    ("\033[34m", "\033[32m", "\033[33m", "\033[31m", "\033[2m", "\033[1m", "\033[0m")
    if sys.stdout.isatty() else ("",) * 7
)

BANNER = rf"""{BLUE}
   ___  ____ ___ _   _ _____ _
  / _ \/ ___|_ _| \ | |_   _(_)_______ _ __
 | | | \___ \| ||  \| | | | | |_  / _ \ '__|
 | |_| |___) | || |\  | | | | |/ /  __/ |
  \___/|____/___|_| \_| |_| |_/___\___|_|   {RESET}{DIM}v{__version__}{RESET}
"""


def _case(store, ref, create_from_target=None):
    case = store.find_case(ref)
    if case:
        return case
    if ref is None and create_from_target:
        print(f"{DIM}No cases yet - creating one for {create_from_target}{RESET}")
        return store.create_case(create_from_target, create_from_target)
    sys.exit(f"{RED}No case '{ref}'. Create one with: osintizer case new NAME -t TARGET{RESET}")


def cmd_serve(a, store):
    from .server import serve
    print(BANNER)
    serve(store, Runner(store), a.host, a.port, not a.no_browser)


def cmd_doctor(a, store):
    print(BANNER)
    missing = []
    print(f"{BOLD}Collectors{RESET}")
    for c in C.COLLECTORS:
        ok = c.installed()
        mark = f"{GREEN}✔{RESET}" if ok else f"{RED}✘{RESET}"
        where = c.binary_path() or ("built in" if c.builtin else c.install)
        tag = f" {YELLOW}[active]{RESET}" if c.active else ""
        print(f"  {mark} {c.name:<22}{tag} {DIM}{where}{RESET}")
        if not ok:
            missing.append(c)
    apt = sorted({c.install.split()[-1] for c in missing if c.install.startswith("sudo apt")})
    pipx = sorted({c.install.split()[-1] for c in missing if c.install.startswith("pipx")})
    if apt or pipx:
        print(f"\n{BOLD}Install the missing ones:{RESET}")
        if apt:
            print(f"  sudo apt update && sudo apt install -y {' '.join(apt)}")
        if pipx:
            print(f"  pipx install {' && pipx install '.join(pipx)}")
    print(f"\n{DIM}Database: {store.path}{RESET}")


def cmd_case(a, store):
    if a.action == "list":
        cases = store.list_cases()
        if not cases:
            print("No cases yet.")
        for c in cases:
            print(f"  {BOLD}{c['id']:>3}{RESET}  {c['name']:<32} {DIM}{c['target'] or '':<24}{RESET} "
                  f"{c['finding_count']:>5} findings  {c['run_count']:>3} runs")
    elif a.action == "new":
        if not a.name:
            sys.exit("Usage: osintizer case new NAME -t TARGET")
        try:
            c = store.create_case(a.name, a.target or "", a.scope or "")
        except ValueError as e:
            sys.exit(f"{RED}{e}{RESET}")
        print(f"{GREEN}Created case #{c['id']} {c['name']}{RESET} (scope: {c['scope'] or 'none'})")
    elif a.action == "delete":
        c = _case(store, a.name)
        store.delete_case(c["id"])
        print(f"Deleted case {c['name']}")


def cmd_run(a, store):
    case = _case(store, a.case, create_from_target=a.target)
    col = C.BY_ID.get(a.collector)
    if not col:
        sys.exit(f"{RED}Unknown collector '{a.collector}'. Options: {', '.join(C.BY_ID)}{RESET}")
    if col.active and not a.active:
        sys.exit(f"{YELLOW}{col.name} is an ACTIVE collector (sends traffic to the target). "
                 f"Re-run with --active if you're authorized.{RESET}")
    runner = Runner(store)
    print(f"{BLUE}▸{RESET} {col.name} → {a.target}  {DIM}(case: {case['name']}){RESET}")
    stream = (lambda s: sys.stdout.write(f"{DIM}{s}{RESET}")) if a.verbose else None
    try:
        run_id = runner.start(case["id"], col.id, a.target, a.args, wait=True, on_output=stream)
    except C.TargetError as e:
        sys.exit(f"{RED}{e}{RESET}")
    run = store.get_run(run_id)
    color = GREEN if run["status"] == "done" else RED
    print(f"{color}{run['status']}{RESET}: +{run['findings_new']} new, {run['findings_seen']} already known"
          + (f"  {RED}{run['error']}{RESET}" if run["error"] else ""))
    _print_counts(store, case["id"])


def cmd_ingest(a, store):
    case = _case(store, a.case, create_from_target=a.target or "pasted-output")
    if a.file in (None, "-"):
        if sys.stdin.isatty():
            sys.exit("Pipe tool output in, or give a file: osintizer ingest results.txt")
        text = sys.stdin.read()
    else:
        with open(a.file, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    runner = Runner(store)
    try:
        _, (new, seen) = runner.ingest(case["id"], text, a.tool, a.file or "stdin", a.target or "")
    except ValueError as e:
        sys.exit(f"{RED}{e}{RESET}")
    print(f"{GREEN}Filed into '{case['name']}':{RESET} +{new} new, {seen} already known")
    _print_counts(store, case["id"])


def _print_counts(store, case_id):
    counts = store.category_counts(case_id)
    if counts:
        print("  " + "  ".join(f"{LABELS[c]}: {BOLD}{counts[c]}{RESET}" for c in CATEGORY_IDS if counts.get(c)))


def cmd_findings(a, store):
    case = _case(store, a.case)
    rows = store.list_findings(case["id"], a.group)
    for cat in CATEGORIES:
        items = [f for f in rows if f["category"] == cat["id"] and (a.all or f["in_scope"])]
        if not items:
            continue
        print(f"\n{BLUE}{BOLD}{cat['label']}{RESET} {DIM}({len(items)}){RESET}")
        for f in items:
            star = f"{YELLOW}★{RESET} " if f["starred"] else "  "
            detail = f"  {DIM}{f['detail']}{RESET}" if f["detail"] else ""
            print(f"  {star}{f['value']}{detail}")


def cmd_export(a, store):
    case = _case(store, a.case)
    content = {"md": lambda: to_markdown(store, case["id"], a.all, a.all),
               "csv": lambda: to_csv(store, case["id"]),
               "json": lambda: to_json(store, case["id"])}[a.format]()
    if a.output:
        with open(a.output, "w", encoding="utf-8") as fh:
            fh.write(content)
        print(f"{GREEN}Wrote {a.output}{RESET}")
    else:
        sys.stdout.write(content)


def cmd_import(a, store):
    with open(a.file, encoding="utf-8") as fh:
        data = json.load(fh)
    try:
        c = store.import_case(data, a.name)
    except (KeyError, ValueError) as e:
        sys.exit(f"{RED}Import failed: {e}{RESET}")
    print(f"{GREEN}Imported as case #{c['id']} {c['name']}{RESET}")


def build_parser():
    p = argparse.ArgumentParser(prog="osintizer", description="Collect, auto-extract and organize OSINT recon findings.")
    p.add_argument("--version", action="version", version=f"OSINTizer {__version__}")
    p.add_argument("--db", help="database file (default ~/.local/share/osintizer/osintizer.db)")
    sub = p.add_subparsers(dest="cmd")

    s = sub.add_parser("serve", help="start the web dashboard (default)")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8787)
    s.add_argument("--no-browser", action="store_true")

    sub.add_parser("doctor", help="check which collectors are installed")

    s = sub.add_parser("case", help="manage cases")
    s.add_argument("action", choices=["list", "new", "delete"])
    s.add_argument("name", nargs="?")
    s.add_argument("-t", "--target")
    s.add_argument("-s", "--scope", help="comma-separated in-scope domains")

    s = sub.add_parser("run", help="run a collector and file its findings")
    s.add_argument("collector", choices=list(C.BY_ID))
    s.add_argument("target")
    s.add_argument("-c", "--case", help="case name or id (default: most recent)")
    s.add_argument("--args", help='override the argument template, e.g. "-d {target} -b all"')
    s.add_argument("-v", "--verbose", action="store_true", help="stream tool output")
    s.add_argument("--active", action="store_true", help="allow an active collector (nmap, whatweb)")

    s = sub.add_parser("ingest", help="file tool output (file or stdin) into findings")
    s.add_argument("file", nargs="?")
    s.add_argument("-c", "--case")
    s.add_argument("--tool", default="auto", help="parser to use: " + ", ".join(["auto", *C.BY_ID]))
    s.add_argument("-t", "--target", help="what the tool was run against")

    s = sub.add_parser("findings", help="print grouped findings")
    s.add_argument("-c", "--case")
    s.add_argument("-g", "--group", choices=CATEGORY_IDS)
    s.add_argument("-a", "--all", action="store_true", help="include out-of-scope")

    s = sub.add_parser("export", help="export a report")
    s.add_argument("-c", "--case")
    s.add_argument("-f", "--format", choices=["md", "csv", "json"], default="md")
    s.add_argument("-o", "--output")
    s.add_argument("-a", "--all", action="store_true", help="include out-of-scope and false positives")

    s = sub.add_parser("import", help="import a case backup (.json)")
    s.add_argument("file")
    s.add_argument("--name", help="import under a different case name")
    return p


def main(argv=None):
    p = build_parser()
    a = p.parse_args(argv)
    store = Store(a.db)
    cmd = a.cmd or "serve"
    if cmd == "serve" and not hasattr(a, "host"):
        a.host, a.port, a.no_browser = "127.0.0.1", 8787, False
    handlers = {
        "serve": cmd_serve, "doctor": cmd_doctor, "case": cmd_case, "run": cmd_run,
        "ingest": cmd_ingest, "findings": cmd_findings, "export": cmd_export, "import": cmd_import,
    }
    try:
        handlers[cmd](a, store)
    except KeyboardInterrupt:
        return 130
    except BrokenPipeError:
        return 0
    return 0
