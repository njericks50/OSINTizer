"""Export a case as a Markdown report, CSV, or portable JSON."""

from __future__ import annotations

import csv
import io
import json
import time

from .categories import CATEGORIES


def _ts(t):
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(t)) if t else ""


def _md_escape(s: str) -> str:
    return str(s).replace("|", "\\|").replace("\n", " ")


def to_markdown(store, case_id, include_out_of_scope=False, include_false_positives=False) -> str:
    case = store.get_case(case_id)
    findings = store.list_findings(case_id)
    runs = store.list_runs(case_id)
    keep = [
        f for f in findings
        if (include_out_of_scope or f["in_scope"])
        and (include_false_positives or f["status"] != "false-positive")
    ]
    out = [f"# OSINTizer Report — {case['name']}", ""]
    out.append(f"- **Target:** {case['target'] or '—'}")
    out.append(f"- **Scope:** {case['scope'].replace(',', ', ') or '—'}")
    out.append(f"- **Generated:** {_ts(time.time())}")
    out.append(f"- **Collector runs:** {len(runs)}")
    out.append("")
    out.append("## Summary")
    out.append("")
    out.append("| Group | Count | Starred |")
    out.append("|---|---:|---:|")
    for c in CATEGORIES:
        items = [f for f in keep if f["category"] == c["id"]]
        if items:
            out.append(f"| {c['label']} | {len(items)} | {sum(1 for f in items if f['starred'])} |")
    out.append("")

    starred = [f for f in keep if f["starred"]]
    if starred:
        out.append("## ★ Key Findings")
        out.append("")
        for f in starred:
            label = next(c["label"] for c in CATEGORIES if c["id"] == f["category"])
            note = f" — {f['notes']}" if f["notes"] else ""
            out.append(f"- **{label}:** `{f['value']}`{note}")
        out.append("")

    for c in CATEGORIES:
        items = [f for f in keep if f["category"] == c["id"]]
        if not items:
            continue
        out.append(f"## {c['label']} ({len(items)})")
        out.append("")
        out.append("| ★ | Value | Detail | Status | Sources | Notes |")
        out.append("|---|---|---|---|---|---|")
        for f in items:
            out.append(
                f"| {'★' if f['starred'] else ''} | `{_md_escape(f['value'])}` | {_md_escape(f['detail'])} | "
                f"{f['status']} | {', '.join(f['sources'])} | {_md_escape(f['notes'])} |"
            )
        out.append("")

    if case["notes"].strip():
        out.append("## Analyst Notes")
        out.append("")
        out.append(case["notes"].strip())
        out.append("")

    out.append("## Collector Run Log")
    out.append("")
    out.append("| # | Collector | Target | Status | New | Started | Command |")
    out.append("|---:|---|---|---|---:|---|---|")
    for r in reversed(runs):
        out.append(
            f"| {r['id']} | {r['collector']} | {_md_escape(r['target'])} | {r['status']} | "
            f"{r['findings_new']} | {_ts(r['started'])} | `{_md_escape(r['command'])}` |"
        )
    out.append("")
    return "\n".join(out)


def to_csv(store, case_id) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["group", "value", "detail", "in_scope", "status", "starred", "sources", "hits",
                "first_seen", "notes"])
    labels = {c["id"]: c["label"] for c in CATEGORIES}
    for f in store.list_findings(case_id):
        w.writerow([labels.get(f["category"], f["category"]), f["value"], f["detail"],
                    "yes" if f["in_scope"] else "no", f["status"], "yes" if f["starred"] else "",
                    ";".join(f["sources"]), f["hits"], _ts(f["first_seen"]), f["notes"]])
    return buf.getvalue()


def to_json(store, case_id) -> str:
    return json.dumps(store.export_case(case_id), indent=2, default=str)
