"""SQLite-backed storage for cases, collector runs and grouped findings."""

from __future__ import annotations

import os
import sqlite3
import threading
import time
from pathlib import Path

from .categories import CATEGORY_IDS


def default_home() -> Path:
    env = os.environ.get("OSINTIZER_HOME")
    if env:
        return Path(env).expanduser()
    xdg = os.environ.get("XDG_DATA_HOME")
    base = Path(xdg).expanduser() if xdg else Path.home() / ".local" / "share"
    return base / "osintizer"


SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS cases (
    id       INTEGER PRIMARY KEY,
    name     TEXT UNIQUE NOT NULL,
    target   TEXT DEFAULT '',
    scope    TEXT DEFAULT '',
    notes    TEXT DEFAULT '',
    created  REAL
);
CREATE TABLE IF NOT EXISTS runs (
    id             INTEGER PRIMARY KEY,
    case_id        INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    collector      TEXT NOT NULL,
    target         TEXT DEFAULT '',
    command        TEXT DEFAULT '',
    status         TEXT DEFAULT 'queued',
    output         TEXT DEFAULT '',
    error          TEXT DEFAULT '',
    started        REAL,
    finished       REAL,
    findings_new   INTEGER DEFAULT 0,
    findings_seen  INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY,
    case_id     INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    category    TEXT NOT NULL,
    value       TEXT NOT NULL,
    vkey        TEXT NOT NULL,
    detail      TEXT DEFAULT '',
    in_scope    INTEGER DEFAULT 1,
    status      TEXT DEFAULT 'new',
    starred     INTEGER DEFAULT 0,
    notes       TEXT DEFAULT '',
    first_seen  REAL,
    last_seen   REAL,
    hits        INTEGER DEFAULT 1,
    UNIQUE(case_id, category, vkey)
);
CREATE TABLE IF NOT EXISTS finding_sources (
    finding_id  INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    run_id      INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    PRIMARY KEY (finding_id, run_id)
);
CREATE INDEX IF NOT EXISTS idx_findings_case ON findings(case_id, category);
CREATE INDEX IF NOT EXISTS idx_runs_case ON runs(case_id);
"""

FINDING_STATUSES = ("new", "verified", "interesting", "false-positive")
MAX_OUTPUT = 2_000_000  # characters of raw tool output kept per run


class Store:
    def __init__(self, path: str | Path | None = None):
        if path is None:
            home = default_home()
            home.mkdir(parents=True, exist_ok=True)
            path = home / "osintizer.db"
        self.path = str(path)
        self._lock = threading.RLock()
        self.db = sqlite3.connect(self.path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        self.db.execute("PRAGMA journal_mode = WAL")
        # Any run left "running" by a previous crash can never finish.
        self.db.execute(
            "UPDATE runs SET status='interrupted', finished=? WHERE status IN ('running','queued')",
            (time.time(),),
        )
        self.db.commit()

    # ---------------------------------------------------------------- helpers
    def _q(self, sql, args=()):
        with self._lock:
            return [dict(r) for r in self.db.execute(sql, args).fetchall()]

    def _one(self, sql, args=()):
        rows = self._q(sql, args)
        return rows[0] if rows else None

    def _exec(self, sql, args=()):
        with self._lock:
            cur = self.db.execute(sql, args)
            self.db.commit()
            return cur

    # ------------------------------------------------------------------ cases
    def list_cases(self):
        return self._q(
            """SELECT c.*,
                      (SELECT COUNT(*) FROM findings f WHERE f.case_id=c.id) AS finding_count,
                      (SELECT COUNT(*) FROM runs r WHERE r.case_id=c.id) AS run_count
               FROM cases c ORDER BY c.created DESC"""
        )

    def get_case(self, case_id):
        return self._one("SELECT * FROM cases WHERE id=?", (case_id,))

    def find_case(self, ref):
        """Look a case up by numeric id or by name."""
        if ref is None:
            return self._one("SELECT * FROM cases ORDER BY created DESC LIMIT 1")
        if str(ref).isdigit():
            c = self.get_case(int(ref))
            if c:
                return c
        return self._one("SELECT * FROM cases WHERE name=?", (str(ref),))

    def create_case(self, name, target="", scope="", notes=""):
        name = (name or "").strip()
        if not name:
            raise ValueError("Case name is required")
        if self._one("SELECT id FROM cases WHERE name=?", (name,)):
            raise ValueError(f"A case named '{name}' already exists")
        cur = self._exec(
            "INSERT INTO cases(name,target,scope,notes,created) VALUES(?,?,?,?,?)",
            (name, target.strip(), normalize_scope(scope, target), notes, time.time()),
        )
        return self.get_case(cur.lastrowid)

    def update_case(self, case_id, **fields):
        allowed = {k: v for k, v in fields.items() if k in ("name", "target", "scope", "notes")}
        if "scope" in allowed:
            allowed["scope"] = normalize_scope(allowed["scope"], allowed.get("target", ""))
        if not allowed:
            return self.get_case(case_id)
        sets = ", ".join(f"{k}=?" for k in allowed)
        self._exec(f"UPDATE cases SET {sets} WHERE id=?", (*allowed.values(), case_id))
        if "scope" in allowed:
            self.rescope(case_id)
        return self.get_case(case_id)

    def delete_case(self, case_id):
        self._exec("DELETE FROM cases WHERE id=?", (case_id,))

    def scope_domains(self, case_id):
        case = self.get_case(case_id)
        if not case:
            return []
        return [d for d in case["scope"].split(",") if d]

    def rescope(self, case_id):
        """Re-evaluate in/out of scope for host-like findings after scope changes."""
        from .extractors import in_scope  # local import avoids a cycle

        scope = self.scope_domains(case_id)
        rows = self._q(
            "SELECT id, category, value FROM findings WHERE case_id=? AND category IN ('domains','subdomains','emails','urls','files')",
            (case_id,),
        )
        with self._lock:
            for r in rows:
                self.db.execute(
                    "UPDATE findings SET in_scope=? WHERE id=?",
                    (1 if in_scope(r["category"], r["value"], scope) else 0, r["id"]),
                )
            self.db.commit()

    # ------------------------------------------------------------------- runs
    def create_run(self, case_id, collector, target="", command="", status="queued"):
        cur = self._exec(
            "INSERT INTO runs(case_id,collector,target,command,status,started) VALUES(?,?,?,?,?,?)",
            (case_id, collector, target, command, status, time.time()),
        )
        return cur.lastrowid

    def update_run(self, run_id, **fields):
        allowed = {
            k: v for k, v in fields.items()
            if k in ("status", "output", "error", "finished", "findings_new", "findings_seen", "command")
        }
        if "output" in allowed and allowed["output"] and len(allowed["output"]) > MAX_OUTPUT:
            allowed["output"] = allowed["output"][:MAX_OUTPUT] + "\n[... output truncated by OSINTizer ...]\n"
        if not allowed:
            return
        sets = ", ".join(f"{k}=?" for k in allowed)
        self._exec(f"UPDATE runs SET {sets} WHERE id=?", (*allowed.values(), run_id))

    def list_runs(self, case_id):
        return self._q(
            """SELECT id, case_id, collector, target, command, status, error, started, finished,
                      findings_new, findings_seen, LENGTH(output) AS output_size
               FROM runs WHERE case_id=? ORDER BY id DESC""",
            (case_id,),
        )

    def get_run(self, run_id):
        return self._one("SELECT * FROM runs WHERE id=?", (run_id,))

    def delete_run(self, run_id):
        # Findings only ever found by this run go with it.
        with self._lock:
            orphan_ids = [
                r[0] for r in self.db.execute(
                    """SELECT finding_id FROM finding_sources WHERE run_id=?
                       AND finding_id NOT IN (SELECT finding_id FROM finding_sources WHERE run_id<>?)""",
                    (run_id, run_id),
                )
            ]
            self.db.execute("DELETE FROM runs WHERE id=?", (run_id,))
            for fid in orphan_ids:
                self.db.execute(
                    "DELETE FROM findings WHERE id=? AND starred=0 AND notes=''", (fid,)
                )
            self.db.commit()

    # --------------------------------------------------------------- findings
    def add_findings(self, case_id, run_id, items):
        """Upsert extracted findings. Returns (new_count, already_seen_count)."""
        now = time.time()
        new = seen = 0
        with self._lock:
            for it in items:
                cat = it["category"]
                if cat not in CATEGORY_IDS:
                    cat = "notes"
                value = str(it["value"]).strip()[:2000]
                if not value:
                    continue
                vkey = value.lower()
                detail = str(it.get("detail", ""))[:500]
                scope_flag = 1 if it.get("in_scope", True) else 0
                row = self.db.execute(
                    "SELECT id, detail FROM findings WHERE case_id=? AND category=? AND vkey=?",
                    (case_id, cat, vkey),
                ).fetchone()
                if row:
                    fid = row["id"]
                    merged = row["detail"]
                    if detail and detail.lower() not in merged.lower():
                        merged = (merged + "; " + detail).strip("; ")[:500]
                    already = self.db.execute(
                        "SELECT 1 FROM finding_sources WHERE finding_id=? AND run_id=?",
                        (fid, run_id),
                    ).fetchone() if run_id else None
                    if not already:
                        self.db.execute(
                            "UPDATE findings SET last_seen=?, hits=hits+1, detail=? WHERE id=?",
                            (now, merged, fid),
                        )
                        seen += 1
                else:
                    cur = self.db.execute(
                        """INSERT INTO findings(case_id,category,value,vkey,detail,in_scope,first_seen,last_seen)
                           VALUES(?,?,?,?,?,?,?,?)""",
                        (case_id, cat, value, vkey, detail, scope_flag, now, now),
                    )
                    fid = cur.lastrowid
                    new += 1
                if run_id:
                    self.db.execute(
                        "INSERT OR IGNORE INTO finding_sources(finding_id, run_id) VALUES(?,?)",
                        (fid, run_id),
                    )
            self.db.commit()
        return new, seen

    def list_findings(self, case_id, category=None):
        sql = """SELECT f.*,
                        (SELECT GROUP_CONCAT(DISTINCT r.collector) FROM finding_sources s
                         JOIN runs r ON r.id=s.run_id WHERE s.finding_id=f.id) AS sources
                 FROM findings f WHERE f.case_id=?"""
        args = [case_id]
        if category:
            sql += " AND f.category=?"
            args.append(category)
        sql += " ORDER BY f.category, f.starred DESC, f.vkey"
        rows = self._q(sql, args)
        for r in rows:
            r["sources"] = sorted(set((r["sources"] or "").split(","))) if r["sources"] else []
            r.pop("vkey", None)
        return rows

    def get_finding(self, fid):
        return self._one("SELECT * FROM findings WHERE id=?", (fid,))

    def update_finding(self, fid, **fields):
        allowed = {}
        if "status" in fields:
            if fields["status"] not in FINDING_STATUSES:
                raise ValueError(f"status must be one of {', '.join(FINDING_STATUSES)}")
            allowed["status"] = fields["status"]
        if "starred" in fields:
            allowed["starred"] = 1 if fields["starred"] else 0
        if "notes" in fields:
            allowed["notes"] = str(fields["notes"])[:5000]
        if "detail" in fields:
            allowed["detail"] = str(fields["detail"])[:500]
        if allowed:
            sets = ", ".join(f"{k}=?" for k in allowed)
            self._exec(f"UPDATE findings SET {sets} WHERE id=?", (*allowed.values(), fid))
        return self.get_finding(fid)

    def delete_finding(self, fid):
        self._exec("DELETE FROM findings WHERE id=?", (fid,))

    def category_counts(self, case_id):
        rows = self._q(
            "SELECT category, COUNT(*) AS n FROM findings WHERE case_id=? GROUP BY category",
            (case_id,),
        )
        return {r["category"]: r["n"] for r in rows}

    # ------------------------------------------------------------ portability
    def export_case(self, case_id):
        case = self.get_case(case_id)
        if not case:
            raise KeyError(case_id)
        runs = self._q("SELECT * FROM runs WHERE case_id=? ORDER BY id", (case_id,))
        return {
            "osintizer_export": 1,
            "case": case,
            "findings": self.list_findings(case_id),
            "runs": runs,
        }

    def import_case(self, data, rename=None):
        if data.get("osintizer_export") != 1:
            raise ValueError("Not an OSINTizer case export")
        src = data["case"]
        name = rename or src["name"]
        base, n = name, 2
        while self._one("SELECT id FROM cases WHERE name=?", (name,)):
            name = f"{base} ({n})"
            n += 1
        case = self.create_case(name, src.get("target", ""), src.get("scope", ""), src.get("notes", ""))
        run_map = {}
        for r in data.get("runs", []):
            rid = self.create_run(case["id"], r["collector"], r.get("target", ""), r.get("command", ""), r.get("status", "done"))
            self.update_run(rid, output=r.get("output", ""), error=r.get("error", ""),
                            finished=r.get("finished"), findings_new=r.get("findings_new", 0),
                            findings_seen=r.get("findings_seen", 0))
            run_map[r["collector"]] = rid
        for f in data.get("findings", []):
            run_id = run_map.get((f.get("sources") or [None])[0])
            self.add_findings(case["id"], run_id, [{
                "category": f["category"], "value": f["value"],
                "detail": f.get("detail", ""), "in_scope": f.get("in_scope", 1),
            }])
            row = self._one(
                "SELECT id FROM findings WHERE case_id=? AND category=? AND vkey=?",
                (case["id"], f["category"], str(f["value"]).strip().lower()),
            )
            if row:
                self.update_finding(row["id"], status=f.get("status", "new"),
                                    starred=f.get("starred", 0), notes=f.get("notes", ""))
        return case


def normalize_scope(scope, target=""):
    """Turn "Example.com, *.example.org" (+ the target) into a clean comma list."""
    items = []
    for raw in f"{scope or ''},{target or ''}".replace(" ", ",").split(","):
        d = raw.strip().lower().lstrip("*.").rstrip(".")
        if d.startswith("http://") or d.startswith("https://"):
            d = d.split("://", 1)[1].split("/", 1)[0]
        if "@" in d:
            d = d.split("@", 1)[1]
        if d and "." in d and not d.replace(".", "").isdigit() and d not in items:
            items.append(d)
    return ",".join(items)
