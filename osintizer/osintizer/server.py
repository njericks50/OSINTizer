"""Local web dashboard (Python standard library only - nothing to pip install)."""

from __future__ import annotations

import json
import mimetypes
import re
import threading
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from . import __version__
from . import collectors as C
from .categories import CATEGORIES
from .extractors import detect_type
from .reports import to_csv, to_json, to_markdown
from .store import FINDING_STATUSES

STATIC = Path(__file__).parent / "static"
MAX_BODY = 25 * 1024 * 1024


class ApiError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


def make_handler(store, runner, allowed_hosts):
    routes = []

    def route(method, pattern):
        rx = re.compile("^" + pattern + "$")

        def deco(fn):
            routes.append((method, rx, fn))
            return fn
        return deco

    def need_case(cid):
        case = store.get_case(int(cid))
        if not case:
            raise ApiError(404, "Case not found")
        return case

    # ------------------------------------------------------------------ meta
    @route("GET", r"/api/meta")
    def meta(h, q, body):
        return {
            "version": __version__,
            "categories": CATEGORIES,
            "statuses": FINDING_STATUSES,
            "collectors": [c.to_dict() for c in C.COLLECTORS],
            "db": store.path,
        }

    @route("GET", r"/api/detect")
    def detect(h, q, body):
        t = q.get("target", [""])[0]
        kind = detect_type(t)
        return {"type": kind, "collectors": [c.id for c in C.matching_collectors(t)]}

    # ----------------------------------------------------------------- cases
    @route("GET", r"/api/cases")
    def cases(h, q, body):
        return store.list_cases()

    @route("POST", r"/api/cases")
    def new_case(h, q, body):
        try:
            return store.create_case(body.get("name", ""), body.get("target", ""),
                                     body.get("scope", ""), body.get("notes", ""))
        except ValueError as e:
            raise ApiError(400, str(e))

    @route("PATCH", r"/api/cases/(\d+)")
    def patch_case(h, q, body, cid):
        need_case(cid)
        return store.update_case(int(cid), **body)

    @route("DELETE", r"/api/cases/(\d+)")
    def del_case(h, q, body, cid):
        need_case(cid)
        store.delete_case(int(cid))
        return {"ok": True}

    @route("POST", r"/api/cases/import")
    def import_case(h, q, body):
        try:
            return store.import_case(body)
        except (KeyError, ValueError) as e:
            raise ApiError(400, f"Import failed: {e}")

    # -------------------------------------------------------------- findings
    @route("GET", r"/api/cases/(\d+)/findings")
    def findings(h, q, body, cid):
        need_case(cid)
        return store.list_findings(int(cid))

    @route("POST", r"/api/cases/(\d+)/findings")
    def add_finding(h, q, body, cid):
        need_case(cid)
        cat, value = body.get("category"), (body.get("value") or "").strip()
        if not value:
            raise ApiError(400, "Value is required")
        run_id = store.create_run(int(cid), "manual", "", "(added by hand)", "done")
        new, _ = store.add_findings(int(cid), run_id, [{
            "category": cat, "value": value, "detail": body.get("detail", ""), "in_scope": True,
        }])
        store.update_run(run_id, findings_new=new)
        return {"new": new}

    @route("PATCH", r"/api/findings/(\d+)")
    def patch_finding(h, q, body, fid):
        if not store.get_finding(int(fid)):
            raise ApiError(404, "Finding not found")
        try:
            return store.update_finding(int(fid), **body)
        except ValueError as e:
            raise ApiError(400, str(e))

    @route("DELETE", r"/api/findings/(\d+)")
    def del_finding(h, q, body, fid):
        store.delete_finding(int(fid))
        return {"ok": True}

    # ------------------------------------------------------------------ runs
    @route("GET", r"/api/cases/(\d+)/runs")
    def runs(h, q, body, cid):
        need_case(cid)
        return store.list_runs(int(cid))

    @route("POST", r"/api/cases/(\d+)/runs")
    def start_run(h, q, body, cid):
        need_case(cid)
        ids = body.get("collectors") or [body.get("collector")]
        args = body.get("args") or {}
        started, errors = [], []
        allow_active = bool(body.get("allow_active"))
        for col_id in ids:
            col = C.BY_ID.get(col_id)
            if col and col.active and not allow_active:
                errors.append({"collector": col_id, "error": f"{col.name} is active - enable 'Allow active collectors' first"})
                continue
            try:
                started.append(runner.start(int(cid), col_id, body.get("target", ""),
                                            args.get(col_id) if isinstance(args, dict) else args))
            except C.TargetError as e:
                errors.append({"collector": col_id, "error": str(e)})
        if not started and errors:
            raise ApiError(400, errors[0]["error"])
        return {"started": started, "errors": errors}

    @route("GET", r"/api/runs/(\d+)")
    def get_run(h, q, body, rid):
        run = store.get_run(int(rid))
        if not run:
            raise ApiError(404, "Run not found")
        return run

    @route("POST", r"/api/runs/(\d+)/cancel")
    def cancel_run(h, q, body, rid):
        return {"cancelled": runner.cancel(int(rid))}

    @route("DELETE", r"/api/runs/(\d+)")
    def del_run(h, q, body, rid):
        store.delete_run(int(rid))
        return {"ok": True}

    @route("POST", r"/api/cases/(\d+)/ingest")
    def ingest(h, q, body, cid):
        need_case(cid)
        try:
            run_id, (new, seen) = runner.ingest(int(cid), body.get("text", ""), body.get("tool", "auto"),
                                                body.get("label", ""), body.get("target", ""))
        except ValueError as e:
            raise ApiError(400, str(e))
        return {"run": run_id, "new": new, "seen": seen}

    # ---------------------------------------------------------------- export
    @route("GET", r"/api/cases/(\d+)/export")
    def export(h, q, body, cid):
        case = need_case(cid)
        fmt = q.get("format", ["md"])[0]
        slug = re.sub(r"[^A-Za-z0-9_-]+", "_", case["name"]).strip("_") or "case"
        if fmt == "md":
            oos = q.get("all", ["0"])[0] == "1"
            return ("text/markdown", f"{slug}_report.md", to_markdown(store, int(cid), oos, oos))
        if fmt == "csv":
            return ("text/csv", f"{slug}_findings.csv", to_csv(store, int(cid)))
        if fmt == "json":
            return ("application/json", f"{slug}.osintizer.json", to_json(store, int(cid)))
        raise ApiError(400, "format must be md, csv or json")

    class Handler(BaseHTTPRequestHandler):
        server_version = f"OSINTizer/{__version__}"

        def log_message(self, fmt, *args):  # keep the terminal quiet
            pass

        def _send(self, status, payload, ctype="application/json", filename=None):
            if ctype == "application/json" and not isinstance(payload, (bytes, str)):
                payload = json.dumps(payload, default=str)
            data = payload.encode("utf-8") if isinstance(payload, str) else payload
            self.send_response(status)
            self.send_header("Content-Type", ctype + ("; charset=utf-8" if ctype.startswith(("text", "application/json")) else ""))
            self.send_header("Content-Length", str(len(data)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cache-Control", "no-store")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
                "script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'",
            )
            if filename:
                self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(data)

        def _host_ok(self):
            host = (self.headers.get("Host") or "").rsplit(":", 1)[0].strip("[]").lower()
            return host in allowed_hosts

        def _dispatch(self, method):
            if not self._host_ok():  # blocks DNS-rebinding attacks against the local API
                return self._send(403, {"error": "Host not allowed"})
            parts = urlsplit(self.path)
            path, query = parts.path, parse_qs(parts.query)
            if not path.startswith("/api/"):
                if method != "GET":
                    return self._send(405, {"error": "Method not allowed"})
                return self._static(path)
            if method != "GET" and self.headers.get("X-OSINTizer") != "1":
                # Browsers can't add this header cross-site without a preflight we never approve.
                return self._send(403, {"error": "Missing X-OSINTizer header"})
            body = {}
            if method in ("POST", "PATCH", "PUT"):
                length = int(self.headers.get("Content-Length") or 0)
                if length > MAX_BODY:
                    return self._send(413, {"error": "Request too large"})
                raw = self.rfile.read(length) if length else b""
                if raw:
                    try:
                        body = json.loads(raw.decode("utf-8"))
                    except ValueError:
                        return self._send(400, {"error": "Body must be JSON"})
            for m, rx, fn in routes:
                if m != method:
                    continue
                match = rx.match(path)
                if match:
                    try:
                        result = fn(self, query, body, *match.groups())
                    except ApiError as e:
                        return self._send(e.status, {"error": str(e)})
                    except Exception as e:  # pragma: no cover
                        return self._send(500, {"error": f"{type(e).__name__}: {e}"})
                    if isinstance(result, tuple):
                        ctype, fname, content = result
                        return self._send(200, content, ctype, fname)
                    return self._send(200, result)
            return self._send(404, {"error": "Not found"})

        def _static(self, path):
            if path in ("", "/"):
                path = "/index.html"
            target = (STATIC / path.lstrip("/")).resolve()
            if not str(target).startswith(str(STATIC.resolve())) or not target.is_file():
                return self._send(404, "Not found", "text/plain")
            ctype = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
            return self._send(200, target.read_bytes(), ctype)

        def do_GET(self):
            self._dispatch("GET")

        def do_HEAD(self):
            self._dispatch("GET")

        def do_POST(self):
            self._dispatch("POST")

        def do_PATCH(self):
            self._dispatch("PATCH")

        def do_DELETE(self):
            self._dispatch("DELETE")

    return Handler


def serve(store, runner, host="127.0.0.1", port=8787, open_browser=True):
    allowed = {"localhost", "127.0.0.1", "::1", host.lower()}
    if host in ("0.0.0.0", "::"):
        import socket
        allowed |= {socket.gethostname().lower(), socket.getfqdn().lower()}
        try:
            allowed.add(socket.gethostbyname(socket.gethostname()))
        except OSError:
            pass
    handler = make_handler(store, runner, allowed)
    httpd = ThreadingHTTPServer((host, port), handler)
    httpd.daemon_threads = True
    url = f"http://{'127.0.0.1' if host in ('0.0.0.0', '::') else host}:{port}/"
    print(f"\n  OSINTizer {__version__} running at {url}")
    print(f"  Database: {store.path}")
    if host not in ("127.0.0.1", "localhost", "::1"):
        print("  WARNING: listening beyond localhost - anyone on your network can reach this dashboard.")
    print("  Press Ctrl+C to stop.\n")
    if open_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n  Stopped.")
    finally:
        httpd.server_close()
