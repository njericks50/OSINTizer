"""Runs collectors in the background and files their findings automatically.

This is the piece that removes the old "download a .json, import it into
Findings" step: the moment a collector finishes (or while you paste output),
its output is parsed and the results land in the case's grouped findings.
"""

from __future__ import annotations

import os
import shlex
import signal
import subprocess
import tempfile
import threading
import time

from . import collectors as C
from .extractors import extract, strip_ansi


class Runner:
    # Network-safety defaults. One collector at a time plus a short pause between runs
    # keeps DNS/connection bursts small enough for home routers and firewalls (pfSense etc).
    def __init__(self, store, max_parallel: int = 1, cooldown: float = 3.0):
        self.store = store
        self._procs: dict[int, subprocess.Popen] = {}
        self._cancelled: set[int] = set()
        self._lock = threading.Lock()
        self._slots = threading.Semaphore(max(1, max_parallel))
        self.cooldown = cooldown

    # -------------------------------------------------------------- public
    def start(self, case_id: int, collector_id: str, target: str, args: str | None = None,
              wait: bool = False, on_output=None) -> int:
        col = C.BY_ID.get(collector_id)
        if not col:
            raise C.TargetError(f"Unknown collector '{collector_id}'")
        target = C.validate_target(col, target)
        argv = C.build_argv(col, target, args)
        command = " ".join(shlex.quote(a) for a in argv)
        run_id = self.store.create_run(case_id, col.id, target, command, "queued")
        t = threading.Thread(
            target=self._execute, args=(run_id, case_id, col, target, argv, on_output), daemon=True
        )
        t.start()
        if wait:
            t.join()
        return run_id

    def cancel(self, run_id: int) -> bool:
        with self._lock:
            self._cancelled.add(run_id)
            proc = self._procs.get(run_id)
        if proc and proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except Exception:
                proc.terminate()
            return True
        return False

    def ingest(self, case_id: int, text: str, tool: str = "auto", label: str = "", target: str = ""):
        """File pasted/imported tool output exactly like a collector run."""
        text = strip_ansi(text or "")
        if not text.strip():
            raise ValueError("Nothing to ingest")
        tool = (tool or "auto").lower()
        name = tool if tool not in ("auto", "") else "paste"
        run_id = self.store.create_run(case_id, name, target, f"(pasted) {label}".strip(), "running")
        self.store.update_run(run_id, output=text)
        return run_id, self._file_findings(run_id, case_id, text, tool, target)

    # ------------------------------------------------------------- internal
    def _file_findings(self, run_id, case_id, text, tool, target):
        scope = self.store.scope_domains(case_id)
        items = extract(text, tool, target, scope)
        new, seen = self.store.add_findings(case_id, run_id, items)
        self.store.update_run(run_id, status="done", finished=time.time(),
                              findings_new=new, findings_seen=seen)
        return new, seen

    def _execute(self, run_id, case_id, col, target, argv, on_output):
        with self._slots:
            if run_id in self._cancelled:
                self.store.update_run(run_id, status="cancelled", finished=time.time())
                return
            self.store.update_run(run_id, status="running")
            try:
                if col.builtin:
                    output = C.BUILTINS[col.builtin](target, col.timeout)
                    if on_output:
                        on_output(output)
                    status = "done"
                else:
                    output, status = self._run_process(run_id, col, argv, on_output)
            except Exception as exc:  # network errors, missing binaries ...
                self.store.update_run(run_id, status="error", error=str(exc), finished=time.time())
                return
            self.store.update_run(run_id, output=output)
            try:
                new, seen = self.store.add_findings(
                    case_id, run_id, extract(output, col.id, target, self.store.scope_domains(case_id))
                )
            except Exception as exc:
                self.store.update_run(run_id, status="error", error=f"extraction failed: {exc}",
                                      finished=time.time())
                return
            self.store.update_run(run_id, status=status, finished=time.time(),
                                  findings_new=new, findings_seen=seen)
            time.sleep(self.cooldown)  # breathing room before the next queued run

    def _run_process(self, run_id, col, argv, on_output):
        workdir = tempfile.mkdtemp(prefix=f"osintizer-{col.id}-")
        env = dict(os.environ, NO_COLOR="1", TERM="dumb", PYTHONUNBUFFERED="1")
        proc = subprocess.Popen(
            argv, cwd=workdir, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL, start_new_session=True,
        )
        with self._lock:
            self._procs[run_id] = proc
        chunks: list[str] = []
        last_flush = time.time()
        deadline = time.time() + col.timeout
        timed_out = False

        def reader():
            for raw in iter(proc.stdout.readline, b""):
                line = raw.decode("utf-8", "replace")
                chunks.append(line)
                if on_output:
                    on_output(strip_ansi(line))

        rt = threading.Thread(target=reader, daemon=True)
        rt.start()
        while proc.poll() is None:
            if time.time() > deadline:
                timed_out = True
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                except Exception:
                    proc.terminate()
                break
            if time.time() - last_flush > 1.0:  # live output for the UI console
                self.store.update_run(run_id, output=strip_ansi("".join(chunks)))
                last_flush = time.time()
            time.sleep(0.25)
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        rt.join(timeout=5)
        with self._lock:
            self._procs.pop(run_id, None)
            cancelled = run_id in self._cancelled
        output = strip_ansi("".join(chunks))
        # Some tools also drop result files in their working directory (e.g. sherlock's <user>.txt).
        # (Skipped for tools whose files only repeat what they already printed.)
        for name in ([] if col.id in ("sherlock", "maigret", "holehe") else sorted(os.listdir(workdir))):
            path = os.path.join(workdir, name)
            if os.path.isfile(path) and os.path.getsize(path) < 5_000_000:
                with open(path, encoding="utf-8", errors="replace") as fh:
                    output += f"\n\n# ---- file written by {col.name}: {name} ----\n" + fh.read()
        if cancelled:
            status = "cancelled"
        elif timed_out:
            status = "timeout"
        elif proc.returncode not in (0, None) and not output.strip():
            status = "error"
        else:
            status = "done"
        return output, status
