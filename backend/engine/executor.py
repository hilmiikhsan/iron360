"""Execution layer. The ONLY place a security tool is ever spawned.

Guarantees enforced here, in order, before any process starts:
  1. global executor switch is on
  2. the tool is in the allowlist and its binary is installed
  3. the host is authorized + in-scope for the target (scope.check)
  4. for URL/param tools, the host *inside* the URL is also in-scope
  5. argv is a list (no shell), built only from sanitized options

Processes run under Popen with reader threads (so large output never deadlocks),
an overall timeout, and a cooperative `stop_event` — when the operator presses
Stop, the running process is killed immediately.
"""
from __future__ import annotations

import datetime as dt
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from ..config import get_settings
from ..models import Target
from . import scope, tools

settings = get_settings()


@dataclass
class ExecResult:
    ok: bool
    tool: str
    host: str
    command: str
    stdout: str = ""
    stderr: str = ""
    exit_code: int | None = None
    denied_reason: str = ""
    evidence_path: str = ""
    duration_s: float = 0.0


def _extract_hosts(host: str, options: dict) -> list[str]:
    hosts = [host]
    if options.get("param_url"):
        hosts.append(scope.normalize_host(options["param_url"]))
    return hosts


def run(target: Target, tool_name: str, host: str, options: dict | None = None,
        stop_event: threading.Event | None = None,
        line_emit: Callable[[str], None] | None = None,
        timeout: int | None = None) -> ExecResult:
    """Execute a tool and return the result. If `line_emit` is provided, each stdout line is
    forwarded to it in real-time so the frontend can stream output live (Claude-Code-style)."""
    options = options or {}

    if not settings.executor_enabled:
        return ExecResult(False, tool_name, host, "", denied_reason="executor globally disabled (dry-run mode)")

    tool = tools.REGISTRY.get(tool_name)
    if tool is None:
        return ExecResult(False, tool_name, host, "", denied_reason=f"unknown tool '{tool_name}'")
    if not tool.installed:
        return ExecResult(False, tool_name, host, "", denied_reason=f"tool '{tool_name}' ({tool.binary}) not installed on executor host")

    for h in _extract_hosts(host, options):
        decision = scope.check(target, h)
        if not decision.allowed:
            return ExecResult(False, tool_name, host, "", denied_reason=decision.reason)

    norm_host = scope.normalize_host(host)
    try:
        argv = tool.build(norm_host, options)
        stdin_data = tool.stdin(norm_host, options) if tool.stdin else None
    except (ValueError, KeyError) as e:
        return ExecResult(False, tool_name, host, "", denied_reason=f"option validation failed: {e}")

    command = " ".join(argv)
    started = time.time()
    try:
        proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE if stdin_data is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
    except Exception as e:  # noqa: BLE001
        return ExecResult(False, tool_name, host, command, denied_reason=f"spawn error: {e}")

    out_buf: list[str] = []
    err_buf: list[str] = []

    def _drain(stream, buf, emit_line=None):
        try:
            for line in stream:
                buf.append(line)
                if emit_line:
                    try:
                        emit_line(line.rstrip("\n"))
                    except Exception:  # noqa: BLE001
                        pass
        except Exception:  # noqa: BLE001
            pass

    t_out = threading.Thread(target=_drain, args=(proc.stdout, out_buf, line_emit), daemon=True)
    t_err = threading.Thread(target=_drain, args=(proc.stderr, err_buf), daemon=True)
    t_out.start()
    t_err.start()

    if stdin_data is not None:
        try:
            proc.stdin.write(stdin_data)
            proc.stdin.close()
        except Exception:  # noqa: BLE001
            pass

    cancelled = timed_out = False
    while True:
        try:
            proc.wait(timeout=0.3)
            break
        except subprocess.TimeoutExpired:
            pass
        if stop_event is not None and stop_event.is_set():
            cancelled = True
            proc.kill()
            break
        if time.time() - started > (timeout or settings.tool_timeout):
            timed_out = True
            proc.kill()
            break

    try:
        proc.wait(timeout=3)
    except Exception:  # noqa: BLE001
        pass
    t_out.join(timeout=2)
    t_err.join(timeout=2)

    stdout = "".join(out_buf)
    stderr = "".join(err_buf)
    duration = time.time() - started

    if cancelled:
        return ExecResult(False, tool_name, host, command, stdout=stdout[:20000], stderr=stderr[:4000],
                          denied_reason="stopped by operator", duration_s=duration)
    if timed_out:
        return ExecResult(False, tool_name, host, command,
                          denied_reason=f"timed out after {timeout or settings.tool_timeout}s",
                          duration_s=duration)

    code = proc.returncode
    ev_path = settings.evidence_dir / f"{tool_name}_{norm_host}_{uuid.uuid4().hex[:8]}.txt"
    try:
        ev_path.write_text(f"$ {command}\n\n[exit {code}] [{duration:.1f}s]\n\n--- STDOUT ---\n{stdout}\n\n--- STDERR ---\n{stderr}")
    except OSError:
        ev_path = Path("")

    return ExecResult(
        ok=True, tool=tool_name, host=host, command=command,
        stdout=stdout[:20000], stderr=stderr[:4000], exit_code=code,
        evidence_path=str(ev_path), duration_s=duration,
    )
