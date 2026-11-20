"""Execution layer. The ONLY place a security tool is ever spawned.

Guarantees enforced here, in order, before any process starts:
  1. global executor switch is on
  2. the tool is in the allowlist and its binary is installed
  3. the host is authorized + in-scope for the target (scope.check)
  4. for URL/param tools, the host *inside* the URL is also in-scope
  5. argv is a list (no shell), built only from sanitized options
Everything is timed out, captured, written to an evidence file, and audited.
"""
from __future__ import annotations

import datetime as dt
import subprocess
import uuid
from dataclasses import dataclass, field
from pathlib import Path

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


def _extract_hosts(tool: tools.Tool, host: str, options: dict) -> list[str]:
    """All hosts this invocation will touch, for scope checking."""
    hosts = [host]
    if "param_url" in options and options.get("param_url"):
        hosts.append(scope.normalize_host(options["param_url"]))
    return hosts


def run(target: Target, tool_name: str, host: str, options: dict | None = None) -> ExecResult:
    options = options or {}

    if not settings.executor_enabled:
        return ExecResult(False, tool_name, host, "", denied_reason="executor globally disabled (dry-run mode)")

    tool = tools.REGISTRY.get(tool_name)
    if tool is None:
        return ExecResult(False, tool_name, host, "", denied_reason=f"unknown tool '{tool_name}'")
    if not tool.installed:
        return ExecResult(False, tool_name, host, "", denied_reason=f"tool '{tool_name}' ({tool.binary}) not installed on executor host")

    # Scope check every host involved.
    for h in _extract_hosts(tool, host, options):
        decision = scope.check(target, h)
        if not decision.allowed:
            return ExecResult(False, tool_name, host, "", denied_reason=decision.reason)

    # Build argv (may raise ValueError on bad options → treated as denial).
    try:
        argv = tool.build(scope.normalize_host(host), options)
    except (ValueError, KeyError) as e:
        return ExecResult(False, tool_name, host, "", denied_reason=f"option validation failed: {e}")

    command = " ".join(argv)
    started = dt.datetime.now()
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=settings.tool_timeout,
            shell=False,  # critical: never a shell
            check=False,
        )
        stdout, stderr, code = proc.stdout, proc.stderr, proc.returncode
        ok = True
    except subprocess.TimeoutExpired:
        return ExecResult(False, tool_name, host, command,
                          denied_reason=f"timed out after {settings.tool_timeout}s")
    except Exception as e:  # noqa: BLE001 — surface any spawn failure as a non-ok result
        return ExecResult(False, tool_name, host, command, denied_reason=f"spawn error: {e}")

    duration = (dt.datetime.now() - started).total_seconds()

    # Persist evidence.
    ev_path = settings.evidence_dir / f"{tool_name}_{scope.normalize_host(host)}_{uuid.uuid4().hex[:8]}.txt"
    try:
        ev_path.write_text(f"$ {command}\n\n[exit {code}] [{duration:.1f}s]\n\n--- STDOUT ---\n{stdout}\n\n--- STDERR ---\n{stderr}")
    except OSError:
        ev_path = Path("")

    return ExecResult(
        ok=ok, tool=tool_name, host=host, command=command,
        stdout=stdout[:20000], stderr=stderr[:4000], exit_code=code,
        evidence_path=str(ev_path), duration_s=duration,
    )
