"""CPHunter bridge — CVE mass-detection (VA) + proof-of-impact exploitation (PT).

CPHunter is an external CVE scanner/exploiter (the operator's own tool). Iron360 drives
it so the AI orchestrates and validates every result:

  detect()  -> runs `cphunter.py <targets> --scan --cve-vuln` against the single in-scope
               host, parses results_vun_scan/<CVE>/evidence.jsonl + inconclusive.txt, and
               returns structured findings (VULNERABLE / INCONCLUSIVE + evidence/version).
               CPHunter only auto-fires its SAFE-by-default confirmation here; destructive
               PoCs are held. The AI then cross-checks each claim (anti-false-positive).

  exploit() -> runs `cphunter.py --exploit-cve-vuln <CVE> <host>` for a confirmed CVE
               (PT phase only, behind interactive approval). CPHunter's per-CVE adapter
               fires the real PoC with safe defaults (no destructive account-create flags
               are passed), captures stdout/returncode, which the AI validates as real
               proof-of-impact.

Everything is scope-enforced (host must be in engagement scope) and serialized (CPHunter
writes to a fixed results_vun_scan/ dir, so only one run at a time).
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import threading
import time
from pathlib import Path

from ..config import get_settings
from ..models import Target
from . import scope

settings = get_settings()
_LOCK = threading.Lock()


def _root() -> Path | None:
    if not settings.cphunter_dir:
        return None
    p = Path(settings.cphunter_dir)
    return p if (p / "cphunter.py").is_file() else None


def available() -> bool:
    return _root() is not None


def _safe_name(target: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", target) or "target"


def _run_proc(argv: list[str], cwd: Path, stop_event: threading.Event | None,
              timeout: float) -> tuple[int | None, str]:
    """Run CPHunter, streaming nothing; return (returncode, combined output). Honors stop/timeout."""
    try:
        proc = subprocess.Popen(argv, cwd=str(cwd), stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    except Exception as e:  # noqa: BLE001
        return None, f"spawn error: {e}"
    out: list[str] = []
    t = threading.Thread(target=lambda: [out.append(l) for l in proc.stdout], daemon=True)
    t.start()
    started = time.time()
    while True:
        try:
            proc.wait(timeout=0.5)
            break
        except subprocess.TimeoutExpired:
            pass
        if stop_event is not None and stop_event.is_set():
            proc.kill()
            break
        if time.time() - started > timeout:
            proc.kill()
            break
    try:
        proc.wait(timeout=3)
    except Exception:  # noqa: BLE001
        pass
    t.join(timeout=2)
    return proc.returncode, "".join(out)[:20000]


# --------------------------------------------------------------------- detection
def detect(target: Target, host: str, emit, stop_event: threading.Event | None = None) -> list[dict]:
    """Mass CVE detection on one in-scope host. Returns draft findings for AI cross-check."""
    root = _root()
    if root is None:
        return []
    if not scope.check(target, scope.normalize_host(host)).allowed:
        emit({"type": "reasoning", "text": "CPHunter detection skipped — host out of scope."})
        return []

    with _LOCK:
        # Write the single in-scope host to a temp targets file inside the CPHunter dir.
        tfile = root / f".iron360_targets_{os.getpid()}.txt"
        try:
            tfile.write_text(scope.normalize_host(host) + "\n")
        except OSError as e:
            emit({"type": "reasoning", "text": f"CPHunter detection skipped — cannot write targets file: {e}"})
            return []
        argv = [settings.cphunter_python, "cphunter.py", tfile.name, "--scan", "--cve-vuln",
                "--cve-vuln-reset", "--cve-vuln-workers", str(settings.cphunter_workers),
                "--cve-vuln-timeout", str(settings.cphunter_timeout)]
        emit({"type": "exec", "tool": "cphunter", "host": host, "command": " ".join(argv),
              "ok": True, "exit_code": 0, "output": "(running CPHunter CVE mass-detection…)", "duration_s": 0})
        rc, out = _run_proc(argv, root, stop_event, timeout=max(600.0, settings.tool_timeout))
        try:
            tfile.unlink()
        except OSError:
            pass
        findings = _parse_results(root / "results_vun_scan", host)

    emit({"type": "exec", "tool": "cphunter", "host": host, "command": "cphunter --cve-vuln (parsed)",
          "ok": True, "exit_code": rc if rc is not None else -1,
          "output": (out[-3000:] if out else "(no output)"), "duration_s": 0})
    vuln = sum(1 for f in findings if f["state"] == "vulnerable")
    incl = sum(1 for f in findings if f["state"] == "inconclusive")
    emit({"type": "reasoning", "text": f"CPHunter: {vuln} CVE VULNERABLE, {incl} INCONCLUSIVE on {host} "
          "(handing to AI for cross-check)."})
    return findings


def _parse_results(results_root: Path, host: str) -> list[dict]:
    if not results_root.is_dir():
        return []
    norm = scope.normalize_host(host)
    findings: list[dict] = []
    for cve_dir in sorted(results_root.iterdir()):
        if not cve_dir.is_dir():
            continue
        cve_id = cve_dir.name
        # exploit auto-fire results (safe-by-default), keyed for enrichment
        ex_state, ex_evid = None, ""
        exf = cve_dir / "exploit_results.jsonl"
        if exf.is_file():
            for line in exf.read_text(errors="ignore").splitlines():
                try:
                    r = json.loads(line)
                except Exception:  # noqa: BLE001
                    continue
                if norm in (r.get("host", ""), scope.normalize_host(r.get("target", ""))):
                    ex_state, ex_evid = r.get("exploit_state"), (r.get("exploit_evidence") or "")
        # VULNERABLE (evidence.jsonl)
        evf = cve_dir / "evidence.jsonl"
        matched = False
        if evf.is_file():
            for line in evf.read_text(errors="ignore").splitlines():
                try:
                    r = json.loads(line)
                except Exception:  # noqa: BLE001
                    continue
                if norm not in (r.get("host", ""), scope.normalize_host(r.get("target", ""))):
                    continue
                matched = True
                findings.append({
                    "cve": cve_id.split()[0], "state": "vulnerable", "host": norm,
                    "port": r.get("port"), "evidence": (r.get("evidence") or "")[:1500],
                    "version": r.get("version") or "", "metadata": r.get("metadata") or {},
                    "exploit_state": ex_state, "exploit_evidence": ex_evid[:800],
                })
        # INCONCLUSIVE (only if not already vulnerable)
        if not matched:
            incf = cve_dir / "inconclusive.txt"
            if incf.is_file():
                for line in incf.read_text(errors="ignore").splitlines():
                    tgt = line.split("\t")[0].strip()
                    if tgt and scope.normalize_host(tgt) == norm:
                        ev = line.split("\t", 1)[1] if "\t" in line else ""
                        findings.append({"cve": cve_id.split()[0], "state": "inconclusive",
                                         "host": norm, "evidence": ev[:800], "metadata": {}})
                        break
    return findings


# --------------------------------------------------------------------- exploitation
def exploit(target: Target, cve_id: str, host: str, emit, stop_event: threading.Event | None = None) -> dict:
    """Fire CPHunter's PoC for one confirmed CVE (PT phase, approval-gated). Safe defaults only."""
    root = _root()
    if root is None:
        return {"ran": False, "success": None, "output": "CPHunter not available"}
    if not scope.check(target, scope.normalize_host(host)).allowed:
        return {"ran": False, "success": None, "output": "host out of scope"}

    norm = scope.normalize_host(host)
    with _LOCK:
        argv = [settings.cphunter_python, "cphunter.py", "--exploit-cve-vuln", cve_id, norm,
                "--no-pip-install"]
        rc, out = _run_proc(argv, root, stop_event, timeout=max(180.0, settings.tool_timeout))
        # Read the per-target run log for the captured PoC output.
        log_text = ""
        runs = root / "results_vun_scan" / cve_id / "exploit_runs" / f"{_safe_name(norm)}.log"
        if runs.is_file():
            log_text = runs.read_text(errors="ignore")[-4000:]
        success_file = root / "results_vun_scan" / cve_id / "exploit_success.txt"
        success = False
        if success_file.is_file():
            success = any(norm in l for l in success_file.read_text(errors="ignore").splitlines())
    combined = (log_text or out or "")[:4000]
    emit({"type": "exec", "tool": f"cphunter-exploit:{cve_id}", "host": host,
          "command": " ".join(argv), "ok": rc == 0, "exit_code": rc if rc is not None else -1,
          "output": combined or "(no output)", "duration_s": 0})
    return {"ran": True, "success": success, "output": combined, "returncode": rc}
