"""CIS-Benchmark compliance checks (the Nessus 'compliance/audit' capability).

Given the output of the credentialed SSH assessment (auth:* sources collected by
auth_va), this module deterministically evaluates a set of CIS Linux Benchmark
controls and emits pass/fail results. Failures become findings with a concrete
remediation config — no AI inference, so the verdicts are reproducible and defensible.

Each control maps to a CIS section id (best-effort, Ubuntu/Debian Linux L1 server).
"""
from __future__ import annotations

import re
from typing import Callable

Emit = Callable[[dict], None]


def _auth(collected: list[tuple[str, str, str]]) -> dict[str, str]:
    """Pick out the credentialed (auth:*) outputs by short name -> text."""
    out: dict[str, str] = {}
    for source, _cmd, text in collected:
        if source.startswith("auth:"):
            out[source.split(":", 1)[1]] = text or ""
    return out


def _sshd_val(text: str, key: str) -> str | None:
    for line in text.splitlines():
        line = line.strip()
        if line.lower().startswith(key.lower()):
            parts = line.split(None, 1)
            if len(parts) == 2:
                return parts[1].strip().lower()
    return None


def _finding(title, severity, control, status, evidence, remediation, fix_config, fix_steps) -> dict:
    return {
        "title": f"[CIS {control}] {title}",
        "severity": severity,
        "status": status,  # confirmed (fail proven from config) | likely
        "confidence": 90,
        "affected": "host (credentialed)",
        "cve": "",
        "description": f"CIS Benchmark control {control}. {title}.",
        "evidence": evidence,
        "remediation": remediation,
        "fix_config": fix_config,
        "fix_steps": fix_steps,
        "sources": ["cis-benchmark", "auth-va"],
    }


def run_cis(collected: list[tuple[str, str, str]], emit: Emit) -> list[dict]:
    a = _auth(collected)
    if not a:
        return []

    results: list[dict] = []   # control-level pass/fail (for the compliance summary)
    findings: list[dict] = []  # failures promoted to findings

    def record(control, title, passed):
        results.append({"control": control, "title": title, "result": "pass" if passed else "fail"})

    # ---- 5.2 SSH server hardening ----
    ssh = a.get("ssh_hardening", "")
    if ssh:
        prl = _sshd_val(ssh, "PermitRootLogin")
        ok = prl in (None, "no", "prohibit-password")  # None = not set = sshd default 'prohibit-password'
        record("5.2.8", "SSH PermitRootLogin disabled", ok)
        if prl == "yes":
            findings.append(_finding(
                "SSH root login permitted", "high", "5.2.8", "confirmed",
                "sshd_config: PermitRootLogin yes",
                "Disable direct root login over SSH; use a normal user + sudo.",
                "# /etc/ssh/sshd_config\nPermitRootLogin no",
                "1. Set PermitRootLogin no.\n2. sshd -t && systemctl reload ssh.\n3. Verify: sshd -T | grep permitrootlogin"))

        empty = _sshd_val(ssh, "PermitEmptyPasswords")
        ok = empty in (None, "no")
        record("5.2.x", "SSH empty passwords disabled", ok)
        if empty == "yes":
            findings.append(_finding(
                "SSH empty passwords permitted", "critical", "5.2.x", "confirmed",
                "sshd_config: PermitEmptyPasswords yes",
                "Never allow empty passwords for SSH.",
                "# /etc/ssh/sshd_config\nPermitEmptyPasswords no",
                "1. Set PermitEmptyPasswords no.\n2. systemctl reload ssh."))

        pwauth = _sshd_val(ssh, "PasswordAuthentication")
        ok = pwauth == "no"
        record("5.2.x", "SSH key-based auth enforced (PasswordAuthentication no)", ok)
        if pwauth != "no":
            findings.append(_finding(
                "SSH password authentication enabled", "medium", "5.2.x", "likely",
                f"sshd_config: PasswordAuthentication {pwauth or '(default yes)'}",
                "Prefer key-based authentication; disable password auth where operationally possible.",
                "# /etc/ssh/sshd_config\nPasswordAuthentication no",
                "1. Deploy SSH keys first.\n2. Set PasswordAuthentication no.\n3. systemctl reload ssh."))

        x11 = _sshd_val(ssh, "X11Forwarding")
        ok = x11 in (None, "no")
        record("5.2.x", "SSH X11Forwarding disabled", ok)
        if x11 == "yes":
            findings.append(_finding(
                "SSH X11Forwarding enabled", "low", "5.2.x", "confirmed",
                "sshd_config: X11Forwarding yes",
                "Disable X11 forwarding unless explicitly required.",
                "# /etc/ssh/sshd_config\nX11Forwarding no",
                "1. Set X11Forwarding no.\n2. systemctl reload ssh."))

        tries = _sshd_val(ssh, "MaxAuthTries")
        try:
            ok = tries is not None and int(tries) <= 4
        except ValueError:
            ok = False
        record("5.2.x", "SSH MaxAuthTries <= 4", ok)
        if not ok:
            findings.append(_finding(
                "SSH MaxAuthTries not hardened", "low", "5.2.x", "likely",
                f"sshd_config: MaxAuthTries {tries or '(default 6)'}",
                "Limit authentication attempts to slow brute-force.",
                "# /etc/ssh/sshd_config\nMaxAuthTries 4",
                "1. Set MaxAuthTries 4.\n2. systemctl reload ssh."))

    # ---- 3.5 Host firewall ----
    fw = a.get("firewall", "")
    fw_ok = bool(fw) and ("active" in fw.lower() or "chain" in fw.lower()) and "no-fw-info" not in fw
    inactive = "status: inactive" in fw.lower()
    record("3.5.1", "Host firewall configured/active", fw_ok and not inactive)
    if inactive or (fw and "no-fw-info" in fw):
        findings.append(_finding(
            "Host firewall inactive", "medium", "3.5.1", "likely",
            fw.strip()[:200] or "no firewall info",
            "Enable a host firewall and default-deny inbound except required services.",
            "# ufw example\nufw default deny incoming\nufw default allow outgoing\nufw allow 22/tcp\nufw enable",
            "1. Define allow rules for required ports.\n2. Enable ufw.\n3. Verify: ufw status verbose."))

    # ---- 1.3 Passwordless sudo ----
    sudo = a.get("sudo", "")
    nopass = "NOPASSWD" in sudo
    record("1.3.x", "No passwordless sudo (NOPASSWD)", not nopass)
    if nopass:
        findings.append(_finding(
            "Passwordless sudo configured", "medium", "1.3.x", "confirmed",
            "sudo -l reports NOPASSWD entries",
            "Require a password for sudo escalation; remove NOPASSWD unless strictly needed (e.g. automation with scoped commands).",
            "# visudo — remove NOPASSWD:\n%admin ALL=(ALL:ALL) ALL",
            "1. Audit NOPASSWD entries in /etc/sudoers and /etc/sudoers.d/.\n2. Remove or scope them.\n3. Verify: sudo -l."))

    # ---- 6.1 World-writable files ----
    ww = a.get("world_writable", "")
    ww_files = [l for l in ww.splitlines() if l.strip()]
    record("6.1.x", "No world-writable files", len(ww_files) == 0)
    if ww_files:
        findings.append(_finding(
            "World-writable files present", "medium", "6.1.x", "confirmed",
            f"{len(ww_files)} world-writable file(s), e.g. " + ", ".join(ww_files[:5]),
            "Remove world-write permission from files that don't require it.",
            "# Review then fix each:\nchmod o-w <file>",
            "1. Review the listed files.\n2. Strip the world-write bit.\n3. Re-run: find / -xdev -type f -perm -0002."))

    # ---- 1.8 Patching recency ----
    patch = a.get("patch_recency", "")
    stale = not patch.strip()
    record("1.8.x", "Recent patch activity present", not stale)
    if stale:
        findings.append(_finding(
            "No recent patch activity detected", "medium", "1.8.x", "likely",
            "No recent apt/rpm update history found.",
            "Establish a regular patching cadence and apply pending security updates.",
            "# Debian/Ubuntu\napt update && apt upgrade -y\n# enable unattended-upgrades for security patches",
            "1. Apply pending updates.\n2. Enable unattended-upgrades.\n3. Verify: apt list --upgradable."))

    emit({"type": "reasoning", "text":
          f"CIS compliance: evaluated {len(results)} control(s) — "
          f"{sum(1 for r in results if r['result'] == 'pass')} pass / "
          f"{sum(1 for r in results if r['result'] == 'fail')} fail."})
    emit({"type": "intel", "kind": "compliance", "items": results})
    return findings
