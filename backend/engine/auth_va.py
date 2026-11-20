"""Authenticated (credentialed) Vulnerability Assessment — the Nessus hallmark.

When a target carries SSH credentials (from the engagement), Iron360 logs in over SSH
and runs a battery of READ-ONLY enumeration commands: OS/kernel, installed packages,
listening services, SSH hardening, SUID / world-writable files, sudo config, cron, patch
recency. The output is handed to the AI, which correlates package versions with CVEs and
flags misconfigurations — exactly the kind of deep check an unauthenticated scan cannot do.

Scope-enforced (the host must be in the engagement scope) and non-destructive.
"""
from __future__ import annotations

import io
import threading

from ..models import Target
from . import scope

# Read-only, non-destructive credentialed checks (Linux).
_CHECKS: list[tuple[str, str]] = [
    ("os", "cat /etc/os-release 2>/dev/null | head -8"),
    ("kernel", "uname -a; echo; uname -r"),
    ("uptime", "uptime 2>/dev/null"),
    ("local_users", "awk -F: '$3>=1000 && $3<65534 {print $1}' /etc/passwd 2>/dev/null | head -30"),
    ("sudo", "sudo -n -l 2>/dev/null | head -40 || echo 'no-passwordless-sudo'"),
    ("listening", "ss -tlnp 2>/dev/null | head -40 || netstat -tlnp 2>/dev/null | head -40"),
    ("ssh_hardening", "grep -Ei '^(PermitRootLogin|PasswordAuthentication|PermitEmptyPasswords|Protocol|X11Forwarding|MaxAuthTries)' /etc/ssh/sshd_config 2>/dev/null"),
    ("suid_binaries", "find / -perm -4000 -type f 2>/dev/null | head -50"),
    ("world_writable", "find / -path /proc -prune -o -perm -0002 -type f -print 2>/dev/null | head -40"),
    ("cron", "ls -la /etc/cron.d /etc/cron.daily 2>/dev/null; echo '---'; cat /etc/crontab 2>/dev/null | head -20"),
    ("pkg_count", "(dpkg -l 2>/dev/null | grep -c '^ii') || (rpm -qa 2>/dev/null | wc -l)"),
    ("key_packages", "(dpkg -l 2>/dev/null || rpm -qa 2>/dev/null) | grep -Ei 'openssh|apache2|httpd|nginx|mysql|mariadb|postgres|php|openssl|samba|vsftpd|proftpd|bind9|exim|sudo|polkit|glibc' | head -40"),
    ("kernel_pkgs", "dpkg -l 2>/dev/null | grep -E 'linux-image|linux-headers' | tail -5 || uname -r"),
    ("patch_recency", "grep -h 'Start-Date' /var/log/apt/history.log 2>/dev/null | tail -3; rpm -qa --last 2>/dev/null | head -3"),
    ("firewall", "(ufw status 2>/dev/null | head -10) || (iptables -L -n 2>/dev/null | head -15) || echo 'no-fw-info'"),
]


def available() -> bool:
    try:
        import paramiko  # noqa: F401
        return True
    except Exception:  # noqa: BLE001
        return False


def _load_key(secret: str):
    import paramiko
    for cls in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey):
        try:
            return cls.from_private_key(io.StringIO(secret))
        except Exception:  # noqa: BLE001
            continue
    return None


def run_auth_va(target: Target, emit, stop_event: threading.Event | None = None) -> list[tuple[str, str, str]]:
    if target.auth_type not in ("ssh_password", "ssh_key") or not target.auth_user:
        return []
    if not available():
        emit({"type": "reasoning", "text": "Authenticated VA skipped — paramiko (SSH) not installed on executor."})
        return []

    host = scope.normalize_host(target.value)
    if not scope.check(target, host).allowed:
        emit({"type": "reasoning", "text": "Authenticated VA skipped — host out of scope."})
        return []

    import paramiko
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    port = target.auth_port or 22
    try:
        if target.auth_type == "ssh_key":
            pkey = _load_key(target.auth_secret)
            if pkey is None:
                emit({"type": "reasoning", "text": "Authenticated VA: could not parse the provided SSH private key."})
                return []
            client.connect(host, port=port, username=target.auth_user, pkey=pkey, timeout=15,
                           look_for_keys=False, allow_agent=False)
        else:
            client.connect(host, port=port, username=target.auth_user, password=target.auth_secret,
                           timeout=15, look_for_keys=False, allow_agent=False)
    except Exception as e:  # noqa: BLE001
        emit({"type": "reasoning", "text": f"Authenticated VA: SSH login failed ({type(e).__name__}: {e})."})
        return []

    emit({"type": "reasoning", "text": f"Authenticated VA: SSH login OK as {target.auth_user}@{host}:{port}. "
          f"Running {len(_CHECKS)} credentialed checks."})
    collected: list[tuple[str, str, str]] = []
    for name, cmd in _CHECKS:
        if stop_event is not None and stop_event.is_set():
            break
        try:
            _in, out, _err = client.exec_command(cmd, timeout=20)
            text = out.read().decode(errors="ignore")[:6000]
        except Exception:  # noqa: BLE001
            text = ""
        collected.append((f"auth:{name}", cmd, text))
    try:
        client.close()
    except Exception:  # noqa: BLE001
        pass
    return collected
