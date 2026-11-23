"""Iron360 modules beyond VAPT AI.

Per the brief, Iron360's dashboard also hosts Threat Intel, Dark Web Crawling,
Domain Health and SIEM Log. The brief says to focus on VAPT AI first, so:
  - Domain Health is implemented (functional) — it reuses the in-scope, installed recon tools.
  - Threat Intel / Dark Web / SIEM return a structured capability spec with status "planned"
    (phase 2), so the module is present and honest rather than faked.
"""
from __future__ import annotations

import concurrent.futures
import re
import socket
import ssl
import subprocess

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..database import get_db
from ..engine import executor, scope
from ..models import Target, User
from ..security import get_current_user

router = APIRouter(prefix="/api/modules", tags=["modules"])


def _tls_probe(host: str) -> dict:
    out = {"ok": False, "protocol": None, "cipher": None, "issuer": None,
           "expires": None, "san": [], "serial": None, "sig_alg": None, "error": None}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, 443), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                out["ok"] = True
                out["protocol"] = ss.version()
                out["cipher"] = ss.cipher()[0] if ss.cipher() else None
                cert = ss.getpeercert()
                if cert:
                    out["issuer"] = dict(x[0] for x in cert.get("issuer", [])).get("organizationName")
                    out["expires"] = cert.get("notAfter")
                    out["serial"] = cert.get("serialNumber")
                    san = cert.get("subjectAltName") or []
                    out["san"] = [v for _, v in san]
                cert_bin = ss.getpeercert(binary_form=True)
                if cert_bin:
                    try:
                        from cryptography import x509
                        c = x509.load_der_x509_certificate(cert_bin)
                        out["sig_alg"] = c.signature_algorithm_oid._name
                    except Exception:
                        pass
    except Exception as e:  # noqa: BLE001
        out["error"] = str(e)
    return out


def _dns_probe(host: str) -> dict:
    dns: dict = {"resolved": [], "error": None, "mx": [], "txt": [], "ns": [], "has_spf": False,
                 "has_dmarc": False, "has_dkim": False}
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM, 0, socket.AI_CANONNAME)
        dns["resolved"] = sorted({i[4][0] for i in infos})
    except Exception as e:  # noqa: BLE001
        dns["error"] = str(e)
        return dns

    # MX, TXT, NS via dig (fast, no extra deps)
    for rtype, key in [("MX", "mx"), ("TXT", "txt"), ("NS", "ns")]:
        try:
            r = subprocess.run(["dig", "+short", "+time=3", "+tries=1", rtype, host],
                               capture_output=True, text=True, timeout=5)
            if r.returncode == 0 and r.stdout.strip():
                dns[key] = [l.strip().strip('"') for l in r.stdout.strip().split("\n") if l.strip()]
        except Exception:
            pass

    # SPF check
    for txt in dns.get("txt", []):
        if "v=spf1" in txt.lower():
            dns["has_spf"] = True
            break

    # DMARC check
    try:
        r = subprocess.run(["dig", "+short", "+time=3", "+tries=1", "TXT", f"_dmarc.{host}"],
                           capture_output=True, text=True, timeout=5)
        if r.returncode == 0 and "v=dmarc1" in (r.stdout or "").lower():
            dns["has_dmarc"] = True
    except Exception:
        pass

    return dns


def _http_probe(target: "Target", host: str) -> dict:
    from http.client import HTTPSConnection, HTTPConnection
    result: dict = {"raw": "", "ok": False, "headers": {}, "security_headers": []}
    res = executor.run(target, "httpx", host, {}, timeout=10)
    if res.ok:
        result["ok"] = True
        result["raw"] = (res.stdout or "").strip()
    else:
        result["raw"] = res.denied_reason

    # Probe security headers directly
    try:
        conn = HTTPSConnection(host, timeout=8)
        try:
            conn.request("HEAD", "/")
            resp = conn.getresponse()
        except Exception:
            conn = HTTPConnection(host, timeout=8)
            conn.request("HEAD", "/")
            resp = conn.getresponse()
        hdrs = {k.lower(): v for k, v in resp.getheaders()}
        result["headers"] = hdrs
        result["status_code"] = resp.status

        wanted = {
            "strict-transport-security": ("HSTS", "high",
                "Forces HTTPS; prevents downgrade attacks"),
            "content-security-policy": ("CSP", "medium",
                "Mitigates XSS and injection attacks"),
            "x-frame-options": ("X-Frame-Options", "medium",
                "Prevents clickjacking"),
            "x-content-type-options": ("X-Content-Type-Options", "low",
                "Prevents MIME-sniffing"),
            "x-xss-protection": ("X-XSS-Protection", "info",
                "Legacy XSS filter (deprecated but still useful)"),
            "referrer-policy": ("Referrer-Policy", "low",
                "Controls referrer information leakage"),
            "permissions-policy": ("Permissions-Policy", "low",
                "Controls browser feature access"),
        }
        for hdr, (label, sev, desc) in wanted.items():
            present = hdr in hdrs
            result["security_headers"].append({
                "header": label, "present": present, "severity": sev,
                "value": hdrs.get(hdr, ""),
                "description": desc,
            })
        conn.close()
    except Exception:
        pass

    return result


@router.get("/domain-health/{target_id}")
def domain_health(target_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    target = db.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    host = scope.normalize_host(target.value)
    decision = scope.check(target, host)
    if not decision.allowed:
        raise HTTPException(status_code=403, detail=decision.reason)

    # Run all probes in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        f_dns = pool.submit(_dns_probe, host)
        f_tls = pool.submit(_tls_probe, host)
        f_http = pool.submit(_http_probe, target, host)
        dns = f_dns.result(timeout=20)
        tls = f_tls.result(timeout=20)
        http_data = f_http.result(timeout=25)

    # Grading
    issues = []
    if tls.get("protocol") in ("TLSv1", "TLSv1.1"):
        issues.append({"sev": "high", "msg": f"Weak TLS protocol: {tls['protocol']} (should be TLSv1.2+)"})
    if tls.get("error"):
        issues.append({"sev": "info", "msg": f"TLS probe: {tls['error']}"})
    if not dns.get("resolved"):
        issues.append({"sev": "high", "msg": "Host does not resolve (DNS failure)"})
    if not dns.get("has_spf"):
        issues.append({"sev": "medium", "msg": "No SPF record — vulnerable to email spoofing"})
    if not dns.get("has_dmarc"):
        issues.append({"sev": "medium", "msg": "No DMARC record — no email authentication policy"})

    # Security header issues
    for sh in http_data.get("security_headers", []):
        if not sh["present"] and sh["severity"] in ("high", "medium"):
            issues.append({"sev": sh["severity"],
                           "msg": f"Missing {sh['header']} header — {sh['description']}"})

    score = max(0, 100 - sum({"high": 30, "medium": 15, "low": 7, "info": 2}.get(i["sev"], 0) for i in issues))
    return {"target": target.value, "score": score, "dns": dns, "tls": tls, "http": http_data, "issues": issues}


_PLANNED = {
    "threat-intel": {
        "title": "Threat Intelligence",
        "status": "planned",
        "summary": "Korelasikan aset target dengan IOC, CVE feed, leaked-credential, dan reputasi IP/domain.",
        "capabilities": ["CVE/NVD feed matching per tech-stack", "IP/domain reputation",
                          "Leaked credentials (HIBP-style)", "Typosquat / phishing domain monitoring"],
        "needs": ["API key feed intel (opsional)", "Scheduler enrichment"],
    },
    "dark-web": {
        "title": "Dark Web Crawling",
        "status": "planned",
        "summary": "Pantau kebocoran data/kredensial & penyebutan brand klien di forum/marketplace onion.",
        "capabilities": ["Keyword/brand monitoring", "Credential-leak alerting", "Paste-site monitoring"],
        "needs": ["Tor egress / crawler infra", "Legal review per klien"],
    },
    "siem-log": {
        "title": "SIEM Log",
        "status": "planned",
        "summary": "Ingest log klien, deteksi anomali dengan AI, dan beri rekomendasi config konkret (bukan sekadar saran).",
        "capabilities": ["Log ingestion (syslog/beats)", "AI anomaly detection",
                          "Concrete hardening config output", "Alert correlation"],
        "needs": ["Log pipeline (OpenSearch/Elastic)", "Storage"],
    },
}


@router.get("/spec/{name}")
def module_spec(name: str, user: User = Depends(get_current_user)):
    spec = _PLANNED.get(name)
    if not spec:
        raise HTTPException(status_code=404, detail="Unknown module")
    return spec
