"""Iron360 modules beyond VAPT AI.

Per the brief, Iron360's dashboard also hosts Threat Intel, Dark Web Crawling,
Domain Health and SIEM Log. The brief says to focus on VAPT AI first, so:
  - Domain Health is implemented (functional) — it reuses the in-scope, installed recon tools.
  - Threat Intel / Dark Web / SIEM return a structured capability spec with status "planned"
    (phase 2), so the module is present and honest rather than faked.
"""
from __future__ import annotations

import socket
import ssl

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..database import get_db
from ..engine import executor, scope
from ..models import Target, User
from ..security import get_current_user

router = APIRouter(prefix="/api/modules", tags=["modules"])


def _tls_probe(host: str) -> dict:
    out = {"ok": False, "protocol": None, "cipher": None, "issuer": None, "expires": None, "error": None}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, 443), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                out["ok"] = True
                out["protocol"] = ss.version()
                out["cipher"] = ss.cipher()[0] if ss.cipher() else None
                cert = ss.getpeercert()
                if cert:
                    out["issuer"] = dict(x[0] for x in cert.get("issuer", [])).get("organizationName")
                    out["expires"] = cert.get("notAfter")
    except Exception as e:  # noqa: BLE001
        out["error"] = str(e)
    return out


@router.get("/domain-health/{target_id}")
def domain_health(target_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    target = db.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    host = scope.normalize_host(target.value)
    decision = scope.check(target, host)
    if not decision.allowed:
        raise HTTPException(status_code=403, detail=decision.reason)

    # DNS resolution
    dns = {"resolved": [], "error": None}
    try:
        infos = socket.getaddrinfo(host, None)
        dns["resolved"] = sorted({i[4][0] for i in infos})
    except Exception as e:  # noqa: BLE001
        dns["error"] = str(e)

    tls = _tls_probe(host)

    # HTTP headers / tech via httpx (scope-enforced executor)
    http = {"raw": "", "ok": False}
    res = executor.run(target, "httpx", host, {})
    if res.ok:
        http = {"ok": True, "raw": (res.stdout or "").strip()}
    else:
        http = {"ok": False, "raw": res.denied_reason}

    # Simple grading
    issues = []
    if tls.get("protocol") in ("TLSv1", "TLSv1.1"):
        issues.append({"sev": "medium", "msg": f"Weak TLS protocol negotiated: {tls['protocol']}"})
    if tls.get("error"):
        issues.append({"sev": "info", "msg": f"TLS probe: {tls['error']}"})
    if not dns["resolved"]:
        issues.append({"sev": "high", "msg": "Host does not resolve"})

    score = max(0, 100 - sum({"high": 30, "medium": 15, "low": 7, "info": 2}.get(i["sev"], 0) for i in issues))
    return {"target": target.value, "score": score, "dns": dns, "tls": tls, "http": http, "issues": issues}


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
