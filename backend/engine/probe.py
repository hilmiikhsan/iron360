"""Active payload testing (scope-enforced).

After gf-pattern tagging finds candidate parameters, this sends targeted payloads to
the AUTHORIZED, in-scope target and PROVES a vulnerability from the response — turning
'likely' candidates into 'confirmed' findings with reproducible evidence:
  - reflected XSS: unique marker reflected unencoded in the response
  - error-based SQLi: DB error strings appear after injecting a quote
  - boolean-based SQLi: TRUE vs FALSE conditions yield materially different responses
  - LFI / path traversal: /etc/passwd content appears in the response

Every request is scope-checked (host must be in the engagement scope) and low-volume.
Uses the httpx python library already in the dependencies.
"""
from __future__ import annotations

import re
import threading
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import httpx

from ..models import Target
from . import scope

_SQL_ERRORS = re.compile(
    r"(SQL syntax|mysql_fetch|ORA-\d{5}|PostgreSQL.*ERROR|SQLSTATE|Unclosed quotation|"
    r"quoted string not properly terminated|SQLite3::|near \".*\": syntax error|"
    r"Warning.*mysqli?|supplied argument is not a valid MySQL)", re.I)
_PASSWD = re.compile(r"root:.*?:0:0:")

XSS_MARKER = 'iron360x"><svg/onload=alert(1)>'
SQLI_QUOTE = "'"
LFI_PAYLOAD = "../../../../../../../../etc/passwd"

_HEADERS = {"User-Agent": "Iron360-VAPT/1.0 (authorized assessment)"}


def _set_param(url: str, value: str, param: str | None = None) -> str:
    u = urlparse(url)
    qs = parse_qsl(u.query, keep_blank_values=True)
    if not qs:
        return url
    target_param = param or qs[0][0]
    qs = [(k, value if k == target_param else v) for k, v in qs]
    return urlunparse(u._replace(query=urlencode(qs)))


def _first_param(url: str) -> str | None:
    qs = parse_qsl(urlparse(url).query, keep_blank_values=True)
    return qs[0][0] if qs else None


def _get(client: httpx.Client, url: str) -> httpx.Response | None:
    try:
        return client.get(url)
    except Exception:  # noqa: BLE001
        return None


def test_xss(client, url: str, param: str) -> dict | None:
    r = _get(client, _set_param(url, XSS_MARKER, param))
    if r is not None and XSS_MARKER in r.text:
        return {
            "title": f"Reflected XSS in '{param}' parameter", "severity": "high", "status": "confirmed",
            "confidence": 92, "affected": url, "cve": "",
            "description": f"The '{param}' parameter reflects input unencoded, allowing reflected XSS.",
            "evidence": f"Payload {XSS_MARKER} was reflected verbatim in the HTTP response body (unencoded).",
            "remediation": "Context-aware output encoding on reflected values; add a strict CSP.",
            "fix_config": ("# nginx CSP (defense-in-depth)\nadd_header Content-Security-Policy "
                           "\"default-src 'self'; script-src 'self'\" always;\n"
                           "// Server-side: HTML-encode on output, e.g. htmlspecialchars($v, ENT_QUOTES, 'UTF-8');"),
            "fix_steps": "1. Encode the reflected value at output. 2. Add CSP. 3. Re-test the payload — it must appear encoded.",
            "sources": ["iron360-probe"],
        }
    return None


def test_sqli(client, url: str, param: str) -> dict | None:
    # error-based
    r_err = _get(client, _set_param(url, "iron360" + SQLI_QUOTE, param))
    if r_err is not None and _SQL_ERRORS.search(r_err.text):
        return {
            "title": f"SQL Injection (error-based) in '{param}'", "severity": "critical", "status": "confirmed",
            "confidence": 90, "affected": url, "cve": "",
            "description": f"Injecting a single quote into '{param}' triggers a database error — SQL injection.",
            "evidence": "A SQL error message appeared in the response after injecting a single quote.",
            "remediation": "Use parameterized queries / prepared statements; never concatenate input into SQL.",
            "fix_config": ("$stmt = $pdo->prepare('SELECT * FROM t WHERE col = :v');\n$stmt->execute([':v' => $input]);"),
            "fix_steps": "1. Convert the query to a prepared statement. 2. Re-test — the quote must no longer error.",
            "sources": ["iron360-probe"],
        }
    # boolean-based (differential)
    base = _get(client, url)
    r_true = _get(client, _set_param(url, "1' AND '1'='1", param))
    r_false = _get(client, _set_param(url, "1' AND '1'='2", param))
    if base is not None and r_true is not None and r_false is not None:
        lt, lf = len(r_true.text), len(r_false.text)
        if lt and lf and abs(lt - lf) > max(60, 0.15 * max(lt, lf)) and abs(len(base.text) - lt) < abs(len(base.text) - lf):
            return {
                "title": f"SQL Injection (boolean-based blind) in '{param}'", "severity": "critical", "status": "confirmed",
                "confidence": 85, "affected": url, "cve": "",
                "description": f"'{param}' is injectable: TRUE and FALSE conditions return materially different responses.",
                "evidence": f"AND '1'='1' -> {lt} bytes vs AND '1'='2' -> {lf} bytes (differential proves blind SQLi).",
                "remediation": "Use parameterized queries; validate and type-cast the parameter.",
                "fix_config": "$stmt = $pdo->prepare('SELECT * FROM t WHERE id = :id');\n$stmt->execute([':id' => (int)$id]);",
                "fix_steps": "1. Parameterize the query. 2. Re-test: TRUE/FALSE responses must become identical.",
                "sources": ["iron360-probe"],
            }
    return None


def test_lfi(client, url: str, param: str) -> dict | None:
    r = _get(client, _set_param(url, LFI_PAYLOAD, param))
    if r is not None and _PASSWD.search(r.text):
        return {
            "title": f"Local File Inclusion / Path Traversal in '{param}'", "severity": "critical", "status": "confirmed",
            "confidence": 93, "affected": url, "cve": "",
            "description": f"'{param}' allows traversal to arbitrary files (read /etc/passwd).",
            "evidence": "The response contained /etc/passwd content (root:...:0:0:) after a traversal payload.",
            "remediation": "Reject path separators; use an allowlist of permitted files; canonicalize and verify the path.",
            "fix_config": ("$allowed = ['home','about']; $p = basename($_GET['page']);\n"
                           "if (!in_array($p, $allowed)) { http_response_code(400); exit; }"),
            "fix_steps": "1. Allowlist filenames + basename(). 2. Re-test the traversal payload — it must be blocked.",
            "sources": ["iron360-probe"],
        }
    return None


def run_probes(target: Target, cats: dict, emit, stop_event: threading.Event | None = None,
               max_per_cat: int = 2) -> list[dict]:
    findings: list[dict] = []
    plan = [("xss", test_xss), ("sqli", test_sqli), ("lfi", test_lfi)]
    with httpx.Client(timeout=12, verify=False, follow_redirects=True, headers=_HEADERS) as client:
        for cat, fn in plan:
            if stop_event is not None and stop_event.is_set():
                break
            for url in cats.get(cat, [])[:max_per_cat]:
                if stop_event is not None and stop_event.is_set():
                    break
                host = scope.normalize_host(url)
                if not scope.check(target, host).allowed:
                    continue
                param = _first_param(url)
                if not param:
                    continue
                emit({"type": "reasoning", "text": f"Active {cat.upper()} probe on '{param}' @ {url[:80]}"})
                try:
                    f = fn(client, url, param)
                except Exception:  # noqa: BLE001
                    f = None
                if f:
                    findings.append(f)
    return findings
