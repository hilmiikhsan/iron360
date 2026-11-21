"""Active payload testing (scope-enforced) — OWASP Top 10 / PortSwigger coverage.

After gf-pattern tagging finds candidate parameters, this sends targeted, SAFE payloads
to the AUTHORIZED, in-scope target and PROVES a vulnerability from the response — turning
'likely' candidates into 'confirmed' findings with reproducible evidence.

Parameter-based tests (need a candidate URL with a query param):
  - Reflected XSS            marker reflected unencoded in the response
  - SQLi (error + boolean)   DB error string / TRUE-vs-FALSE differential
  - OS command injection     time-based (sleep) differential  [A03]
  - SSTI                     unique arithmetic evaluated in the response  [A03]
  - LFI / path traversal     /etc/passwd content appears  [A01/A03]
  - Open redirect            Location header points to attacker domain  [A01]

Target-level tests (run against the base URL, no param needed):
  - CORS misconfiguration    Origin reflected + ACAC:true  [A05]
  - CRLF / header injection  injected header appears in the response  [A03]
  - Host-header injection    poisoned Host reflected in body/redirect  [A03]
  - Security headers         missing CSP / X-Frame-Options / HSTS (clickjacking)  [A05]

Every request is scope-checked (host must be in the engagement scope), low-volume, and
non-destructive. Uses the httpx python library already in the dependencies.
"""
from __future__ import annotations

import re
import time
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
# SSTI: large unique product, very unlikely to appear by coincidence; test several engines.
_SSTI_PAYLOADS = ["{{1337*1337}}", "${1337*1337}", "#{1337*1337}", "<%= 1337*1337 %>"]
_SSTI_RESULT = "1787569"
# Command injection: time-based (robust, blind-safe). Delay must be clearly above baseline.
_CMDI_DELAY = 6
_CMDI_PAYLOADS = [";sleep 6", "|sleep 6", "$(sleep 6)", "`sleep 6`", "& ping -c 6 127.0.0.1 &"]
# Open redirect: a harmless external host we never actually visit, only detect in Location.
_REDIRECT_PAYLOADS = ["https://iron360-oob.example", "//iron360-oob.example", "/\\iron360-oob.example"]
_CRLF_PAYLOAD = "%0d%0aIron360-Injected:1"

_HEADERS = {"User-Agent": "Iron360-VAPT/1.0 (authorized assessment)"}


def _set_param(url: str, value: str, param: str | None = None) -> str:
    u = urlparse(url)
    qs = parse_qsl(u.query, keep_blank_values=True)
    if not qs:
        return url
    target_param = param or qs[0][0]
    qs = [(k, value if k == target_param else v) for k, v in qs]
    return urlunparse(u._replace(query=urlencode(qs, safe="/:${}#<>|&`")))


def _first_param(url: str) -> str | None:
    qs = parse_qsl(urlparse(url).query, keep_blank_values=True)
    return qs[0][0] if qs else None


def _get(client: httpx.Client, url: str, **kw):
    try:
        return client.get(url, **kw)
    except Exception:  # noqa: BLE001
        return None


# ------------------------------------------------------------- parameter-based tests
def test_xss(client, url: str, param: str) -> dict | None:
    r = _get(client, _set_param(url, XSS_MARKER, param))
    if r is not None and XSS_MARKER in r.text:
        return _f("Reflected XSS in '%s' parameter" % param, "high", "confirmed", 92, url, "A03", "Cross-site scripting",
                  f"The '{param}' parameter reflects input unencoded, allowing reflected XSS.",
                  f"Payload {XSS_MARKER} was reflected verbatim (unencoded) in the response body.",
                  "Context-aware output encoding on reflected values; add a strict CSP.",
                  ("# nginx CSP (defense-in-depth)\nadd_header Content-Security-Policy "
                   "\"default-src 'self'; script-src 'self'\" always;\n"
                   "// Server-side: htmlspecialchars($v, ENT_QUOTES, 'UTF-8');"),
                  "1. Encode the reflected value at output. 2. Add CSP. 3. Re-test — payload must appear encoded.")
    return None


def test_sqli(client, url: str, param: str) -> dict | None:
    r_err = _get(client, _set_param(url, "iron360" + SQLI_QUOTE, param))
    if r_err is not None and _SQL_ERRORS.search(r_err.text):
        return _f("SQL Injection (error-based) in '%s'" % param, "critical", "confirmed", 90, url, "A03", "SQL injection",
                  f"Injecting a single quote into '{param}' triggers a database error — SQL injection.",
                  "A SQL error message appeared in the response after injecting a single quote.",
                  "Use parameterized queries / prepared statements; never concatenate input into SQL.",
                  "$stmt = $pdo->prepare('SELECT * FROM t WHERE col = :v');\n$stmt->execute([':v' => $input]);",
                  "1. Convert to a prepared statement. 2. Re-test — the quote must no longer error.")
    base = _get(client, url)
    r_true = _get(client, _set_param(url, "1' AND '1'='1", param))
    r_false = _get(client, _set_param(url, "1' AND '1'='2", param))
    if base is not None and r_true is not None and r_false is not None:
        lt, lf = len(r_true.text), len(r_false.text)
        if lt and lf and abs(lt - lf) > max(60, 0.15 * max(lt, lf)) and abs(len(base.text) - lt) < abs(len(base.text) - lf):
            return _f("SQL Injection (boolean-based blind) in '%s'" % param, "critical", "confirmed", 85, url, "A03",
                      "SQL injection",
                      f"'{param}' is injectable: TRUE and FALSE conditions return materially different responses.",
                      f"AND '1'='1' -> {lt} bytes vs AND '1'='2' -> {lf} bytes (differential proves blind SQLi).",
                      "Use parameterized queries; validate and type-cast the parameter.",
                      "$stmt = $pdo->prepare('SELECT * FROM t WHERE id = :id');\n$stmt->execute([':id' => (int)$id]);",
                      "1. Parameterize the query. 2. Re-test: TRUE/FALSE responses must become identical.")
    return None


def test_lfi(client, url: str, param: str) -> dict | None:
    r = _get(client, _set_param(url, LFI_PAYLOAD, param))
    if r is not None and _PASSWD.search(r.text):
        return _f("Local File Inclusion / Path Traversal in '%s'" % param, "critical", "confirmed", 93, url, "A01",
                  "Path traversal",
                  f"'{param}' allows traversal to arbitrary files (read /etc/passwd).",
                  "The response contained /etc/passwd content (root:...:0:0:) after a traversal payload.",
                  "Reject path separators; use an allowlist of permitted files; canonicalize and verify the path.",
                  ("$allowed = ['home','about']; $p = basename($_GET['page']);\n"
                   "if (!in_array($p, $allowed)) { http_response_code(400); exit; }"),
                  "1. Allowlist filenames + basename(). 2. Re-test the traversal payload — it must be blocked.")
    return None


def test_ssti(client, url: str, param: str) -> dict | None:
    for p in _SSTI_PAYLOADS:
        r = _get(client, _set_param(url, "iron360" + p, param))
        if r is not None and _SSTI_RESULT in r.text and p not in r.text:
            return _f("Server-Side Template Injection in '%s'" % param, "critical", "confirmed", 90, url, "A03",
                      "Server-side template injection",
                      f"'{param}' is evaluated by a server-side template engine — SSTI (often leads to RCE).",
                      f"Payload {p} evaluated to {_SSTI_RESULT} in the response (arithmetic executed server-side).",
                      "Never pass user input into template source; use a sandboxed engine + logic-less templates.",
                      "# Pass data as context, never concatenate into the template string:\n"
                      "render_template('page.html', name=user_input)  # NOT render_template_string(user_input)",
                      "1. Move user input to template variables. 2. Re-test — the arithmetic must not evaluate.")
    return None


def test_cmdi(client, url: str, param: str) -> dict | None:
    base = _get(client, url)
    base_t = _elapsed(client, _set_param(url, "iron360", param))
    if base_t is None:
        return None
    for p in _CMDI_PAYLOADS:
        t = _elapsed(client, _set_param(url, "iron360" + p, param))
        if t is not None and t >= _CMDI_DELAY - 0.5 and t - base_t >= _CMDI_DELAY - 1.5:
            return _f("OS Command Injection in '%s'" % param, "critical", "confirmed", 88, url, "A03",
                      "OS command injection",
                      f"'{param}' passes input to an OS command — time-based command injection confirmed.",
                      f"Payload '{p}' delayed the response to {t:.1f}s vs baseline {base_t:.1f}s (injected sleep executed).",
                      "Never pass user input to a shell; use language-native APIs with argument arrays; strict allowlist.",
                      "// Safe: pass args as a list, no shell\n"
                      "subprocess.run(['ping', '-c', '1', host])  # NOT os.system('ping ' + host)",
                      "1. Remove shell invocation / use arg arrays. 2. Re-test — the sleep delay must disappear.")
    return None


def test_redirect(client, url: str, param: str) -> dict | None:
    for p in _REDIRECT_PAYLOADS:
        r = _get(client, _set_param(url, p, param), follow_redirects=False)
        if r is None:
            continue
        loc = r.headers.get("location", "")
        if r.status_code in (301, 302, 303, 307, 308) and "iron360-oob.example" in loc:
            return _f("Open Redirect in '%s'" % param, "medium", "confirmed", 88, url, "A01",
                      "Open redirect",
                      f"'{param}' controls the redirect target — open redirect (phishing / OAuth token theft / SSRF pivot).",
                      f"Payload {p} produced a {r.status_code} redirect to {loc}.",
                      "Allowlist redirect destinations; never redirect to a raw user-supplied URL.",
                      "$allowed = ['/dashboard','/home'];\nif (!in_array($next, $allowed)) $next = '/home';\nheader('Location: '.$next);",
                      "1. Allowlist internal paths only. 2. Re-test — the external redirect must be blocked.")
    return None


# ------------------------------------------------------------- target-level tests
def test_cors(client, base_url: str) -> dict | None:
    evil = "https://iron360-evil.example"
    r = _get(client, base_url, headers={**_HEADERS, "Origin": evil})
    if r is None:
        return None
    acao = r.headers.get("access-control-allow-origin", "")
    acac = r.headers.get("access-control-allow-credentials", "").lower()
    if acao == evil or (acao == "*" and acac == "true"):
        sev = "high" if acac == "true" else "medium"
        return _f("CORS misconfiguration", sev, "confirmed", 85, base_url, "A05",
                  "Cross-origin resource sharing (CORS)",
                  "The server reflects an arbitrary Origin (and allows credentials) — any site can read authenticated responses.",
                  f"Request Origin: {evil} -> Access-Control-Allow-Origin: {acao}; Allow-Credentials: {acac or 'n/a'}.",
                  "Never reflect Origin; use a strict server-side allowlist; don't combine wildcard with credentials.",
                  "# Only echo Origin if it is in your allowlist\nif origin in ALLOWED_ORIGINS:\n    resp.headers['Access-Control-Allow-Origin'] = origin",
                  "1. Replace Origin reflection with an allowlist. 2. Re-test with a foreign Origin — it must not be reflected.")
    return None


def test_crlf(client, base_url: str) -> dict | None:
    u = urlparse(base_url)
    probe = urlunparse(u._replace(path=(u.path or "/") + _CRLF_PAYLOAD))
    r = _get(client, probe)
    if r is not None and ("iron360-injected" in {k.lower() for k in r.headers.keys()}
                          or r.headers.get("Iron360-Injected") == "1"):
        return _f("CRLF / HTTP response-header injection", "medium", "confirmed", 82, base_url, "A03",
                  "HTTP request smuggling / response splitting",
                  "User input is placed into a response header without CRLF sanitization — header injection.",
                  "Injected sequence %0d%0aIron360-Injected:1 produced a new response header.",
                  "Strip CR/LF from any value placed in a response header; use the framework's header API.",
                  "value = re.sub(r'[\\r\\n]', '', user_value)",
                  "1. Sanitize CR/LF in header values. 2. Re-test — the injected header must not appear.")
    return None


def test_host_header(client, base_url: str) -> dict | None:
    evil = "iron360-evil.example"
    r = _get(client, base_url, headers={**_HEADERS, "Host": evil}, follow_redirects=False)
    if r is None:
        return None
    loc = r.headers.get("location", "")
    if evil in loc or evil in r.text:
        return _f("Host header injection", "medium", "needs_review", 70, base_url, "A03",
                  "Host header attacks",
                  "The app reflects an attacker-controlled Host header — may enable cache poisoning / password-reset poisoning.",
                  f"Host: {evil} was reflected in {'Location: ' + loc if evil in loc else 'the response body'}.",
                  "Validate Host against an allowlist of expected domains; use absolute URLs from config, not the Host header.",
                  "# nginx: reject unknown hosts\nserver { server_name _; return 421; }  # default server block",
                  "1. Pin expected Host(s). 2. Re-test with a foreign Host — it must be rejected, not reflected.")
    return None


def test_security_headers(client, base_url: str) -> dict | None:
    r = _get(client, base_url)
    if r is None:
        return None
    h = {k.lower(): v for k, v in r.headers.items()}
    missing = []
    if "content-security-policy" not in h:
        missing.append("Content-Security-Policy")
    if "x-frame-options" not in h and "frame-ancestors" not in h.get("content-security-policy", "").lower():
        missing.append("X-Frame-Options (clickjacking)")
    if base_url.startswith("https") and "strict-transport-security" not in h:
        missing.append("Strict-Transport-Security (HSTS)")
    if "x-content-type-options" not in h:
        missing.append("X-Content-Type-Options")
    if not missing:
        return None
    sev = "medium" if "X-Frame-Options (clickjacking)" in missing else "low"
    return _f("Missing security headers", sev, "confirmed", 90, base_url, "A05",
              "Security misconfiguration",
              "Key hardening response headers are absent, enabling clickjacking / MIME-sniffing / downgrade risks.",
              "Missing: " + ", ".join(missing),
              "Add the missing hardening headers at the web server / app layer.",
              ("# nginx\nadd_header Content-Security-Policy \"default-src 'self'; frame-ancestors 'none'\" always;\n"
               "add_header X-Frame-Options DENY always;\n"
               "add_header X-Content-Type-Options nosniff always;\n"
               "add_header Strict-Transport-Security \"max-age=63072000; includeSubDomains\" always;"),
              "1. Add headers. 2. nginx -t && reload. 3. Re-test: curl -I must show them.")


_GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/graphql/console", "/graphiql", "/query"]
_INTROSPECT = {"query": "{__schema{queryType{name} types{name}}}"}

# path -> (regex signature proving real exposure)  [HackTricks pentesting-web / OWASP A01/A05]
_EXPOSED_PATHS = {
    "/.git/config": re.compile(r"\[core\]|repositoryformatversion"),
    "/.env": re.compile(r"(APP_KEY|DB_PASSWORD|SECRET|API_KEY|AWS_)"),
    "/.svn/entries": re.compile(r"^\d+\s|svn://|dir"),
    "/server-status": re.compile(r"Apache Server Status"),
    "/actuator/health": re.compile(r'"status"\s*:\s*"(UP|DOWN)"'),
    "/actuator/env": re.compile(r'"(propertySources|activeProfiles)"'),
    "/phpinfo.php": re.compile(r"phpinfo\(\)|PHP Version"),
    "/.aws/credentials": re.compile(r"aws_access_key_id", re.I),
    "/wp-config.php.bak": re.compile(r"DB_PASSWORD|DB_NAME"),
    "/.DS_Store": re.compile(r"Bud1"),
}


def test_graphql(client, base_url: str) -> dict | None:
    for path in _GRAPHQL_PATHS:
        url = base_url.rstrip("/") + path
        try:
            r = client.post(url, json=_INTROSPECT)
        except Exception:  # noqa: BLE001
            continue
        if r is None:
            continue
        body = r.text
        if r.status_code == 200 and "__schema" in body and ('"types"' in body or '"queryType"' in body):
            return _f("GraphQL introspection enabled", "medium", "confirmed", 85, url, "A05",
                      "GraphQL API vulnerabilities",
                      "The GraphQL endpoint answers introspection — the full schema (types, queries, mutations) is exposed.",
                      f"POST {path} with an introspection query returned a populated __schema.",
                      "Disable introspection in production; enforce auth + query depth/complexity limits.",
                      "# Apollo Server\nnew ApolloServer({ introspection: false });",
                      "1. Disable introspection in prod. 2. Re-test — introspection must return an error.")
    return None


def test_exposed_paths(client, base_url: str) -> dict | None:
    hits = []
    for path, sig in _EXPOSED_PATHS.items():
        r = _get(client, base_url.rstrip("/") + path)
        if r is not None and r.status_code == 200 and sig.search(r.text):
            hits.append(path)
    if hits:
        sev = "high" if any(p in hits for p in ("/.env", "/.git/config", "/.aws/credentials",
                                                "/wp-config.php.bak", "/actuator/env")) else "medium"
        return _f("Sensitive files / endpoints exposed", sev, "confirmed", 90, base_url, "A05",
                  "Information disclosure",
                  "Internal config/VCS/debug endpoints are publicly reachable and leak sensitive data.",
                  "Exposed with matching content: " + ", ".join(hits),
                  "Block these paths at the web server; remove them from the web root; rotate any leaked secrets.",
                  ("# nginx — deny dotfiles & debug endpoints\n"
                   "location ~ /\\.(git|svn|env|aws|DS_Store) { deny all; return 404; }\n"
                   "location /actuator { deny all; }\nlocation /server-status { deny all; }"),
                  "1. Block/remove the paths. 2. Rotate leaked secrets. 3. Re-test — each must return 403/404.")
    return None


def test_http_methods(client, base_url: str) -> dict | None:
    try:
        r = client.request("OPTIONS", base_url)
    except Exception:  # noqa: BLE001
        r = None
    allow = (r.headers.get("allow", "") if r is not None else "").upper()
    risky = [m for m in ("PUT", "DELETE", "TRACE", "CONNECT", "PATCH") if m in allow]
    # TRACE → Cross-Site Tracing (XST)
    try:
        rt = client.request("TRACE", base_url)
        trace_on = rt is not None and rt.status_code == 200 and "TRACE" in rt.text.upper()
    except Exception:  # noqa: BLE001
        trace_on = False
    if risky or trace_on:
        detail = (f"OPTIONS Allow: {allow}. " if risky else "") + ("TRACE enabled (XST). " if trace_on else "")
        return _f("Dangerous HTTP methods enabled", "medium" if ("PUT" in risky or "DELETE" in risky) else "low",
                  "confirmed", 80, base_url, "A05", "HTTP methods misconfiguration",
                  "The server permits write/debug HTTP methods that should be disabled.",
                  detail.strip(),
                  "Disable PUT/DELETE/TRACE/CONNECT unless explicitly required; allow only GET/POST/HEAD.",
                  "# nginx\nif ($request_method !~ ^(GET|POST|HEAD)$) { return 405; }",
                  "1. Restrict methods. 2. Re-test OPTIONS/TRACE — risky methods must be rejected.")
    return None


# ------------------------------------------------------------- helpers
def _elapsed(client, url: str) -> float | None:
    t0 = time.time()
    r = _get(client, url)
    return (time.time() - t0) if r is not None else None


def _f(title, severity, status, confidence, affected, owasp, portswigger,
       description, evidence, remediation, fix_config, fix_steps) -> dict:
    return {"title": title, "severity": severity, "status": status, "confidence": confidence,
            "affected": affected, "cve": "", "owasp": owasp, "portswigger": portswigger,
            "description": f"[{owasp} · {portswigger}] {description}", "evidence": evidence,
            "remediation": remediation, "fix_config": fix_config, "fix_steps": fix_steps,
            "sources": ["iron360-probe"]}


_PARAM_PLAN = [
    ("xss", test_xss), ("sqli", test_sqli), ("lfi", test_lfi),
    ("rce", test_cmdi), ("ssti", test_ssti), ("redirect", test_redirect),
]


def run_probes(target: Target, cats: dict, emit, stop_event: threading.Event | None = None,
               max_per_cat: int = 2) -> list[dict]:
    findings: list[dict] = []
    with httpx.Client(timeout=15, verify=False, follow_redirects=True, headers=_HEADERS) as client:
        # Parameter-based active tests on gf candidates.
        for cat, fn in _PARAM_PLAN:
            if stop_event is not None and stop_event.is_set():
                break
            # SSTI/RCE reuse reflected (xss) candidates when no dedicated bucket exists.
            urls = cats.get(cat) or (cats.get("xss", []) if cat in ("ssti", "rce") else [])
            for url in urls[:max_per_cat]:
                if stop_event is not None and stop_event.is_set():
                    break
                if not scope.check(target, scope.normalize_host(url)).allowed:
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

        # Target-level tests on the base URL (no param needed).
        if stop_event is None or not stop_event.is_set():
            host = scope.normalize_host(target.value)
            if scope.check(target, host).allowed:
                base_url = f"https://{host}"
                emit({"type": "reasoning", "text": "Active target-level probes: CORS, CRLF, Host-header, security headers, "
                      "GraphQL introspection, exposed files, HTTP methods."})
                for fn in (test_cors, test_crlf, test_host_header, test_security_headers,
                           test_graphql, test_exposed_paths, test_http_methods):
                    if stop_event is not None and stop_event.is_set():
                        break
                    try:
                        f = fn(client, base_url)
                    except Exception:  # noqa: BLE001
                        f = None
                    if f:
                        findings.append(f)
    return findings
