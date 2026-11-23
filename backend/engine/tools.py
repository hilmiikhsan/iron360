"""Tool allowlist registry.

The AI cannot run arbitrary shell. It may only request tools defined here, and
only with the options each tool explicitly allows. Every argv is built as a list
(no shell string), so there is no command-injection surface. The target host is
injected by the executor AFTER a scope check — never taken raw from the model.
"""
from __future__ import annotations

import re
import shutil
from dataclasses import dataclass, field
from typing import Callable

from ..config import get_settings

_settings = get_settings()


def _content_wordlist(o: dict) -> str:
    if o.get("wordlist"):
        return _clean(o["wordlist"])
    return _settings.wordlist("raft-small-directories.txt", "common.txt")

# Characters permitted in free-form option values (paths, wordlist names, params).
_SAFE_VALUE = re.compile(r"^[A-Za-z0-9._\-/=:,%&?]{0,200}$")


def _clean(value: str) -> str:
    v = str(value).strip()
    if not _SAFE_VALUE.match(v):
        raise ValueError(f"option value rejected by sanitizer: {value!r}")
    return v


@dataclass
class Tool:
    name: str
    binary: str
    category: str          # recon | va | exploit
    intensity: str         # passive | active | intrusive
    description: str
    # builder(host, options) -> argv list. Must only use sanitized values.
    build: Callable[[str, dict], list[str]]
    needs_scheme: bool = False  # host should be presented as URL (http/https)
    # optional stdin(host, options) -> str for tools that read targets on stdin
    stdin: Callable[[str, dict], str] | None = None

    @property
    def installed(self) -> bool:
        return shutil.which(self.binary) is not None


def _url(host: str, opts: dict) -> str:
    scheme = "https" if opts.get("scheme", "https") == "https" else "http"
    return f"{scheme}://{host}"


REGISTRY: dict[str, Tool] = {}


def _register(tool: Tool) -> None:
    REGISTRY[tool.name] = tool


# ---------------------------------------------------------------- recon
_register(Tool(
    name="subfinder", binary="subfinder", category="recon", intensity="passive",
    description="Passive subdomain enumeration for a root domain.",
    build=lambda host, o: ["subfinder", "-silent", "-d", host],
))

_register(Tool(
    name="dnsx", binary="dnsx", category="recon", intensity="passive",
    description="Resolve a host's DNS records (A, CNAME) — host supplied on stdin.",
    build=lambda host, o: ["dnsx", "-silent", "-a", "-cname", "-resp"],
    stdin=lambda host, o: host + "\n",
))

_register(Tool(
    name="reverseip", binary="nmap", category="recon", intensity="passive",
    description="Reverse-DNS / reverse-IP mass lookup for an IP or CIDR (no packets sent to hosts). "
                "Discovers hostnames/vhosts sharing an address.",
    build=lambda host, o: ["nmap", "-sL", "-Pn", host],
))

_register(Tool(
    name="httpx", binary="httpx", category="recon", intensity="active",
    description="Probe a host for live HTTP services; returns status, title, tech, server.",
    build=lambda host, o: ["httpx", "-silent", "-status-code", "-title", "-tech-detect",
                            "-web-server", "-follow-redirects", "-u", host],
))

_register(Tool(
    name="whatweb", binary="whatweb", category="recon", intensity="active",
    description="Fingerprint web technologies (CMS, server, frameworks, versions).",
    build=lambda host, o: ["whatweb", "--no-errors", "-a", "3", _url(host, o)],
    needs_scheme=True,
))

_register(Tool(
    name="wafw00f", binary="wafw00f", category="recon", intensity="active",
    description="Detect which WAF/firewall protects the target (informs evasion/expectations).",
    build=lambda host, o: ["wafw00f", "-a", _url(host, o)],
    needs_scheme=True,
))

_register(Tool(
    name="gau", binary="gau", category="recon", intensity="passive",
    description="Gather known URLs for a domain from Wayback/OTX/CommonCrawl (passive).",
    build=lambda host, o: ["gau", "--threads", "5", "--timeout", "25", host],
))

_register(Tool(
    name="waybackurls", binary="waybackurls", category="recon", intensity="passive",
    description="Fetch a domain's archived URLs from the Wayback Machine (passive).",
    build=lambda host, o: ["waybackurls", host],
))

_register(Tool(
    name="hakrawler", binary="hakrawler", category="recon", intensity="active",
    description="Fast endpoint/URL crawler — host supplied on stdin.",
    build=lambda host, o: ["hakrawler", "-u", "-d", "2", "-t", "10"],
    stdin=lambda host, o: _url(host, o) + "\n",
    needs_scheme=True,
))

_register(Tool(
    name="paramspider", binary="paramspider", category="recon", intensity="passive",
    description="Mine URL parameters for a domain from archives (parameter discovery).",
    build=lambda host, o: ["paramspider", "-d", host, "--subs", "false"],
))

_register(Tool(
    name="amass", binary="amass", category="recon", intensity="passive",
    description="Subdomain enumeration / asset mapping (passive mode only).",
    build=lambda host, o: ["amass", "enum", "-passive", "-d", host, "-timeout", "5"],
))

_register(Tool(
    name="assetfinder", binary="assetfinder", category="recon", intensity="passive",
    description="Discover subdomains for a domain (passive).",
    build=lambda host, o: ["assetfinder", "--subs-only", host],
))

_register(Tool(
    name="findomain", binary="findomain", category="recon", intensity="passive",
    description="Subdomain enumeration using certificate transparency + APIs (passive).",
    build=lambda host, o: ["findomain", "-t", host, "-q"],
))

_register(Tool(
    name="dig", binary="dig", category="recon", intensity="passive",
    description="DNS lookup + attempt AXFR zone transfer against the domain's NS.",
    build=lambda host, o: ["dig", "+nocmd", "+noall", "+answer", "ANY", host],
))

_register(Tool(
    name="katana", binary="katana", category="recon", intensity="active",
    description="Crawl a site for endpoints/URLs (depth 2, JS-aware).",
    build=lambda host, o: ["katana", "-u", _url(host, o), "-silent", "-d", "2", "-jc", "-timeout", "15"],
    needs_scheme=True,
))

_register(Tool(
    name="sslscan", binary="sslscan", category="recon", intensity="active",
    description="Enumerate SSL/TLS protocols and ciphers (weak protocol detection).",
    build=lambda host, o: ["sslscan", "--no-colour", host],
))

_register(Tool(
    name="testssl", binary="testssl", category="va", intensity="active",
    description="Deep TLS/SSL audit — protocols, ciphers, certificate chain, BEAST/POODLE/ROBOT/Heartbleed.",
    build=lambda host, o: ["testssl", "--quiet", "--color", "0", "--fast",
                           "--vulnerable", "--headers", host],
))

_register(Tool(
    name="wapiti", binary="wapiti", category="va", intensity="active",
    description="Web application vulnerability scanner — XSS, SQLi, file inclusion, SSRF, command injection, XXE.",
    build=lambda host, o: ["wapiti", "-u", _url(host, o), "--flush-session",
                           "-f", "txt", "--color", "--timeout", "10", "-S", "normal"],
    needs_scheme=True,
))

# ---------------------------------------------------------------- VA
_register(Tool(
    name="nmap", binary="nmap", category="va", intensity="active",
    description="Port/service scan. Options: ports ('80,443' or 'top1000'), sv (version detect), "
                "scripts (NSE category e.g. 'vuln' or 'default,vuln,safe').",
    build=lambda host, o: (
        ["nmap", "-Pn", "-T4"]
        + (["-sV"] if o.get("sv") else [])
        + (["--script", _clean(o["scripts"])] if o.get("scripts") else [])
        + (["-p", _clean(o["ports"])] if o.get("ports") and o["ports"] != "top1000" else ["--top-ports", "1000"])
        + [host]
    ),
))

_register(Tool(
    name="naabu", binary="naabu", category="va", intensity="active",
    description="Fast port scan (connect mode, no root). Top 1000 ports.",
    build=lambda host, o: ["naabu", "-host", host, "-silent", "-top-ports", "1000", "-c", "50", "-scan-type", "c"],
))

_register(Tool(
    name="nikto", binary="nikto", category="va", intensity="active",
    description="Web server vulnerability scanner (misconfig, outdated software, dangerous files).",
    build=lambda host, o: ["nikto", "-host", _url(host, o), "-maxtime", "150s", "-nointeractive", "-ask", "no"],
    needs_scheme=True,
))

_register(Tool(
    name="nuclei", binary="nuclei", category="va", intensity="active",
    description="Template-based vulnerability scanner. Options: severity (comma list e.g. 'critical,high'), "
                "tags (comma list e.g. 'cve,exposure').",
    build=lambda host, o: (
        ["nuclei", "-silent", "-jsonl"]
        + (["-severity", _clean(o["severity"])] if o.get("severity") else ["-severity", "critical,high,medium"])
        + (["-tags", _clean(o["tags"])] if o.get("tags") else [])
        + ["-u", _url(host, o)]
    ),
    needs_scheme=True,
))

_register(Tool(
    name="wpscan", binary="wpscan", category="va", intensity="active",
    description="WordPress scanner — core/plugin/theme versions + known vulns.",
    build=lambda host, o: ["wpscan", "--url", _url(host, o), "--no-banner", "--random-user-agent",
                           "--format", "cli-no-color", "--enumerate", "vp,vt"],
    needs_scheme=True,
))

_register(Tool(
    name="droopescan", binary="droopescan", category="va", intensity="active",
    description="CMS scanner for Drupal/SilverStripe/Joomla/WordPress (version + known issues).",
    build=lambda host, o: ["droopescan", "scan", _clean(o.get("cms", "drupal")), "-u", _url(host, o)],
    needs_scheme=True,
))

_register(Tool(
    name="dirsearch", binary="dirsearch", category="va", intensity="active",
    description="Directory/file brute-force with smart extensions + status filtering.",
    build=lambda host, o: ["dirsearch", "-u", _url(host, o), "-q", "--format=plain",
                           "-e", "php,asp,aspx,jsp,html,js,txt,bak,zip,sql,conf,env,json"],
    needs_scheme=True,
))

# ---------------------------------------------------------------- exploit / deep (intrusive)
_register(Tool(
    name="ffuf", binary="ffuf", category="exploit", intensity="intrusive",
    description="Content/endpoint fuzzing. Option: wordlist (absolute path). FUZZ keyword appended to URL path.",
    build=lambda host, o: [
        "ffuf", "-s", "-mc", "200,204,301,302,307,401,403",
        "-w", _content_wordlist(o),
        "-u", f"{_url(host, o)}/FUZZ",
    ],
    needs_scheme=True,
))

_register(Tool(
    name="gobuster", binary="gobuster", category="exploit", intensity="intrusive",
    description="Directory/file brute-force. Option: wordlist (absolute path).",
    build=lambda host, o: ["gobuster", "dir", "-q", "-t", "30", "-u", _url(host, o), "-w", _content_wordlist(o)],
    needs_scheme=True,
))

_register(Tool(
    name="arjun", binary="arjun", category="exploit", intensity="intrusive",
    description="Discover hidden HTTP parameters (GET/POST) on a URL.",
    build=lambda host, o: ["arjun", "-u", _url(host, o), "-m", "GET", "-q"],
    needs_scheme=True,
))

_register(Tool(
    name="sqlmap", binary="sqlmap", category="exploit", intensity="intrusive",
    description="SQL injection validation on a specific URL (must include a parameter). "
                "Option: param_url (full URL with parameter). Runs non-interactively, read-only (--batch, no risk/level bump).",
    build=lambda host, o: [
        "sqlmap", "--batch", "--disable-coloring", "--flush-session",
        "-u", _require_param_url(host, o),
    ],
    needs_scheme=True,
))


_register(Tool(
    name="dalfox", binary="dalfox", category="exploit", intensity="intrusive",
    description="XSS scanner/validator on a URL with a parameter. Option: param_url (full URL with parameter).",
    build=lambda host, o: ["dalfox", "url", _require_param_url(host, o), "--silence", "--no-color", "--timeout", "20"],
    needs_scheme=True,
))

_register(Tool(
    name="feroxbuster", binary="feroxbuster", category="exploit", intensity="intrusive",
    description="Recursive content/endpoint discovery. Option: wordlist (absolute path).",
    build=lambda host, o: ["feroxbuster", "-u", _url(host, o), "--silent", "-d", "2", "-t", "30",
                           "-w", _content_wordlist(o)],
    needs_scheme=True,
))


_register(Tool(
    name="commix", binary="commix", category="exploit", intensity="intrusive",
    description="OS command-injection detection/validation on a URL with a parameter. "
                "Option: param_url (full URL with parameter). Non-interactive (--batch); detection payloads only.",
    build=lambda host, o: ["commix", "--url=" + _require_param_url(host, o), "--batch",
                           "--skip-waf", "--technique=cet"],
    needs_scheme=True,
))

_register(Tool(
    name="xsstrike", binary="xsstrike", category="exploit", intensity="intrusive",
    description="Advanced XSS detection/fuzzing (WAF-aware) on a URL with a parameter. Option: param_url.",
    build=lambda host, o: ["xsstrike", "-u", _require_param_url(host, o), "--skip-dom"],
    needs_scheme=True,
))


def _require_param_url(host: str, o: dict) -> str:
    url = _clean(o.get("param_url", ""))
    if "?" not in url or "=" not in url:
        raise ValueError("sqlmap requires a param_url containing a query parameter, e.g. https://host/p?id=1")
    return url


def _cphunter_bin() -> str | None:
    """Return cphunter.py path if CPHunter is installed."""
    if _settings.cphunter_dir:
        from pathlib import Path
        p = Path(_settings.cphunter_dir) / "cphunter.py"
        if p.is_file():
            return str(p)
    return None


_CPH_MODULES = {
    "java4shell":  ("CVE-2026-114938", "CVE-2026-114938 — OpenJDK AVX-512 Base64 heap overflow (critical). Targets Keycloak/Jenkins/Confluence/Spring/Tomcat/Elasticsearch."),
    "nginx2root":  ("CVE-2026-123007", "CVE-2026-123007 — nginx HTTP/2 flow-control integer underflow → RCE (critical). Targets nginx 1.9.5–1.30.6 / 1.31.0–1.31.8 with h2."),
    "sshole":      ("CVE-2026-123158", "CVE-2026-123158 — OpenSSH musl crypt() auth bypass (high). Targets Alpine/musl-based OpenSSH < 10.6p2."),
}

for _mod_id, (_cve_id, _mod_desc) in _CPH_MODULES.items():
    _register(Tool(
        name=f"cphunter_{_mod_id}",
        binary=_settings.cphunter_python if _settings.cphunter_python else "python3",
        category="exploit",
        intensity="active",
        description=f"CPHunter {_mod_desc} Option: port (target port).",
        build=(lambda cve: lambda host, o: [
            _settings.cphunter_python or "python3",
            _cphunter_bin() or "cphunter.py",
            host, "--scan", "--cve-vuln",
            "--cve-filter", cve,
            "--cve-vuln-timeout", str(_settings.cphunter_timeout),
        ])(str(_cve_id)),
    ))


def installed_tools() -> dict[str, bool]:
    return {name: tool.installed for name, tool in REGISTRY.items()}
