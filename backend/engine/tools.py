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
    description="Resolve hosts / DNS records (A, CNAME, etc.).",
    build=lambda host, o: ["dnsx", "-silent", "-a", "-resp", "-d", host],
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
                            "-web-server", "-u", host],
))

# ---------------------------------------------------------------- VA
_register(Tool(
    name="nmap", binary="nmap", category="va", intensity="active",
    description="Port/service scan. Options: ports (e.g. '80,443' or 'top1000'), sv (service/version detect).",
    build=lambda host, o: (
        ["nmap", "-Pn", "-T4"]
        + (["-sV"] if o.get("sv") else [])
        + (["-p", _clean(o["ports"])] if o.get("ports") and o["ports"] != "top1000" else ["--top-ports", "1000"])
        + [host]
    ),
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

# ---------------------------------------------------------------- exploit / deep (intrusive)
_register(Tool(
    name="ffuf", binary="ffuf", category="exploit", intensity="intrusive",
    description="Content/endpoint fuzzing. Option: wordlist (absolute path). FUZZ keyword appended to URL path.",
    build=lambda host, o: [
        "ffuf", "-s", "-mc", "200,204,301,302,307,401,403",
        "-w", _clean(o["wordlist"]) if o.get("wordlist") else "/usr/share/wordlists/common.txt",
        "-u", f"{_url(host, o)}/FUZZ",
    ],
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


def _require_param_url(host: str, o: dict) -> str:
    url = _clean(o.get("param_url", ""))
    if "?" not in url or "=" not in url:
        raise ValueError("sqlmap requires a param_url containing a query parameter, e.g. https://host/p?id=1")
    return url


def installed_tools() -> dict[str, bool]:
    return {name: tool.installed for name, tool in REGISTRY.items()}
