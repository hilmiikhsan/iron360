"""Knowledge base for Iron360.

Retrieval layer that makes the AI "trained" on the references the user supplied —
NOT by retraining weights, but by RAG + methodology playbooks. Ships the full
reference set from the project brief (web techniques, payloads, pentest-agent
frameworks, AD, recon, commercial scanners) plus the operator's local resources.

`retrieve()` keyword-matches and returns the most relevant references to inject
into the agent's context for a given task. A later iteration can swap the backing
store for an embedding index over the ingested ebooks/repos without changing this
interface.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict


@dataclass
class Reference:
    name: str
    url: str
    category: str      # payloads|methodology|recon|exploit|agent-framework|ad|scanner|local|apk
    tags: list[str]
    note: str


REFERENCES: list[Reference] = [
    # ---- core web methodology / payloads ----
    Reference("PayloadsAllTheThings", "https://github.com/swisskyrepo/PayloadsAllTheThings",
              "payloads", ["sqli", "xss", "ssrf", "lfi", "rce", "xxe", "bypass", "jwt", "upload"],
              "Primary payload/bypass source for every web injection class."),
    Reference("HackTricks", "https://hacktricks.wiki/en/index.html",
              "methodology", ["pentest", "privesc", "web", "network", "ad", "cloud", "enumeration"],
              "End-to-end pentest methodology and technique index."),
    Reference("PortSwigger Web Security Academy", "https://portswigger.net/web-security",
              "methodology", ["xss", "sqli", "ssrf", "auth", "access-control", "deserialization", "jwt"],
              "Authoritative web-vuln explanations, labs, and exploitation detail."),
    Reference("OWASP Top 10", "https://owasp.org/www-project-top-ten/",
              "methodology", ["owasp", "top10", "web", "classification"],
              "Baseline web risk taxonomy for VA classification."),
    Reference("OWASP WSTG", "https://owasp.org/www-project-web-security-testing-guide/",
              "methodology", ["owasp", "testing", "wstg", "checklist"],
              "Web Security Testing Guide — structured, repeatable test cases."),
    Reference("Exploit-DB", "https://www.exploit-db.com/",
              "exploit", ["exploit", "cve", "poc"],
              "Public exploit/PoC lookup by product/version."),
    Reference("bug-bounty-writeups (x1337loser)", "https://github.com/x1337loser/bug-bounty-writeup",
              "methodology", ["bugbounty", "writeups", "chaining"],
              "Real-world bug chains and exploitation narratives."),
    Reference("SQL-Wordlist (orwagodfather)", "https://github.com/orwagodfather/SQL-Wordlist",
              "payloads", ["sqli", "wordlist", "fuzz"],
              "SQLi payload wordlist for parameter fuzzing."),
    Reference("FuzzyAI (CyberArk)", "https://github.com/cyberark/FuzzyAI",
              "payloads", ["llm", "fuzzing", "ai", "jailbreak"],
              "Fuzzing framework for finding weaknesses in AI/LLM-backed apps."),

    # ---- AI / pentest-agent frameworks (design references for Iron360's own agent) ----
    Reference("AI-VAPT (vikramrajkumarmajji)", "https://github.com/vikramrajkumarmajji/AI-VAPT",
              "agent-framework", ["ai", "vapt", "agent"], "AI-driven VAPT orchestration reference."),
    Reference("vapt-agents (cywarriors)", "https://github.com/cywarriors/vapt-agents",
              "agent-framework", ["ai", "vapt", "agent"], "Multi-agent VAPT design patterns."),
    Reference("pentest-agents (H-mmer)", "https://github.com/H-mmer/pentest-agents",
              "agent-framework", ["ai", "agent", "pentest"], "Agent loop / tool-calling patterns for pentest."),
    Reference("sqlmap-skynet", "https://github.com/drcrypterdotru/sqlmap-skynet",
              "agent-framework", ["sqli", "sqlmap", "automation"], "AI-assisted sqlmap automation."),
    Reference("XSSRush (N45HT)", "https://github.com/N45HT/XSSRush",
              "exploit", ["xss", "automation"], "Automated XSS discovery/validation."),
    Reference("PentestGPT (greydgl)", "https://github.com/greydgl/pentestgpt",
              "agent-framework", ["ai", "gpt", "pentest", "guidance"], "LLM-guided penetration testing."),
    Reference("pentagi (vxcontrol)", "https://github.com/vxcontrol/pentagi",
              "agent-framework", ["ai", "autonomous", "agent"], "Autonomous pentest agent architecture."),
    Reference("Strix (usestrix)", "https://github.com/usestrix/strix",
              "agent-framework", ["ai", "agent", "appsec"], "AI AppSec agent reference."),
    Reference("hermes-pentest-lab", "https://github.com/jayelbotvibe-web/hermes-pentest-lab",
              "agent-framework", ["ai", "lab", "pentest"], "Pentest-agent lab reference."),
    Reference("ARTEX (BaaRai)", "https://github.com/BaaRai/ARTEX",
              "agent-framework", ["ai", "redteam", "automation"], "Red-team automation reference."),
    Reference("Cairn (oritera)", "https://github.com/oritera/Cairn",
              "agent-framework", ["ai", "agent"], "Security agent reference."),
    Reference("LazyOwn (grisuno)", "https://github.com/grisuno/LazyOwn",
              "agent-framework", ["c2", "redteam", "automation"], "Red-team framework reference."),
    Reference("hackagent (AISecurityLab)", "https://github.com/AISecurityLab/hackagent",
              "agent-framework", ["ai", "agent"], "AI hacking-agent reference."),
    Reference("claude-pentest-skills (frendysanusi)", "https://github.com/frendysanusi/claude-pentest-skills",
              "agent-framework", ["claude", "skills", "pentest"], "Claude skill definitions for pentest."),
    Reference("claude-code-pentest (Orizon-eu)", "https://github.com/Orizon-eu/claude-code-pentest",
              "agent-framework", ["claude", "pentest", "automation"], "Claude-Code pentest workflow reference."),
    Reference("clawdstrike (backbay-labs)", "https://github.com/backbay-labs/clawdstrike",
              "agent-framework", ["ai", "offensive"], "Offensive AI tooling reference."),
    Reference("AiScan-N (SecNN)", "https://github.com/SecNN/AiScan-N",
              "agent-framework", ["ai", "scanner"], "AI scanning reference."),
    Reference("PentestAgent (0xSojalSec)", "https://github.com/0xSojalSec/PentestAgent",
              "agent-framework", ["ai", "agent", "pentest"], "Pentest agent reference."),
    Reference("pentx-vapt-skill (yashas-13)", "https://github.com/yashas-13/pentx-vapt-skill",
              "agent-framework", ["vapt", "skill"], "VAPT skill reference."),
    Reference("hackers-arise: AI for pentest", "https://hackers-arise.com/artificial-intelligence-ai-in-cybersecurity-part-23-using-pentestcode-for-web-and-network-pentest/",
              "methodology", ["ai", "web", "network"], "Applying AI/pentest-code for web & network pentest."),

    # ---- recon / enumeration ----
    Reference("FinalRecon (thewhiteh4t)", "https://github.com/thewhiteh4t/FinalRecon",
              "recon", ["recon", "osint", "whois", "dns", "headers"], "All-in-one recon technique reference."),
    Reference("OWASP Nettacker", "https://github.com/OWASP/Nettacker",
              "recon", ["recon", "network", "scan"], "Automated network recon/scan methodology."),
    Reference("hakrevdns (hakluke)", "https://github.com/hakluke/hakrevdns",
              "recon", ["reverse-dns", "ptr", "recon"], "Reverse DNS lookup for IP ranges."),
    Reference("subdog (rix4uni)", "https://github.com/rix4uni/subdog",
              "recon", ["subdomain", "enumeration"], "Subdomain enumeration aggregator."),
    Reference("Barcha (S1N6H)", "https://github.com/S1N6H/Barcha",
              "recon", ["recon", "automation"], "Recon automation reference."),
    Reference("bundlespy (MustafaSalhaa)", "https://github.com/MustafaSalhaa/bundlespy",
              "recon", ["js", "bundle", "secrets", "endpoints"], "JS bundle analysis for endpoints/secrets."),
    Reference("reconmap", "https://github.com/reconmap/reconmap",
              "recon", ["recon", "workflow", "collaboration"], "Pentest workflow/recon management reference."),
    Reference("Sn1per (1N3)", "https://github.com/1N3/Sn1per",
              "recon", ["recon", "attack-surface", "automation"], "Attack-surface management & recon automation."),
    Reference("offsec-tools (Syslifters)", "https://github.com/Syslifters/offsec-tools",
              "recon", ["toolkit", "offsec"], "Curated offensive-tool collection."),
    Reference("Vmkatz (nikaiw)", "https://github.com/nikaiw/Vmkatz",
              "exploit", ["vmware", "post-exploitation"], "VMware-focused tooling reference."),
    Reference("Reverse-IP mass scan (local revipv4.py)", "file:///Users/hilmiikhsan/Targets/RSA/TOOLS/revipv4.py",
              "recon", ["reverse-ip", "mass-scan", "vhost"], "Operator's reverse-IP mass-scan script (wired as a tool)."),

    # ---- Active Directory ----
    Reference("AD-PathFinder (NetSPI)", "https://github.com/NetSPI/AD-PathFinder",
              "ad", ["activedirectory", "attack-path", "bloodhound"], "AD attack-path analysis."),
    Reference("AD-CS Cheatsheet", "https://app.notion.com/p/AD-CS-Cheatsheet-3cef388271ac806482fad26aff6d2136",
              "ad", ["adcs", "certificates", "esc"], "AD Certificate Services abuse cheatsheet."),
    Reference("DeathStar (byt3bl33d3r)", "https://github.com/byt3bl33d3r/DeathStar",
              "ad", ["activedirectory", "domain-admin", "automation"], "Automated AD domain-admin path reference."),
    Reference("AutoPWN-Suite", "https://github.com/GamehunterKaan/AutoPWN-Suite",
              "exploit", ["auto", "cve", "scan"], "Automated vuln scan/exploit suite reference."),
    Reference("adscan (ADScanPro)", "https://github.com/ADScanPro/adscan",
              "ad", ["activedirectory", "ldap", "kerberos", "enumeration"], "AD attack-surface scanner methodology."),

    # ---- APK / mobile ----
    Reference("rea (morluto) — APK reverse", "https://github.com/morluto/rea",
              "apk", ["android", "apk", "reverse-engineering"], "APK reverse-engineering reference."),

    # ---- commercial scanners (for cross-validation / corroboration) ----
    Reference("Burp Suite / ZAP / Nessus / Acunetix", "https://portswigger.net/burp",
              "scanner", ["burp", "zap", "nessus", "acunetix", "corroboration"],
              "Cross-reference AI findings against commercial scanners to reduce false positives."),

    # ---- operator local resources (ingested as methodology, never committed) ----
    Reference("Local: EBOOK PENTESTER", "file:///Users/hilmiikhsan/Documents/CYBER SECURITY/EBOOK PENTESTER",
              "local", ["enumeration", "recon", "bughunting", "payloads", "zeroday"],
              "Operator's enumeration/recon/bug-hunting + zero-day blackbook cheat sheets."),
    Reference("Local: EBOOK PDF CYSEC", "file:///Users/hilmiikhsan/Documents/CYBER SECURITY/EBOOK PDF CYSEC",
              "local", ["nmap", "ad", "redteam", "kali"],
              "Operator's Nmap + Active Directory + red-team guides."),
    Reference("Local: security-research", "file:///Users/hilmiikhsan/Documents/python/security-research",
              "local", ["agent", "bughunter", "osint"],
              "Operator's own agent/bug-hunter/OSINT scripts (Agentic-Bug-Hunter, Claude-OSINT, etc.)."),
    Reference("Local: TOOLS (AD + Wireless + reverse-IP)", "file:///Users/hilmiikhsan/Targets/RSA/TOOLS",
              "local", ["activedirectory", "wireless", "reverse-ip"],
              "Operator's AD + wireless pentest PDFs and revipv4.py mass-scan script."),
]


def catalog() -> list[dict]:
    return [asdict(r) for r in REFERENCES]


def categories() -> dict[str, int]:
    out: dict[str, int] = {}
    for r in REFERENCES:
        out[r.category] = out.get(r.category, 0) + 1
    return out


def retrieve(query: str, k: int = 8) -> list[Reference]:
    """Lightweight keyword retrieval over the reference registry."""
    terms = {t for t in query.lower().replace(",", " ").split() if len(t) > 2}
    scored: list[tuple[int, Reference]] = []
    for ref in REFERENCES:
        hay = (ref.name + " " + ref.note + " " + " ".join(ref.tags) + " " + ref.category).lower()
        score = sum(1 for t in terms if t in hay)
        score += sum(2 for t in terms if t in ref.tags)
        if score:
            scored.append((score, ref))
    scored.sort(key=lambda x: x[0], reverse=True)
    return [r for _, r in scored[:k]]


def methodology_brief(query: str) -> str:
    """A compact, injectable block of the most relevant references for the agent."""
    refs = retrieve(query, k=8)
    if not refs:
        return ""
    lines = ["Relevant knowledge-base references for this task (apply/adapt their techniques):"]
    for r in refs:
        lines.append(f"- {r.name} [{r.category}]: {r.note} ({', '.join(r.tags[:5])})")
    return "\n".join(lines)
