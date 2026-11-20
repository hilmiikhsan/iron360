# Iron360 — VAPT AI Console

AI-assisted Vulnerability Assessment & Penetration Testing console for RSA.
This is the **VAPT AI** module (the first of several planned: Threat Intel, Dark Web
Crawling, Domain Health, SIEM Log).

> **Authorized use only.** Iron360 is for lab practice (TryHackMe/HTB) and NDA/SOW-bound
> client engagements. Every assessment is scoped to a single authorized target; the
> executor refuses any host outside the engagement scope.

## Architecture

```
Browser SPA (frontend/)
   │  REST + WebSocket (JWT auth)
   ▼
FastAPI (backend/)
   ├─ routers/        auth, targets, scans, findings, audit, meta
   ├─ engine/
   │    ├─ scope.py         ← scope enforcement (the core safety invariant)
   │    ├─ tools.py         ← tool allowlist (nmap, nuclei, httpx, ffuf, sqlmap…)
   │    ├─ executor.py      ← the ONLY place a tool is spawned (no shell, sanitized argv)
   │    ├─ knowledge.py     ← RAG reference registry (methodology, not retraining)
   │    ├─ orchestrator.py  ← agentic loop: plan → act → observe → decide (+ anti-FP)
   │    └─ runner.py        ← background scan thread + live event bus
   └─ SQLite (data/)
```

**The AI is a co-pilot, not a shell.** The LLM only *requests* allowlisted tools; the
executor validates scope + sanitizes arguments before spawning anything. Findings carry
a confidence score and a validation state (`confirmed / likely / needs_review /
false_positive`) — human validation is always the final gate.

## Run locally

```bash
cd VAPT-AI
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env            # then edit .env (set IRON360_ADMIN_PASSWORD; optional ANTHROPIC_API_KEY)
uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
# open http://127.0.0.1:8000
```

- **No `ANTHROPIC_API_KEY`** → AI engine runs in **SIMULATION** mode (no tokens, demo flow).
- **With a key** → live Claude drives the real executor tools (`IRON360_AI_MODEL`, default `claude-opus-4-8`).

## Security notes

- No credentials are hardcoded. The first admin is seeded once from `IRON360_ADMIN_PASSWORD`,
  then stored only as a PBKDF2-SHA256 hash. Rotate it after first login (Settings).
- JWT secret comes from `IRON360_JWT_SECRET`, or is auto-generated into `data/.jwt_secret` (gitignored).
- `.env`, the local DB, evidence files, and the planning doc are gitignored.
- Security headers + a strict CSP are applied to every response.

## Status

MVP: auth, dynamic target/scope workspaces, agentic VA/Pentest with live streaming,
findings + confidence/validation, knowledge base, audit log. Next: live-mode hardening,
report generation (VAPT template), and the Threat Intel / Dark Web / Domain Health / SIEM modules.
