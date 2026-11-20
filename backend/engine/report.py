"""VAPT report generation.

Builds a self-contained, printable HTML report (RSA-branded) from a target and its
findings — including the concrete, copy-pasteable config fixes. The executive summary
is written by the AI in LIVE mode, or templated in SIMULATION mode. The report page
has a Print button (browser → Save as PDF), so no server-side Chrome is required.
"""
from __future__ import annotations

import datetime as dt
import html

from ..config import get_settings
from ..models import Finding, Target

settings = get_settings()

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_SEV_COLOR = {"critical": "#dc2626", "high": "#ea580c", "medium": "#d97706", "low": "#2563eb", "info": "#64748b"}


def _esc(s: str) -> str:
    return html.escape(str(s or ""))


def executive_summary(target: Target, findings: list[Finding]) -> str:
    counts = {s: sum(1 for f in findings if f.severity == s) for s in _SEV_ORDER}
    confirmed = sum(1 for f in findings if f.status == "confirmed")
    if settings.ai_live:
        try:
            import anthropic
            client = anthropic.Anthropic(api_key=settings.anthropic_api_key)
            facts = "\n".join(
                f"- [{f.severity}/{f.status}] {f.title} (conf {f.confidence}%) @ {f.affected}" for f in findings
            ) or "- No findings."
            resp = client.messages.create(
                model=settings.ai_model, max_tokens=900,
                system="You are a senior RSA penetration tester writing the executive summary of a VAPT report "
                       "for a client's management. Be factual, concise, risk-focused, in professional Indonesian. "
                       "No markdown, 2-3 short paragraphs.",
                thinking={"type": "adaptive"},
                messages=[{"role": "user", "content":
                           f"Target: {target.label} ({target.value}), engagement: {target.engagement}.\n"
                           f"Findings:\n{facts}\n\nWrite the executive summary."}],
            )
            txt = "".join(b.text for b in resp.content if getattr(b, "type", "") == "text").strip()
            if txt:
                return txt
        except Exception:
            pass
    # Templated fallback.
    return (
        f"Penilaian keamanan (VAPT) dilakukan terhadap {target.label} ({target.value}) dalam lingkup engagement "
        f"{target.engagement or 'internal'}, menggunakan metodologi OWASP WSTG dan NIST SP 800-115. "
        f"Pengujian mengidentifikasi {len(findings)} temuan, di antaranya {counts['critical']} Critical, "
        f"{counts['high']} High, dan {counts['medium']} Medium; {confirmed} di antaranya telah tervalidasi (confirmed) "
        f"dengan bukti/PoC yang dapat direproduksi. "
        f"Temuan dengan severity tertinggi disarankan untuk segera ditindaklanjuti sesuai konfigurasi perbaikan "
        f"konkret yang disertakan pada tiap temuan. Validasi akhir dilakukan oleh tim pentester RSA."
    )


def _finding_block(f: Finding, idx: int) -> str:
    color = _SEV_COLOR.get(f.severity, "#64748b")
    fix = ""
    if f.fix_config:
        fix += f'<div class="fixlabel">Konfigurasi perbaikan (siap pakai)</div><pre class="fix">{_esc(f.fix_config)}</pre>'
    if f.fix_steps:
        fix += f'<div class="fixlabel">Langkah penerapan &amp; verifikasi</div><pre class="steps">{_esc(f.fix_steps)}</pre>'
    return f"""
    <div class="finding">
      <div class="fhead">
        <span class="sev" style="background:{color}">{_esc(f.severity.upper())}</span>
        <h3>{idx}. {_esc(f.title)}</h3>
        <span class="status status-{_esc(f.status)}">{_esc(f.status.replace('_',' '))} · {f.confidence}%</span>
      </div>
      <table class="meta">
        <tr><th>Affected</th><td>{_esc(f.affected) or '—'}</td></tr>
        {'<tr><th>CVE</th><td>'+_esc(f.cve)+'</td></tr>' if f.cve else ''}
        <tr><th>Sumber korelasi</th><td>{_esc(', '.join(f.sources or []) or '—')}</td></tr>
      </table>
      <div class="flabel">Deskripsi</div><p>{_esc(f.description) or '—'}</p>
      <div class="flabel">Bukti / PoC</div><pre class="evidence">{_esc(f.evidence) or '(tidak ada)'}</pre>
      <div class="flabel">Rekomendasi</div><p>{_esc(f.remediation) or '—'}</p>
      {fix}
    </div>"""


def build_report_html(target: Target, findings: list[Finding], summary: str) -> str:
    findings = sorted(findings, key=lambda f: (_SEV_ORDER.get(f.severity, 9), -f.confidence))
    counts = {s: sum(1 for f in findings if f.severity == s) for s in _SEV_ORDER}
    today = dt.date.today().strftime("%d %B %Y")
    chips = "".join(
        f'<div class="chip" style="border-color:{_SEV_COLOR[s]}"><b style="color:{_SEV_COLOR[s]}">{counts[s]}</b>{s}</div>'
        for s in _SEV_ORDER
    )
    blocks = "".join(_finding_block(f, i + 1) for i, f in enumerate(findings)) or '<p class="muted">Tidak ada temuan.</p>'
    engine = "AI LIVE" if settings.ai_live else "SIMULATION"

    return f"""<!doctype html><html lang="id"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Laporan VAPT — {_esc(target.label)}</title>
<style>
 * {{ box-sizing: border-box; }}
 body {{ font-family: -apple-system, 'Segoe UI', Roboto, Arial, sans-serif; color:#0f172a; margin:0; background:#f1f5f9; }}
 .page {{ max-width: 900px; margin: 0 auto; background:#fff; padding: 48px 56px; }}
 .brand {{ display:flex; align-items:center; gap:12px; border-bottom:3px solid #0ea5e9; padding-bottom:16px; }}
 .logo {{ width:40px;height:40px;border-radius:9px;background:linear-gradient(135deg,#38bdf8,#6366f1);color:#fff;font-weight:800;display:grid;place-items:center;font-size:18px; }}
 h1 {{ font-size: 22px; margin: 2px 0; }}
 .sub {{ color:#64748b; font-size: 13px; }}
 .toolbar {{ position: sticky; top:0; background:#0f172a; padding:10px 14px; display:flex; gap:10px; }}
 .toolbar button {{ background:#0ea5e9; color:#042; border:none; border-radius:7px; padding:8px 14px; font-weight:700; cursor:pointer; }}
 .toolbar button.sec {{ background:#334155; color:#e2e8f0; }}
 table.info {{ width:100%; border-collapse:collapse; margin:20px 0; font-size:13.5px; }}
 table.info th {{ text-align:left; width:180px; color:#64748b; font-weight:600; padding:6px 0; vertical-align:top; }}
 .chips {{ display:flex; gap:10px; flex-wrap:wrap; margin:16px 0; }}
 .chip {{ border:2px solid; border-radius:10px; padding:8px 14px; font-size:12px; text-transform:uppercase; letter-spacing:.5px; }}
 .chip b {{ font-size:18px; display:block; }}
 h2.sec {{ font-size:16px; border-left:4px solid #0ea5e9; padding-left:10px; margin:34px 0 12px; }}
 .finding {{ border:1px solid #e2e8f0; border-radius:12px; padding:18px; margin:16px 0; page-break-inside: avoid; }}
 .fhead {{ display:flex; align-items:center; gap:10px; }}
 .fhead h3 {{ font-size:15px; margin:0; flex:1; }}
 .sev {{ color:#fff; font-size:11px; font-weight:800; padding:3px 9px; border-radius:6px; }}
 .status {{ font-size:11px; padding:3px 9px; border-radius:999px; border:1px solid #cbd5e1; color:#475569; }}
 .status-confirmed {{ border-color:#10b981; color:#047857; }}
 .status-false_positive {{ text-decoration: line-through; color:#94a3b8; }}
 table.meta {{ width:100%; border-collapse:collapse; margin:10px 0; font-size:13px; }}
 table.meta th {{ text-align:left; width:140px; color:#64748b; font-weight:600; padding:3px 0; }}
 .flabel, .fixlabel {{ font-size:11px; text-transform:uppercase; letter-spacing:.6px; color:#64748b; margin:12px 0 4px; font-weight:700; }}
 .fixlabel {{ color:#047857; }}
 pre {{ background:#0f172a; color:#e2e8f0; padding:12px 14px; border-radius:8px; font-size:12px; overflow:auto; white-space:pre-wrap; word-break:break-word; font-family: ui-monospace, Menlo, Consolas, monospace; }}
 pre.fix {{ background:#042f2e; }}
 pre.steps {{ background:#1e293b; }}
 pre.evidence {{ background:#1e1b4b; }}
 p {{ font-size:13.5px; line-height:1.6; }}
 .muted {{ color:#94a3b8; }}
 .foot {{ margin-top:40px; border-top:1px solid #e2e8f0; padding-top:14px; color:#94a3b8; font-size:12px; }}
 @media print {{ .toolbar {{ display:none; }} body {{ background:#fff; }} .page {{ padding:0; }} }}
</style></head><body>
<div class="toolbar"><button onclick="window.print()">⎙ Print / Save PDF</button>
  <button class="sec" onclick="window.close()">Close</button>
  <span style="color:#64748b;align-self:center;font-size:12px">Engine: {engine}</span></div>
<div class="page">
 <div class="brand"><div class="logo">I</div><div><h1>Laporan Vulnerability Assessment &amp; Penetration Testing</h1>
   <div class="sub">Iron360 · RSA Offensive Security · {today}</div></div></div>

 <table class="info">
   <tr><th>Target</th><td><b>{_esc(target.value)}</b> ({_esc(target.label)})</td></tr>
   <tr><th>Engagement / Klien</th><td>{_esc(target.engagement) or '—'}</td></tr>
   <tr><th>Otorisasi</th><td>{'✔ ' + _esc(target.authorization_ref) if target.authorized else 'Belum diautorisasi'}</td></tr>
   <tr><th>Lingkup (scope)</th><td>{_esc(', '.join([target.value] + (target.scope_extra or [])))}</td></tr>
   <tr><th>Metodologi</th><td>OWASP WSTG · NIST SP 800-115</td></tr>
 </table>

 <h2 class="sec">Ringkasan Eksekutif</h2>
 <p>{_esc(summary).replace(chr(10), '</p><p>')}</p>
 <div class="chips">{chips}</div>

 <h2 class="sec">Temuan Rinci</h2>
 {blocks}

 <div class="foot">Dokumen ini bersifat rahasia dan ditujukan untuk {_esc(target.engagement) or 'klien'} dalam
   kerangka engagement resmi RSA. Seluruh pengujian dilakukan dalam lingkup yang diautorisasi. Validasi akhir
   atas setiap temuan dilakukan oleh pentester RSA. Dihasilkan oleh Iron360 ({engine}).</div>
</div></body></html>"""
