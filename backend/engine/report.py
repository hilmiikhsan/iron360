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


def _fmt(s: str) -> str:
    """Format plain text into readable HTML: split numbered lists and semicolons into lines."""
    import re
    if not s:
        return "—"
    t = html.escape(str(s))
    t = re.sub(r'(\d+)\)\s+', r'\n\1) ', t)
    t = re.sub(r'(\d+)\.\s+', r'\n\1. ', t)
    t = re.sub(r';\s+', ';\n', t)
    t = re.sub(r'\n{3,}', '\n\n', t)
    lines = [l.strip() for l in t.split('\n') if l.strip()]
    if len(lines) <= 1:
        return t.strip()
    parts = []
    for l in lines:
        if re.match(r'^\d+[\.\)]', l):
            parts.append(f'<div style="padding:2px 0 2px 12px;border-left:3px solid #cbd5e1;margin:4px 0">{l}</div>')
        else:
            parts.append(f'<div style="margin:3px 0">{l}</div>')
    return ''.join(parts)


def executive_summary(target: Target, findings: list[Finding]) -> str:
    counts = {s: sum(1 for f in findings if f.severity == s) for s in _SEV_ORDER}
    confirmed = sum(1 for f in findings if f.status == "confirmed")
    if settings.ai_live:
        try:
            from . import llm
            client = llm.make_client()
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
        fix += f'<div class="fixlabel">Langkah penerapan &amp; verifikasi</div><div class="steps-block">{_fmt(f.fix_steps)}</div>'
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
        {'<tr><th>CVSS v3.1</th><td><b>'+str(f.cvss_score)+'</b> · '+_esc(f.cvss_vector or '')+'</td></tr>' if f.cvss_score else ''}
        {'<tr><th>CWE</th><td>'+_esc(f.cwe)+'</td></tr>' if f.cwe else ''}
        <tr><th>Sumber korelasi</th><td>{_esc(', '.join(f.sources or []) or '—')}</td></tr>
        {'<tr><th>Referensi</th><td>'+'<br>'.join('<a href="'+_esc(r)+'">'+_esc(r)+'</a>' for r in (f.references or []))+'</td></tr>' if f.references else ''}
      </table>
      <div class="flabel">Deskripsi</div><div style="font-size:13.5px;line-height:1.6">{_fmt(f.description)}</div>
      <div class="flabel">Bukti / PoC</div><pre class="evidence">{_esc(f.evidence) or '(tidak ada)'}</pre>
      <div class="flabel">Rekomendasi</div><div style="font-size:13.5px;line-height:1.6">{_fmt(f.remediation)}</div>
      {fix}
    </div>"""


def _intel_html(intel: dict | None) -> str:
    if not intel:
        return ""
    html_parts = []
    cves = intel.get("cve") or []
    if cves:
        rows = "".join(
            f"<tr><td><a href='{_esc(c.get('url',''))}'>{_esc(c.get('cve',''))}</a></td>"
            f"<td>{_esc(str(c.get('cvss') or '—'))}</td><td>{_esc(c.get('severity') or '—')}</td>"
            f"<td>{_esc((c.get('summary') or '')[:200])}</td></tr>" for c in cves)
        html_parts.append(
            '<h2 class="sec">Intelijen CVE (NVD)</h2><table class="info"><tr><th>CVE</th><th>CVSS</th>'
            f'<th>Severity</th><th>Ringkasan</th></tr>{rows}</table>')
    owasp = intel.get("owasp") or []
    if owasp:
        rows = "".join(
            f"<tr><td><b>{_esc(m.get('id',''))}</b></td><td>{_esc(m.get('name',''))}</td>"
            f"<td>{_esc(m.get('method',''))}</td>"
            f"<td style='text-align:center'>{'<b style=\"color:#dc2626\">'+str(m.get('findings'))+'</b>' if m.get('findings') else '—'}</td></tr>"
            for m in owasp)
        html_parts.append(
            '<h2 class="sec">Cakupan OWASP Top 10 (2021)</h2><p class="muted">Metode pengujian yang dijalankan '
            f'Iron360 untuk tiap kategori + jumlah temuan.</p><table class="info"><tr><th>ID</th><th>Kategori</th>'
            f'<th>Metode uji</th><th>Temuan</th></tr>{rows}</table>')
    comp = intel.get("compliance") or []
    if comp:
        rows = "".join(
            f"<tr><td>{_esc(c.get('control',''))}</td><td>{_esc(c.get('title',''))}</td>"
            f"<td style='color:{'#047857' if c.get('result')=='pass' else '#dc2626'};font-weight:700'>"
            f"{_esc((c.get('result') or '').upper())}</td></tr>" for c in comp)
        passed = sum(1 for c in comp if c.get("result") == "pass")
        html_parts.append(
            f'<h2 class="sec">Kepatuhan CIS Benchmark</h2><p class="muted">{passed}/{len(comp)} kontrol lulus '
            f'(credentialed).</p><table class="info"><tr><th>Kontrol</th><th>Deskripsi</th><th>Hasil</th></tr>{rows}</table>')
    exps = intel.get("exploit-db") or []
    if exps:
        rows = "".join(
            f"<tr><td><a href='{_esc(e.get('url',''))}'>{_esc(e.get('description',''))}</a></td>"
            f"<td>{_esc(e.get('type',''))}/{_esc(e.get('platform',''))}</td><td>{_esc(e.get('date',''))}</td></tr>"
            for e in exps)
        html_parts.append(
            '<h2 class="sec">Korelasi Exploit-DB</h2><p class="muted">Exploit publik yang cocok dengan versi '
            f'service yang terdeteksi.</p><table class="info"><tr><th>Exploit</th><th>Tipe/Platform</th>'
            f'<th>Tanggal</th></tr>{rows}</table>')
    return "".join(html_parts)


def build_report_html(target: Target, findings: list[Finding], summary: str, intel: dict | None = None) -> str:
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
 .toolbar {{ position: sticky; top:0; background:#0f172a; padding:10px 14px; display:flex; gap:10px; z-index:10; }}
 .toolbar button {{ background:#0ea5e9; color:#042; border:none; border-radius:7px; padding:8px 14px; font-weight:700; cursor:pointer; }}
 .toolbar button.sec {{ background:#334155; color:#e2e8f0; }}
 table.info {{ width:100%; border-collapse:collapse; margin:20px 0; font-size:13.5px; }}
 table.info th {{ text-align:left; width:180px; color:#64748b; font-weight:600; padding:6px 0; vertical-align:top; }}
 table.info td {{ padding:6px 0; }}
 .chips {{ display:flex; gap:10px; flex-wrap:wrap; margin:16px 0; }}
 .chip {{ border:2px solid; border-radius:10px; padding:8px 14px; font-size:12px; text-transform:uppercase; letter-spacing:.5px; }}
 .chip b {{ font-size:18px; display:block; }}
 h2.sec {{ font-size:16px; border-left:4px solid #0ea5e9; padding-left:10px; margin:34px 0 12px; }}
 .finding {{ border:1px solid #e2e8f0; border-radius:12px; padding:20px; margin:20px 0; }}
 .fhead {{ display:flex; align-items:center; gap:10px; flex-wrap:wrap; }}
 .fhead h3 {{ font-size:15px; margin:0; flex:1; min-width:200px; }}
 .sev {{ color:#fff; font-size:11px; font-weight:800; padding:3px 9px; border-radius:6px; flex:none; }}
 .status {{ font-size:11px; padding:3px 9px; border-radius:999px; border:1px solid #cbd5e1; color:#475569; flex:none; }}
 .status-confirmed {{ border-color:#10b981; color:#047857; }}
 .status-false_positive {{ text-decoration: line-through; color:#94a3b8; }}
 table.meta {{ width:100%; border-collapse:collapse; margin:12px 0; font-size:13px; }}
 table.meta th {{ text-align:left; width:140px; color:#64748b; font-weight:600; padding:5px 0; vertical-align:top; }}
 table.meta td {{ padding:5px 0; }}
 .flabel, .fixlabel {{ font-size:11px; text-transform:uppercase; letter-spacing:.6px; color:#64748b; margin:16px 0 6px; font-weight:700; }}
 .fixlabel {{ color:#047857; }}
 pre {{ background:#0f172a; color:#e2e8f0; padding:14px 16px; border-radius:8px; font-size:12px; overflow:auto; white-space:pre-wrap; word-break:break-word; font-family: ui-monospace, Menlo, Consolas, monospace; line-height:1.6; }}
 pre.fix {{ background:#042f2e; }}
 pre.steps {{ background:#1e293b; }}
 pre.evidence {{ background:#1e1b4b; }}
 p {{ font-size:13.5px; line-height:1.7; }}
 .muted {{ color:#94a3b8; }}
 .foot {{ margin-top:40px; border-top:1px solid #e2e8f0; padding-top:14px; color:#94a3b8; font-size:12px; }}
 .steps-block {{ background:#f8fafc; border:1px solid #e2e8f0; border-radius:8px; padding:14px 16px; font-size:12.5px; line-height:1.7; font-family: ui-monospace, Menlo, Consolas, monospace; }}

 @media print {{
   body {{ background:#fff !important; -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
   .toolbar {{ display:none !important; }}
   .page {{ max-width:none; padding:0; margin:0; box-shadow:none; }}
   .brand {{ border-bottom:3px solid #0ea5e9; }}
   .finding {{ page-break-inside: avoid; border:1px solid #cbd5e1; margin:14px 0; padding:16px; }}
   .fhead {{ flex-wrap: wrap; }}
   h2.sec {{ page-break-after: avoid; }}
   pre {{ background:#f1f5f9 !important; color:#0f172a !important; border:1px solid #cbd5e1; font-size:11px; padding:10px 12px; }}
   pre.fix {{ background:#ecfdf5 !important; border-color:#a7f3d0; }}
   pre.evidence {{ background:#eef2ff !important; border-color:#c7d2fe; }}
   .steps-block {{ background:#f8fafc !important; border:1px solid #cbd5e1; page-break-inside: avoid; }}
   .sev {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
   .chip {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
   .chips {{ page-break-inside: avoid; }}
   table.info, table.meta {{ page-break-inside: avoid; }}
   a {{ color:#0ea5e9; text-decoration:none; }}
   .foot {{ page-break-before: avoid; }}
 }}
</style>
<script>
 (function() {{
   var inFrame = false;
   try {{ inFrame = window.self !== window.top || window.frameElement; }} catch(e) {{ inFrame = true; }}
   if (inFrame) {{
     var s = document.createElement('style');
     s.textContent = '.toolbar {{ display:none !important; }}';
     document.head.appendChild(s);
   }}
 }})();
</script>
</head><body>
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

 {_intel_html(intel)}

 <div class="foot">Dokumen ini bersifat rahasia dan ditujukan untuk {_esc(target.engagement) or 'klien'} dalam
   kerangka engagement resmi RSA. Seluruh pengujian dilakukan dalam lingkup yang diautorisasi. Validasi akhir
   atas setiap temuan dilakukan oleh pentester RSA. Dihasilkan oleh Iron360 ({engine}).</div>
</div></body></html>"""
