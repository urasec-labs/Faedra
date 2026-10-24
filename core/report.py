"""
Faedra Pro - Professional Report Generator (HTML + PDF)
Author: Uras AKAS | urasakas.com
"""

from __future__ import annotations
import html
import json
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from core.models import ScanJob, Finding, Severity


SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
    Severity.UNKNOWN: 5,
}

SEVERITY_COLOR = {
    "critical": "#ff2d55",
    "high": "#ff6b35",
    "medium": "#ffcc00",
    "low": "#5ac8fa",
    "info": "#8e8e93",
    "unknown": "#636366",
}


def generate_html_report(job: ScanJob, output_dir: str | Path = "data/reports") -> Path:
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    safe_target = "".join(c if c.isalnum() or c in "-_." else "_" for c in job.target)[:60]
    path = output_dir / f"faedra_{safe_target}_{ts}.html"

    all_findings: List[Finding] = []
    all_assets = []
    for r in job.results:
        all_findings.extend(r.findings)
        all_assets.extend(r.assets)

    all_findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
    sev_counts = {}
    for f in all_findings:
        sev_counts[f.severity.value] = sev_counts.get(f.severity.value, 0) + 1

    path.write_text(_render_html(job, all_findings, all_assets, sev_counts), encoding="utf-8")
    return path


def generate_pdf_report(job: ScanJob, output_dir: str | Path = "data/reports") -> Optional[Path]:
    """Generate a PDF report. Returns path or None if reportlab unavailable."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, HRFlowable
        )
    except ImportError:
        return None

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    safe_target = "".join(c if c.isalnum() or c in "-_." else "_" for c in job.target)[:60]
    path = output_dir / f"faedra_{safe_target}_{ts}.pdf"

    all_findings: List[Finding] = []
    all_assets = []
    for r in job.results:
        all_findings.extend(r.findings)
        all_assets.extend(r.assets)
    all_findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 99))

    doc = SimpleDocTemplate(
        str(path),
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=16 * mm,
        bottomMargin=16 * mm,
    )
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="CoverTitle", parent=styles["Title"], fontSize=22, spaceAfter=8))
    styles.add(ParagraphStyle(name="Section", parent=styles["Heading2"], fontSize=13, spaceBefore=14, spaceAfter=8))
    styles.add(ParagraphStyle(name="BodySmall", parent=styles["Normal"], fontSize=9, leading=12))
    styles.add(ParagraphStyle(name="Muted", parent=styles["Normal"], fontSize=8, textColor=colors.grey))

    story = []
    story.append(Paragraph("FAEDRA PRO", styles["CoverTitle"]))
    story.append(Paragraph("Professional Security Analysis Report", styles["BodySmall"]))
    story.append(Spacer(1, 6))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#6c5ce7")))
    story.append(Spacer(1, 10))

    meta = [
        f"<b>Target:</b> {job.target}",
        f"<b>Profile:</b> {job.profile}",
        f"<b>Operator:</b> {job.operator}",
        f"<b>Started:</b> {job.started_at}",
        f"<b>Finished:</b> {job.finished_at}",
        f"<b>Modules:</b> {len(job.results)}",
        f"<b>Findings:</b> {len(all_findings)}",
        f"<b>Assets:</b> {len({a.value for a in all_assets})}",
    ]
    for line in meta:
        story.append(Paragraph(line, styles["BodySmall"]))
    story.append(Spacer(1, 12))

    # Severity summary
    sev_counts = {}
    for f in all_findings:
        sev_counts[f.severity.value] = sev_counts.get(f.severity.value, 0) + 1
    story.append(Paragraph("Severity Summary", styles["Section"]))
    sev_data = [["Severity", "Count"]]
    for k in ("critical", "high", "medium", "low", "info"):
        if k in sev_counts:
            sev_data.append([k.upper(), str(sev_counts[k])])
    if len(sev_data) == 1:
        sev_data.append(["—", "0"])
    t = Table(sev_data, colWidths=[120, 60])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e2430")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#333")),
        ("PADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(t)

    # Modules
    story.append(Paragraph("Modules", styles["Section"]))
    mod_data = [["Module", "Status", "Assets", "Findings", "Time"]]
    for r in job.results:
        mod_data.append([
            r.module_name,
            "OK" if r.success else "FAIL",
            str(len(r.assets)),
            str(len(r.findings)),
            f"{r.duration_seconds:.1f}s" if r.duration_seconds else "—",
        ])
    t = Table(mod_data, colWidths=[120, 50, 50, 55, 50])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e2430")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#333")),
        ("PADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(t)

    # Findings
    story.append(Paragraph(f"Findings ({len(all_findings)})", styles["Section"]))
    if not all_findings:
        story.append(Paragraph("No findings recorded.", styles["Muted"]))
    else:
        find_data = [["#", "Sev", "Title", "Asset", "Module"]]
        for i, f in enumerate(all_findings[:80], 1):
            find_data.append([
                str(i),
                f.severity.value.upper()[:4],
                (f.title[:42] + "…") if len(f.title) > 43 else f.title,
                (f.asset[:28] + "…") if len(f.asset) > 29 else f.asset,
                f.module[:14],
            ])
        t = Table(find_data, colWidths=[25, 40, 190, 110, 70])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e2430")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 7.5),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#333")),
            ("PADDING", (0, 0), (-1, -1), 3),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(t)

    story.append(Spacer(1, 16))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.grey))
    story.append(Paragraph(
        "Generated by Faedra Pro — Author: Uras AKAS | urasakas.com — Authorized use only.",
        styles["Muted"],
    ))

    doc.build(story)
    return path


def _esc(s) -> str:
    return html.escape(str(s) if s is not None else "")


def _render_html(job: ScanJob, findings: List[Finding], assets, sev_counts: dict) -> str:
    sev_badges = "".join(
        f'<span class="badge" style="background:{SEVERITY_COLOR.get(k, "#666")}">{_esc(k.upper())}: {v}</span> '
        for k, v in sorted(
            sev_counts.items(),
            key=lambda x: SEVERITY_ORDER.get(Severity(x[0]), 99) if x[0] in [s.value for s in Severity] else 99,
        )
    )

    findings_rows = []
    for i, f in enumerate(findings[:200], 1):
        color = SEVERITY_COLOR.get(f.severity.value, "#666")
        findings_rows.append(f"""
        <tr>
            <td>{i}</td>
            <td><span class="sev" style="background:{color}">{_esc(f.severity.value.upper())}</span></td>
            <td>{_esc(f.title)}</td>
            <td class="muted">{_esc(f.asset)}</td>
            <td class="muted">{_esc(f.module)}</td>
            <td class="desc">{_esc((f.description or "")[:180])}</td>
        </tr>""")

    asset_rows = []
    seen = set()
    for a in assets:
        if a.value in seen:
            continue
        seen.add(a.value)
        alive = "Yes" if a.alive else ("No" if a.alive is False else "—")
        techs = ", ".join(a.technologies[:4]) if a.technologies else "—"
        asset_rows.append(f"""
        <tr>
            <td>{_esc(a.value)}</td>
            <td>{_esc(a.type.value)}</td>
            <td>{alive}</td>
            <td class="muted">{_esc(a.source)}</td>
            <td class="muted">{_esc(techs)}</td>
        </tr>""")

    modules_rows = []
    for r in job.results:
        status = "OK" if r.success else "FAIL"
        status_cls = "ok" if r.success else "fail"
        modules_rows.append(f"""
        <tr>
            <td>{_esc(r.module_name)}</td>
            <td><span class="{status_cls}">{status}</span></td>
            <td>{len(r.assets)}</td>
            <td>{len(r.findings)}</td>
            <td class="muted">{f"{r.duration_seconds:.1f}s" if r.duration_seconds else "—"}</td>
        </tr>""")

    duration = "—"
    if job.started_at and job.finished_at:
        duration = f"{(job.finished_at - job.started_at).total_seconds():.1f}s"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Faedra Pro Report — {_esc(job.target)}</title>
<style>
  :root {{ --bg:#0b0d12; --panel:#12151c; --border:#1e2430; --text:#e8eaed; --muted:#8b93a7; --accent:#6c5ce7; }}
  * {{ box-sizing:border-box; margin:0; padding:0; }}
  body {{ font-family:"Segoe UI",system-ui,sans-serif; background:var(--bg); color:var(--text); line-height:1.5; padding:2rem; }}
  .container {{ max-width:1200px; margin:0 auto; }}
  header {{ border:1px solid var(--border); background:linear-gradient(135deg,#141824,#0f1118); border-radius:12px; padding:1.75rem 2rem; margin-bottom:1.5rem; }}
  h1 {{ font-size:1.6rem; }} h1 span {{ color:var(--accent); }}
  .meta {{ color:var(--muted); margin-top:0.6rem; font-size:0.92rem; }}
  .meta strong {{ color:var(--text); }}
  .badges {{ margin-top:1rem; display:flex; flex-wrap:wrap; gap:0.4rem; }}
  .badge {{ display:inline-block; padding:0.25rem 0.65rem; border-radius:999px; font-size:0.75rem; font-weight:600; color:#111; }}
  section {{ background:var(--panel); border:1px solid var(--border); border-radius:12px; padding:1.25rem 1.5rem; margin-bottom:1.25rem; }}
  h2 {{ font-size:1.05rem; margin-bottom:1rem; padding-bottom:0.5rem; border-bottom:1px solid var(--border); color:#c5c9d4; }}
  table {{ width:100%; border-collapse:collapse; font-size:0.88rem; }}
  th,td {{ text-align:left; padding:0.55rem 0.65rem; border-bottom:1px solid var(--border); vertical-align:top; }}
  th {{ color:var(--muted); font-weight:600; font-size:0.78rem; text-transform:uppercase; letter-spacing:0.04em; }}
  tr:hover td {{ background:rgba(255,255,255,0.02); }}
  .sev {{ display:inline-block; padding:0.15rem 0.45rem; border-radius:4px; font-size:0.7rem; font-weight:700; color:#111; }}
  .muted {{ color:var(--muted); }} .desc {{ max-width:340px; }}
  .ok {{ color:#30d158; font-weight:600; }} .fail {{ color:#ff453a; font-weight:600; }}
  footer {{ text-align:center; color:var(--muted); font-size:0.8rem; margin-top:2rem; padding-top:1rem; }}
  .stat-grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(140px,1fr)); gap:0.75rem; }}
  .stat {{ background:#0e1118; border:1px solid var(--border); border-radius:8px; padding:0.85rem 1rem; }}
  .stat .n {{ font-size:1.4rem; font-weight:700; }} .stat .l {{ color:var(--muted); font-size:0.75rem; margin-top:0.15rem; }}
</style>
</head>
<body>
<div class="container">
  <header>
    <h1><span>FAEDRA</span> PRO — Security Report</h1>
    <div class="meta">
      <strong>Target:</strong> {_esc(job.target)} &nbsp;·&nbsp;
      <strong>Profile:</strong> {_esc(job.profile)} &nbsp;·&nbsp;
      <strong>Operator:</strong> {_esc(job.operator)} &nbsp;·&nbsp;
      <strong>Duration:</strong> {_esc(duration)} &nbsp;·&nbsp;
      <strong>Date:</strong> {_esc(job.finished_at or job.created_at)}
    </div>
    <div class="badges">{sev_badges or '<span class="badge" style="background:#8e8e93">No findings</span>'}</div>
  </header>
  <section>
    <h2>Executive Summary</h2>
    <div class="stat-grid">
      <div class="stat"><div class="n">{len(findings)}</div><div class="l">Findings</div></div>
      <div class="stat"><div class="n">{len(seen)}</div><div class="l">Unique Assets</div></div>
      <div class="stat"><div class="n">{len(job.results)}</div><div class="l">Modules Run</div></div>
      <div class="stat"><div class="n">{sev_counts.get("critical",0)+sev_counts.get("high",0)}</div><div class="l">Critical + High</div></div>
    </div>
  </section>
  <section>
    <h2>Modules</h2>
    <table>
      <thead><tr><th>Module</th><th>Status</th><th>Assets</th><th>Findings</th><th>Time</th></tr></thead>
      <tbody>{''.join(modules_rows) or '<tr><td colspan="5" class="muted">No modules</td></tr>'}</tbody>
    </table>
  </section>
  <section>
    <h2>Findings ({len(findings)})</h2>
    <table>
      <thead><tr><th>#</th><th>Severity</th><th>Title</th><th>Asset</th><th>Module</th><th>Description</th></tr></thead>
      <tbody>{''.join(findings_rows) or '<tr><td colspan="6" class="muted">No findings</td></tr>'}</tbody>
    </table>
  </section>
  <section>
    <h2>Assets ({len(seen)})</h2>
    <table>
      <thead><tr><th>Value</th><th>Type</th><th>Alive</th><th>Source</th><th>Technologies</th></tr></thead>
      <tbody>{''.join(asset_rows) or '<tr><td colspan="5" class="muted">No assets</td></tr>'}</tbody>
    </table>
  </section>
  <footer>
    Generated by <strong>Faedra Pro</strong> — Author: Uras AKAS | urasakas.com<br/>
    Authorized use only. This report is confidential.
  </footer>
</div>
</body>
</html>
"""
