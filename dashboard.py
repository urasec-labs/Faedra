#!/usr/bin/env python3
"""
Faedra Pro - Simple Web Dashboard
Author: Uras AKAS | urasakas.com

Serves HTML/PDF/JSON reports and a live index of past scans.
No external web framework required (stdlib only).
"""

from __future__ import annotations
import json
import mimetypes
import re
from datetime import datetime
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, unquote

REPORTS_DIR = Path("data/reports")
ASSETS_DIR = Path("data/assets")
HOST = "127.0.0.1"
PORT = 8787


def list_reports():
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    items = []
    for p in sorted(REPORTS_DIR.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True):
        if p.suffix.lower() not in (".html", ".json", ".pdf"):
            continue
        stat = p.stat()
        items.append({
            "name": p.name,
            "path": str(p),
            "type": p.suffix.lower().lstrip("."),
            "size": stat.st_size,
            "mtime": datetime.fromtimestamp(stat.st_mtime).isoformat(timespec="seconds"),
        })
    return items


def list_inventories():
    ASSETS_DIR.mkdir(parents=True, exist_ok=True)
    items = []
    for p in sorted(ASSETS_DIR.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True):
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            items.append({
                "name": p.name,
                "target": data.get("target", p.stem),
                "assets": len(data.get("assets", [])),
                "updated_at": data.get("updated_at", ""),
            })
        except Exception:
            continue
    return items


def render_index() -> bytes:
    reports = list_reports()
    inventories = list_inventories()

    report_rows = []
    for r in reports[:100]:
        link = f"/reports/{r['name']}"
        report_rows.append(
            f"<tr>"
            f"<td><a href='{link}' target='_blank'>{r['name']}</a></td>"
            f"<td><span class='tag'>{r['type'].upper()}</span></td>"
            f"<td class='muted'>{r['mtime']}</td>"
            f"<td class='muted'>{r['size'] // 1024} KB</td>"
            f"</tr>"
        )

    inv_rows = []
    for inv in inventories[:50]:
        inv_rows.append(
            f"<tr>"
            f"<td>{inv['target']}</td>"
            f"<td>{inv['assets']}</td>"
            f"<td class='muted'>{inv['updated_at']}</td>"
            f"<td class='muted'>{inv['name']}</td>"
            f"</tr>"
        )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Faedra Pro Dashboard</title>
<style>
  :root {{ --bg:#0b0d12; --panel:#12151c; --border:#1e2430; --text:#e8eaed; --muted:#8b93a7; --accent:#6c5ce7; }}
  * {{ box-sizing:border-box; margin:0; padding:0; }}
  body {{ font-family:"Segoe UI",system-ui,sans-serif; background:var(--bg); color:var(--text); line-height:1.5; padding:2rem; }}
  .wrap {{ max-width:1100px; margin:0 auto; }}
  header {{ margin-bottom:1.75rem; }}
  h1 {{ font-size:1.7rem; }} h1 span {{ color:var(--accent); }}
  .sub {{ color:var(--muted); margin-top:0.35rem; }}
  section {{ background:var(--panel); border:1px solid var(--border); border-radius:12px; padding:1.25rem 1.5rem; margin-bottom:1.25rem; }}
  h2 {{ font-size:1rem; margin-bottom:0.9rem; color:#c5c9d4; border-bottom:1px solid var(--border); padding-bottom:0.45rem; }}
  table {{ width:100%; border-collapse:collapse; font-size:0.88rem; }}
  th,td {{ text-align:left; padding:0.5rem 0.6rem; border-bottom:1px solid var(--border); }}
  th {{ color:var(--muted); font-size:0.75rem; text-transform:uppercase; letter-spacing:0.04em; }}
  a {{ color:#a78bfa; text-decoration:none; }} a:hover {{ text-decoration:underline; }}
  .muted {{ color:var(--muted); }}
  .tag {{ display:inline-block; background:#1e2430; border:1px solid #2a3344; padding:0.1rem 0.45rem; border-radius:4px; font-size:0.7rem; font-weight:600; }}
  .stats {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(140px,1fr)); gap:0.75rem; margin-bottom:0.5rem; }}
  .stat {{ background:#0e1118; border:1px solid var(--border); border-radius:8px; padding:0.85rem 1rem; }}
  .stat .n {{ font-size:1.35rem; font-weight:700; }} .stat .l {{ color:var(--muted); font-size:0.75rem; }}
  footer {{ text-align:center; color:var(--muted); font-size:0.8rem; margin-top:1.5rem; }}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1><span>FAEDRA</span> PRO Dashboard</h1>
    <div class="sub">Author: Uras AKAS | urasakas.com · Local reports &amp; inventory</div>
  </header>

  <section>
    <div class="stats">
      <div class="stat"><div class="n">{len(reports)}</div><div class="l">Reports</div></div>
      <div class="stat"><div class="n">{len(inventories)}</div><div class="l">Inventories</div></div>
      <div class="stat"><div class="n">{sum(1 for r in reports if r['type']=='html')}</div><div class="l">HTML</div></div>
      <div class="stat"><div class="n">{sum(1 for r in reports if r['type']=='pdf')}</div><div class="l">PDF</div></div>
    </div>
  </section>

  <section>
    <h2>Reports</h2>
    <table>
      <thead><tr><th>File</th><th>Type</th><th>Modified</th><th>Size</th></tr></thead>
      <tbody>
        {''.join(report_rows) or '<tr><td colspan="4" class="muted">No reports yet. Run a scan first.</td></tr>'}
      </tbody>
    </table>
  </section>

  <section>
    <h2>Asset Inventories</h2>
    <table>
      <thead><tr><th>Target</th><th>Assets</th><th>Updated</th><th>File</th></tr></thead>
      <tbody>
        {''.join(inv_rows) or '<tr><td colspan="4" class="muted">No inventories yet.</td></tr>'}
      </tbody>
    </table>
  </section>

  <footer>
    Faedra Pro · Authorized use only · Bound to {HOST}:{PORT}
  </footer>
</div>
</body>
</html>
"""
    return html.encode("utf-8")


class Handler(SimpleHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print(f"[dashboard] {self.address_string()} — {fmt % args}")

    def do_GET(self):
        parsed = urlparse(self.path)
        path = unquote(parsed.path)

        if path in ("/", "/index.html"):
            body = render_index()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if path.startswith("/reports/"):
            name = path[len("/reports/"):]
            # path traversal guard
            if ".." in name or name.startswith("/"):
                self.send_error(400, "Bad request")
                return
            file_path = REPORTS_DIR / name
            if not file_path.exists() or not file_path.is_file():
                self.send_error(404, "Not found")
                return
            data = file_path.read_bytes()
            ctype = mimetypes.guess_type(str(file_path))[0] or "application/octet-stream"
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return

        if path == "/api/reports":
            body = json.dumps(list_reports(), indent=2).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        self.send_error(404, "Not found")


def main():
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    ASSETS_DIR.mkdir(parents=True, exist_ok=True)
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"Faedra Pro Dashboard")
    print(f"Author : Uras AKAS | urasakas.com")
    print(f"URL    : http://{HOST}:{PORT}")
    print(f"Reports: {REPORTS_DIR.resolve()}")
    print("Press Ctrl+C to stop\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nDashboard stopped.")
        server.server_close()


if __name__ == "__main__":
    main()
