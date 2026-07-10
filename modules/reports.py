#!/usr/bin/env python3
"""Report Generator"""

import json
from datetime import datetime
from pathlib import Path

REPORTS_DIR = Path(__file__).parent.parent / "reports"

def generate_html(db):
    networks = db.get_all_networks()
    creds = db.get_credentials()
    stats = db.get_stats()

    html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>WPS Toolkit Report</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:monospace;background:#0a0a1a;color:#0f0;padding:20px}}
h1{{color:#0ff;text-align:center;margin-bottom:20px}}
h2{{color:#ff0;border-bottom:2px solid #ff0;padding-bottom:5px;margin:20px 0 10px}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin:20px 0}}
.card{{background:#1a1a2e;border:1px solid #333;padding:15px;border-radius:8px;text-align:center}}
.card .n{{font-size:28px;font-weight:bold;color:#0ff}}.card .l{{color:#888;margin-top:4px}}
table{{width:100%;border-collapse:collapse;background:#1a1a2e;margin:10px 0}}
th{{background:#2d1b69;color:#0ff;padding:8px;text-align:left}}
td{{padding:6px 8px;border-bottom:1px solid #222}}
tr:hover{{background:#222}}
.tag{{padding:2px 6px;border-radius:8px;font-size:11px;display:inline-block}}
.g{{background:#0a3d0a;color:#0f0}}.r{{background:#3d0a0a;color:#f44}}
</style></head><body>
<h1>WPS Toolkit - Security Report</h1>
<p>Generated: {datetime.now():%Y-%m-%d %H:%M:%S}</p>
<div class="grid">
<div class="card"><div class="n">{stats["total"]}</div><div class="l">Networks</div></div>
<div class="card"><div class="n">{stats["wps"]}</div><div class="l">WPS</div></div>
<div class="card"><div class="n">{stats["wps_open"]}</div><div class="l">Open</div></div>
<div class="card"><div class="n">{stats["targets"]}</div><div class="l">Targets</div></div>
<div class="card"><div class="n">{len(creds)}</div><div class="l">Credentials</div></div>
</div>
<h2>Networks</h2>
<table><tr><th>BSSID</th><th>ESSID</th><th>CH</th><th>RSSI</th><th>WPS</th><th>Lock</th><th>Enc</th><th>Model</th></tr>"""

    for n in networks:
        wc = "g" if n["has_wps"] else ""
        wps = f'<span class="tag {wc}">Yes</span>' if n["has_wps"] else ""
        html += f"""<tr><td><code>{n["bssid"]}</code></td><td>{n["essid"] or "Hidden"}</td>
        <td>{n["channel"]}</td><td>{n["rssi"]}</td><td>{wps}</td>
        <td>{n["wps_locked"]}</td><td>{n["encryption"] or ""}</td>
        <td>{n["wps_model"] or ""}</td></tr>"""

    html += "</table>"

    if creds:
        html += "<h2>Captured Credentials</h2><table><tr><th>BSSID</th><th>ESSID</th><th>PIN</th><th>PSK</th><th>Method</th></tr>"
        for c in creds:
            html += f"<tr><td>{c['bssid']}</td><td>{c['essid'] or ''}</td><td>{c['pin'] or '-'}</td><td><b>{c['psk'] or '-'}</b></td><td>{c['method'] or '-'}</td></tr>"
        html += "</table>"

    html += "</body></html>"

    fname = f"report_{datetime.now():%Y%m%d_%H%M%S}.html"
    path = REPORTS_DIR / fname
    with open(path, "w") as f:
        f.write(html)
    return str(path)

def export_json(db):
    data = {
        "time": datetime.now().isoformat(),
        "networks": [dict(r) for r in db.get_all_networks()],
        "credentials": [dict(r) for r in db.get_credentials()],
        "sessions": [dict(r) for r in db.get_sessions(200)],
        "stats": db.get_stats(),
    }
    fname = f"export_{datetime.now():%Y%m%d_%H%M%S}.json"
    path = REPORTS_DIR / fname
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)
    return str(path)
