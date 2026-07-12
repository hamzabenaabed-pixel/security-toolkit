#!/usr/bin/env python3
"""Report Generator — safer HTML/JSON exports with assessment context."""

import html as html_lib
import json
from datetime import datetime
from pathlib import Path

REPORTS_DIR = Path(__file__).parent.parent / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)


def _esc(value):
    """Escape values for HTML text nodes / attributes."""
    if value is None:
        return ""
    return html_lib.escape(str(value), quote=True)


def _safe_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def generate_html(db):
    """Generate a self-contained HTML security report."""
    networks = db.get_all_networks()
    creds = db.get_credentials()
    stats = db.get_stats()
    sessions = db.get_sessions(50)
    try:
        intel = db.get_intelligence_stats()
    except Exception:
        intel = {}
    try:
        suspicious = db.get_suspicious_wps_credentials()
    except Exception:
        suspicious = []

    assessments = []
    try:
        assessments = db.fetch_all(
            """SELECT bssid, essid, assessed_at, readiness_score,
                      recommended_method, manufacturer, model, warnings,
                      known_pin_count, intelligence_version
               FROM target_assessments
               ORDER BY assessed_at DESC, id DESC LIMIT 50"""
        )
    except Exception:
        assessments = []

    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    intel_version = _esc(intel.get("version", "unavailable"))
    intel_prefixes = _esc(intel.get("prefixes", 0))
    intel_pins = _esc(intel.get("pins", 0))

    parts = []
    parts.append(
        """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WPS Toolkit Report</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
background:#0a0a1a;color:#c8facc;padding:20px;line-height:1.45}}
h1{{color:#0ff;text-align:center;margin-bottom:8px}}
h2{{color:#ff0;border-bottom:2px solid #444;padding-bottom:5px;margin:28px 0 12px}}
.meta{{text-align:center;color:#888;margin-bottom:18px}}
.banner{{background:#1a1028;border:1px solid #553;color:#fc8;padding:12px 16px;
border-radius:8px;margin:12px auto 20px;max-width:960px}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));
gap:10px;margin:16px 0 8px}}
.card{{background:#1a1a2e;border:1px solid #333;padding:14px;border-radius:8px;text-align:center}}
.card .n{{font-size:26px;font-weight:bold;color:#0ff}}
.card .l{{color:#888;margin-top:4px;font-size:12px}}
table{{width:100%;border-collapse:collapse;background:#1a1a2e;margin:10px 0;
font-size:13px}}
th{{background:#2d1b69;color:#0ff;padding:8px;text-align:left}}
td{{padding:6px 8px;border-bottom:1px solid #222;vertical-align:top}}
tr:hover{{background:#222}}
.tag{{padding:2px 6px;border-radius:8px;font-size:11px;display:inline-block}}
.g{{background:#0a3d0a;color:#0f0}}
.r{{background:#3d0a0a;color:#f44}}
.y{{background:#3d3a0a;color:#ff0}}
.dim{{color:#777}}
code{{color:#9cf}}
.note{{color:#aaa;font-size:12px;margin-top:8px}}
footer{{margin-top:30px;color:#555;font-size:11px;text-align:center}}
</style></head><body>
<h1>WPS Toolkit — Security Report</h1>
<p class="meta">Generated: {generated}</p>
<div class="banner">
<strong>Authorized testing only.</strong>
This report may contain sensitive credentials and network intelligence.
Treat it as confidential. WPS PIN rows without a verified PSK are
<strong>not</strong> treated as successful compromises.
</div>
<div class="grid">
<div class="card"><div class="n">{total}</div><div class="l">Networks</div></div>
<div class="card"><div class="n">{wps}</div><div class="l">WPS</div></div>
<div class="card"><div class="n">{wps_open}</div><div class="l">WPS Open</div></div>
<div class="card"><div class="n">{targets}</div><div class="l">Targets</div></div>
<div class="card"><div class="n">{compromised}</div><div class="l">Compromised</div></div>
<div class="card"><div class="n">{cred_count}</div><div class="l">Credentials</div></div>
<div class="card"><div class="n">{intel_prefixes}</div><div class="l">PIN Prefixes</div></div>
<div class="card"><div class="n">{intel_pins}</div><div class="l">Known PINs</div></div>
</div>
<p class="note">Intelligence snapshot: <code>{intel_version}</code></p>
""".format(
            generated=_esc(generated),
            total=_esc(stats.get("total", 0)),
            wps=_esc(stats.get("wps", 0)),
            wps_open=_esc(stats.get("wps_open", 0)),
            targets=_esc(stats.get("targets", 0)),
            compromised=_esc(stats.get("compromised", 0)),
            cred_count=_esc(len(creds)),
            intel_prefixes=intel_prefixes,
            intel_pins=intel_pins,
            intel_version=intel_version,
        )
    )

    # Networks
    parts.append("<h2>Networks</h2>")
    if not networks:
        parts.append("<p class=\"dim\">No networks stored yet.</p>")
    else:
        parts.append(
            "<table><tr>"
            "<th>BSSID</th><th>ESSID</th><th>CH</th><th>RSSI</th>"
            "<th>WPS</th><th>Lock</th><th>Enc</th><th>Model</th><th>Status</th>"
            "</tr>"
        )
        for n in networks:
            has_wps = _safe_int(n["has_wps"] if "has_wps" in n.keys() else 0)
            wps_html = (
                '<span class="tag g">Yes</span>' if has_wps
                else '<span class="dim">-</span>'
            )
            lock = str(n["wps_locked"] or "Unknown")
            if lock == "No":
                lock_html = '<span class="tag g">Open</span>'
            elif lock == "Yes":
                lock_html = '<span class="tag r">Locked</span>'
            else:
                lock_html = '<span class="tag y">?</span>'
            parts.append(
                "<tr>"
                "<td><code>{bssid}</code></td>"
                "<td>{essid}</td>"
                "<td>{channel}</td>"
                "<td>{rssi}</td>"
                "<td>{wps}</td>"
                "<td>{lock}</td>"
                "<td>{enc}</td>"
                "<td>{model}</td>"
                "<td>{status}</td>"
                "</tr>".format(
                    bssid=_esc(n["bssid"]),
                    essid=_esc(n["essid"] or "Hidden"),
                    channel=_esc(n["channel"]),
                    rssi=_esc(n["rssi"]),
                    wps=wps_html,
                    lock=lock_html,
                    enc=_esc(n["encryption"] or ""),
                    model=_esc(n["wps_model"] or ""),
                    status=_esc(n["status"] or ""),
                )
            )
        parts.append("</table>")

    # Credentials — verified vs suspicious
    parts.append("<h2>Captured Credentials</h2>")
    verified = []
    for c in creds:
        psk = (c["psk"] or "").strip()
        if psk:
            verified.append(c)
    if not verified:
        parts.append(
            "<p class=\"dim\">No verified credentials (PSK present) stored.</p>"
        )
    else:
        parts.append(
            "<table><tr>"
            "<th>BSSID</th><th>ESSID</th><th>PIN</th><th>PSK</th>"
            "<th>Method</th><th>Time</th>"
            "</tr>"
        )
        for c in verified:
            parts.append(
                "<tr>"
                "<td><code>{bssid}</code></td>"
                "<td>{essid}</td>"
                "<td>{pin}</td>"
                "<td><b>{psk}</b></td>"
                "<td>{method}</td>"
                "<td>{time}</td>"
                "</tr>".format(
                    bssid=_esc(c["bssid"]),
                    essid=_esc(c["essid"] or ""),
                    pin=_esc(c["pin"] or "-"),
                    psk=_esc(c["psk"] or "-"),
                    method=_esc(c["method"] or "-"),
                    time=_esc(str(c["captured_at"])[:19]),
                )
            )
        parts.append("</table>")

    if suspicious:
        parts.append("<h2>Suspicious / Incomplete WPS Rows</h2>")
        parts.append(
            "<p class=\"note\">These rows have a PIN but no PSK. "
            "They are <strong>not</strong> verified successes and may be "
            "legacy false positives.</p>"
        )
        parts.append(
            "<table><tr>"
            "<th>ID</th><th>BSSID</th><th>ESSID</th><th>PIN</th>"
            "<th>Method</th><th>Time</th>"
            "</tr>"
        )
        for c in suspicious:
            parts.append(
                "<tr>"
                "<td>{cid}</td>"
                "<td><code>{bssid}</code></td>"
                "<td>{essid}</td>"
                "<td class=\"y\">{pin}</td>"
                "<td>{method}</td>"
                "<td>{time}</td>"
                "</tr>".format(
                    cid=_esc(c["id"]),
                    bssid=_esc(c["bssid"]),
                    essid=_esc(c["essid"] or ""),
                    pin=_esc(c["pin"] or "-"),
                    method=_esc(c["method"] or "-"),
                    time=_esc(str(c["captured_at"])[:19]),
                )
            )
        parts.append("</table>")

    # Assessments
    parts.append("<h2>Recent Target Assessments</h2>")
    if not assessments:
        parts.append(
            "<p class=\"dim\">No saved assessments yet. "
            "Use Attack Center → Target Assessment.</p>"
        )
    else:
        parts.append(
            "<table><tr>"
            "<th>When</th><th>BSSID</th><th>ESSID</th><th>Score</th>"
            "<th>Method</th><th>MFR</th><th>Model</th><th>Known PINs</th>"
            "</tr>"
        )
        for a in assessments:
            parts.append(
                "<tr>"
                "<td>{when}</td>"
                "<td><code>{bssid}</code></td>"
                "<td>{essid}</td>"
                "<td>{score}</td>"
                "<td>{method}</td>"
                "<td>{mfr}</td>"
                "<td>{model}</td>"
                "<td>{pins}</td>"
                "</tr>".format(
                    when=_esc(str(a["assessed_at"])[:19]),
                    bssid=_esc(a["bssid"]),
                    essid=_esc(a["essid"] or ""),
                    score=_esc(a["readiness_score"]),
                    method=_esc(a["recommended_method"] or ""),
                    mfr=_esc(a["manufacturer"] or ""),
                    model=_esc(a["model"] or ""),
                    pins=_esc(a["known_pin_count"]),
                )
            )
        parts.append("</table>")

    # Sessions
    parts.append("<h2>Recent Sessions</h2>")
    if not sessions:
        parts.append("<p class=\"dim\">No attack sessions recorded.</p>")
    else:
        parts.append(
            "<table><tr>"
            "<th>ID</th><th>Type</th><th>BSSID</th><th>ESSID</th>"
            "<th>Status</th><th>PIN</th><th>PSK</th><th>Start</th>"
            "</tr>"
        )
        for s in sessions:
            # Only show PIN/PSK if session marked success-ish and values exist
            pin_disp = s["pin_found"] or "-"
            psk_disp = s["psk_found"] or "-"
            parts.append(
                "<tr>"
                "<td>{sid}</td>"
                "<td>{atype}</td>"
                "<td><code>{bssid}</code></td>"
                "<td>{essid}</td>"
                "<td>{status}</td>"
                "<td>{pin}</td>"
                "<td>{psk}</td>"
                "<td>{start}</td>"
                "</tr>".format(
                    sid=_esc(s["id"]),
                    atype=_esc(s["attack_type"] or ""),
                    bssid=_esc(s["bssid"] or ""),
                    essid=_esc(s["essid"] or ""),
                    status=_esc(s["status"] or ""),
                    pin=_esc(pin_disp),
                    psk=_esc(psk_disp),
                    start=_esc(str(s["start_time"])[:19]),
                )
            )
        parts.append("</table>")

    parts.append(
        "<footer>WPS Security Toolkit — offline report. "
        "Do not publish without redaction.</footer>"
        "</body></html>"
    )

    html = "".join(parts)
    fname = "report_{ts}.html".format(
        ts=datetime.now().strftime("%Y%m%d_%H%M%S")
    )
    path = REPORTS_DIR / fname
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(html)
    return str(path)


def export_json(db):
    """Export structured JSON including assessments and intelligence meta."""
    try:
        intel = db.get_intelligence_stats()
    except Exception:
        intel = {}
    try:
        assessments = [
            dict(r) for r in db.fetch_all(
                "SELECT * FROM target_assessments ORDER BY assessed_at DESC LIMIT 100"
            )
        ]
    except Exception:
        assessments = []
    try:
        attempts = [
            dict(r) for r in db.fetch_all(
                "SELECT bssid, pin, attempted_at, status, duration "
                "FROM wps_pin_attempts ORDER BY attempted_at DESC LIMIT 500"
            )
        ]
    except Exception:
        attempts = []
    try:
        suspicious = [dict(r) for r in db.get_suspicious_wps_credentials()]
    except Exception:
        suspicious = []

    # Split credentials into verified / incomplete for safer consumers
    all_creds = [dict(r) for r in db.get_credentials()]
    verified = []
    incomplete = []
    for row in all_creds:
        if (row.get("psk") or "").strip():
            verified.append(row)
        else:
            incomplete.append(row)

    data = {
        "time": datetime.now().isoformat(timespec="seconds"),
        "tool": "wps-security-toolkit",
        "disclaimer": (
            "Authorized security testing only. "
            "PIN-only rows are not verified successes."
        ),
        "stats": db.get_stats(),
        "intelligence": intel,
        "networks": [dict(r) for r in db.get_all_networks()],
        "credentials_verified": verified,
        "credentials_incomplete": incomplete,
        "credentials_suspicious_wps": suspicious,
        "sessions": [dict(r) for r in db.get_sessions(200)],
        "assessments": assessments,
        "pin_attempts": attempts,
        # Backward-compatible full list
        "credentials": all_creds,
    }
    fname = "export_{ts}.json".format(
        ts=datetime.now().strftime("%Y%m%d_%H%M%S")
    )
    path = REPORTS_DIR / fname
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, default=str)
    return str(path)


def export_diagnostics_json(report, path=None):
    """Write a diagnostics report dict to reports/."""
    if path is None:
        fname = "diagnostics_{ts}.json".format(
            ts=datetime.now().strftime("%Y%m%d_%H%M%S")
        )
        path = REPORTS_DIR / fname
    else:
        path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, default=str)
    return str(path)
