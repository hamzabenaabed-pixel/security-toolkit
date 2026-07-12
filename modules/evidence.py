#!/usr/bin/env python3
"""
Evidence locker — structured session artifacts for lab notes / debugging.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from config import LOGS_DIR, REPORTS_DIR


def _ts():
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def write_attack_evidence(
    bssid,
    essid,
    action,
    result=None,
    assessment=None,
    playbook=None,
    extra=None,
):
    """
    Write a JSON evidence file under logs/evidence/.
    Returns path string.
    """
    out_dir = LOGS_DIR / "evidence"
    out_dir.mkdir(parents=True, exist_ok=True)
    safe_bssid = str(bssid or "unknown").replace(":", "").replace("-", "")
    path = out_dir / "ev_{bssid}_{ts}.json".format(bssid=safe_bssid[:12], ts=_ts())

    payload = {
        "time": datetime.now().isoformat(timespec="seconds"),
        "bssid": bssid,
        "essid": essid,
        "action": action,
        "result": result or {},
        "assessment_summary": {},
        "playbook": playbook or {},
        "extra": extra or {},
        "disclaimer": "Authorized testing only. Treat credentials as confidential.",
    }
    if isinstance(assessment, dict):
        payload["assessment_summary"] = {
            k: assessment.get(k)
            for k in (
                "recommended_method", "pixie_tier", "pixie_confidence",
                "known_pin_count", "readiness_score", "modern_resistant",
                "attack_order", "warnings", "rssi", "wps_locked", "wps_version",
            )
            if k in assessment
        }

    # Avoid dumping huge hex blobs twice
    if isinstance(payload["result"], dict):
        pixie = payload["result"].get("pixie_data") or {}
        if isinstance(pixie, dict):
            payload["result"]["pixie_fields_present"] = [
                k for k, v in pixie.items() if v and k != "BSSID"
            ]
            # keep short previews only
            payload["result"]["pixie_preview"] = {
                k: (str(v)[:16] + "...") if v and len(str(v)) > 16 else v
                for k, v in pixie.items()
                if v and k != "BSSID"
            }

    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False, default=str)
    return str(path)


def write_lab_note_md(evidence_path, title=None):
    """Create a short Markdown lab note beside reports/."""
    evidence_path = Path(evidence_path)
    try:
        data = json.loads(evidence_path.read_text(encoding="utf-8"))
    except Exception:
        return None
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    md_path = REPORTS_DIR / (evidence_path.stem + ".md")
    result = data.get("result") or {}
    lines = [
        "# Lab note — {title}".format(title=title or data.get("essid") or data.get("bssid")),
        "",
        "- Time: `{t}`".format(t=data.get("time")),
        "- BSSID: `{b}`".format(b=data.get("bssid")),
        "- ESSID: {e}".format(e=data.get("essid")),
        "- Action: {a}".format(a=data.get("action")),
        "- Status: **{s}**".format(s=result.get("status")),
        "",
        "## Credentials",
        "- PIN: `{p}`".format(p=result.get("pin") or result.get("pixie_pin") or "-"),
        "- PSK: `{p}`".format(p=result.get("psk") or "-"),
        "",
        "## Next steps",
    ]
    status = str(result.get("status") or "")
    if status == "pixie_pin_unverified":
        lines.append("- Retry **PIN Attack** with the recovered PIN when signal is stronger.")
    elif status == "pixie_not_vulnerable":
        lines.append("- Skip further Pixie on this BSSID; try PMKID / passive / ISP wordlist.")
    elif status == "success":
        lines.append("- Store PSK securely; disable WPS on the AP if you own it.")
    else:
        lines.append("- Re-run assessment; check signal and lock state.")
    lines.extend([
        "",
        "## Evidence file",
        "`{p}`".format(p=str(evidence_path)),
        "",
        "> Authorized testing only.",
        "",
    ])
    md_path.write_text("\n".join(lines), encoding="utf-8")
    return str(md_path)
