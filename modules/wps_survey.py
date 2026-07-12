#!/usr/bin/env python3
"""
Optional WPS survey helpers (wash integration when available).

Falls back gracefully when wash is not installed.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from typing import Dict, List, Optional


def wash_available():
    return bool(shutil.which("wash"))


def survey_wps(interface, timeout=25, channel=None) -> Dict:
    """
    Run wash -i <iface> briefly and parse rows.

    Returns:
      {ok, tool, rows:[{bssid, channel, rssi, wps_version, locked, vendor, essid}], error}
    """
    if not wash_available():
        return {
            "ok": False,
            "tool": "wash",
            "rows": [],
            "error": "wash not installed (apt install reaver often provides wash)",
        }

    cmd = ["wash", "-i", interface, "-C"]  # ignore FCS errors when supported
    # Some wash builds use -a for all channels; keep minimal portable flags
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=max(5, int(timeout)),
        )
    except subprocess.TimeoutExpired as exc:
        # wash often runs until timeout — parse partial stdout
        out = (exc.stdout or "") if isinstance(exc.stdout, str) else (
            exc.stdout.decode(errors="replace") if exc.stdout else ""
        )
        rows = _parse_wash_output(out)
        return {"ok": True, "tool": "wash", "rows": rows, "error": "", "partial": True}
    except FileNotFoundError:
        return {"ok": False, "tool": "wash", "rows": [], "error": "wash not found"}
    except Exception as exc:
        return {"ok": False, "tool": "wash", "rows": [], "error": str(exc)}

    out = (result.stdout or "") + "\n" + (result.stderr or "")
    rows = _parse_wash_output(out)
    return {
        "ok": True,
        "tool": "wash",
        "rows": rows,
        "error": "" if rows else (result.stderr or "no rows"),
        "returncode": result.returncode,
    }


def _parse_wash_output(text: str) -> List[Dict]:
    rows = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("BSSID") or set(line) <= {"-", " "}:
            continue
        # Typical wash:
        # BSSID  Ch  dBm  WPS  Lck  Vendor  ESSID
        m = re.match(
            r"^([0-9A-Fa-f:]{17})\s+(\d+)\s+(-?\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)$",
            line,
        )
        if not m:
            # looser: bssid first field
            parts = line.split()
            if len(parts) >= 6 and re.match(r"^[0-9A-Fa-f:]{17}$", parts[0]):
                bssid, ch, rssi, wps, lck = parts[:5]
                vendor = parts[5] if len(parts) > 5 else ""
                essid = " ".join(parts[6:]) if len(parts) > 6 else ""
            else:
                continue
        else:
            bssid, ch, rssi, wps, lck, vendor, essid = m.groups()

        locked = str(lck).strip().lower()
        if locked in ("yes", "y", "1", "true", "locked"):
            lock_norm = "Yes"
        elif locked in ("no", "n", "0", "false", "open"):
            lock_norm = "No"
        else:
            lock_norm = "Unknown"

        rows.append({
            "bssid": bssid.upper(),
            "channel": int(ch) if str(ch).isdigit() else 0,
            "rssi": int(rssi) if re.match(r"^-?\d+$", str(rssi)) else 0,
            "wps_version": str(wps),
            "wps_locked": lock_norm,
            "vendor": vendor,
            "essid": essid.strip(),
            "source": "wash",
            "has_wps": 1,
        })
    return rows


def lookup_bssid(rows, bssid) -> Optional[Dict]:
    bssid = (bssid or "").upper()
    for row in rows or []:
        if row.get("bssid") == bssid:
            return row
    return None


def merge_lock_into_network(network: dict, wash_row: Optional[dict]) -> dict:
    """Return a shallow-updated network dict with better lock/version if known."""
    out = dict(network or {})
    if not wash_row:
        return out
    if wash_row.get("wps_locked") in ("Yes", "No"):
        out["wps_locked"] = wash_row["wps_locked"]
    if wash_row.get("wps_version"):
        out["wps_version"] = wash_row["wps_version"]
    if wash_row.get("vendor") and not out.get("wps_manufacturer"):
        out["wps_manufacturer"] = wash_row["vendor"]
    out["has_wps"] = 1
    out["wash_seen"] = True
    return out
