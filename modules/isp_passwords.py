#!/usr/bin/env python3
"""
Offline ISP / ONT password *candidates* for authorized testing.

These are heuristic generators (not guarantees). Always verify online only
on networks you own or have written permission to test.

References informing patterns:
  - Field ESSID styles: Fibre_inwi_*, Wifi_Perso_*, fh_*
  - Public research on some Fiberhome HG6145F1 predictable defaults
"""

from __future__ import annotations

import re
from typing import List, Dict


def _clean_essid(essid: str) -> str:
    return str(essid or "").strip()


def _hex_tail_candidates(token: str) -> List[str]:
    token = re.sub(r"[^0-9A-Fa-f]", "", token or "")
    out = []
    if not token:
        return out
    # common transforms
    variants = {
        token.lower(),
        token.upper(),
        token.lower()[::-1],
        token.upper()[::-1],
    }
    try:
        val = int(token, 16)
        # documented style transform used in some Fiberhome writeups: 0xFFFFFF - n
        if 0 < val < 0xFFFFFF:
            inv = (0xFFFFFF - val)
            variants.add(format(inv, "x"))
            variants.add(format(inv, "X"))
            variants.add("wlan" + format(inv, "x"))
    except ValueError:
        pass
    for v in variants:
        if 6 <= len(v) <= 16:
            out.append(v)
    return out


def candidates_for_target(essid="", bssid="", model="", manufacturer="", limit=40) -> List[Dict]:
    """
    Return list of {password, source, confidence}.
    """
    essid = _clean_essid(essid)
    model = str(model or "")
    manufacturer = str(manufacturer or "")
    bssid = str(bssid or "").replace(":", "").replace("-", "").upper()
    items = []
    seen = set()

    def add(pwd, source, confidence):
        pwd = str(pwd or "").strip()
        if not pwd or pwd in seen:
            return
        # Project policy: WPA candidates length 8..12 only
        if not (8 <= len(pwd) <= 12):
            return
        seen.add(pwd)
        items.append({
            "password": pwd,
            "source": source,
            "confidence": int(confidence),
        })

    el = essid.lower()

    # --- Fiberhome / fh_XXXXXX style ---
    m = re.search(r"(?:^|[_\-])fh[_-]?([0-9a-fA-F]{4,8})", essid, re.I)
    if m or "fiberhome" in model.lower() or "hg6145" in model.lower():
        token = m.group(1) if m else ""
        for v in _hex_tail_candidates(token):
            add(v, "fiberhome_hex_transform", 55)
            add("wlan" + v.lower(), "fiberhome_wlan_prefix", 45)
        # SSID itself fragments
        digits = re.findall(r"\d{6,10}", essid)
        for d in digits:
            add(d, "essid_digit_run", 35)

    # --- Inwi fibre style Fibre_inwi_2.4G_XXXX / _XXXX ---
    if "inwi" in el or "fibre_inwi" in el or "fiber_inwi" in el:
        tails = re.findall(r"([0-9A-Fa-f]{4,6})$", essid)
        tails += re.findall(r"_([0-9A-Fa-f]{4,6})(?:$|[^0-9A-Za-z])", essid)
        for t in tails:
            for v in _hex_tail_candidates(t):
                add(v, "inwi_tail", 40)
            add(t.lower(), "inwi_tail_raw", 30)
            add(t.upper(), "inwi_tail_raw", 30)
        # common weak defaults still worth listing low
        for pwd in ("admin123", "inwi1234", "12345678", "password"):
            add(pwd, "inwi_common_weak", 10)

    # --- Orange / Livebox style ---
    if "orange" in el or "livebox" in el:
        for pwd in ("orange", "admin", "1234", "password"):
            add(pwd, "orange_common", 10)
        tails = re.findall(r"([0-9A-Za-z]{6,10})$", essid)
        for t in tails:
            add(t, "orange_essid_tail", 25)

    # --- IAM / Maroc Telecom ---
    if "iam" in el or "maroc" in el or "menara" in el:
        for pwd in ("IAM@1234", "admin", "12345678"):
            add(pwd, "iam_common", 10)

    # --- BSSID-derived weak patterns (very low confidence) ---
    if len(bssid) >= 12:
        add(bssid[-8:].lower(), "bssid_last8", 15)
        add(bssid[-8:].upper(), "bssid_last8", 15)
        add(bssid[6:].lower(), "bssid_nic", 10)

    # --- Model-specific notes as passwords? no — keep generic fallbacks last ---
    for pwd, conf in (
        ("12345678", 5),
        ("1234567890", 5),
        ("password", 5),
        ("admin123", 5),
    ):
        add(pwd, "generic_weak", conf)

    items.sort(key=lambda x: (-x["confidence"], x["password"]))
    return items[: max(1, int(limit))]


def format_candidates(cands, limit=12):
    lines = []
    for i, c in enumerate(cands[:limit], 1):
        lines.append(
            "{i}. {pwd}  ({src}, conf {conf})".format(
                i=i, pwd=c["password"], src=c["source"], conf=c["confidence"]
            )
        )
    return lines
