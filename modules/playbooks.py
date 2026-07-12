#!/usr/bin/env python3
"""
Vendor / family playbooks for authorized Wi-Fi testing.

Returns a structured path: primary method, ordered steps, budgets, warnings.
Does not transmit traffic.
"""

from __future__ import annotations

import re


RALINK_HINTS = ("ralink", "rt2860", "rt2870", "rt3070", "rt5370", "mediatek", "mt76")
ONT_HINTS = (
    "hg6145", "hg8245", "eg8145", "hs8145", "hs8546",
    "f680", "f670", "f660", "zxhn", "fiberhome", "gpon", "ont",
)
ZTE_HINTS = ("zte", "f680", "f670", "f660", "zxhn")
HUAWEI_HINTS = ("huawei", "hg6", "hg8", "echolife", "optixstar")


def _blob(network):
    parts = [
        str(network.get("wps_model") or ""),
        str(network.get("wps_device") or ""),
        str(network.get("manufacturer") or ""),
        str(network.get("essid") or ""),
        str(network.get("bssid") or ""),
    ]
    return " ".join(parts).lower()


def detect_family(network, assessment=None):
    assessment = assessment or {}
    text = _blob(network)
    mfr = str(assessment.get("manufacturer") or network.get("manufacturer") or "").lower()
    model = str(assessment.get("model") or network.get("wps_model") or "").lower()
    essid = str(assessment.get("essid") or network.get("essid") or "").lower()

    if any(h in text or h in model for h in RALINK_HINTS):
        return "ralink_mtk"
    if any(h in text or h in model for h in ONT_HINTS) or assessment.get("modern_resistant"):
        return "isp_ont"
    if any(h in text or h in mfr for h in ZTE_HINTS):
        return "zte_cpe"
    if any(h in text or h in mfr for h in HUAWEI_HINTS):
        return "huawei_cpe"
    if assessment.get("isp_essid") or re.search(r"inwi|fibre|fiber|iam|orange", essid):
        return "isp_generic"
    if int(assessment.get("known_pin_count") or 0) > 0:
        return "known_pin_oui"
    return "generic"


def build_playbook(network, assessment=None):
    """
    Build an actionable playbook from network + optional assessment dict.
    """
    assessment = assessment or {}
    family = detect_family(network, assessment)
    rssi = assessment.get("rssi", network.get("rssi", 0))
    try:
        rssi = int(rssi or 0)
    except (TypeError, ValueError):
        rssi = 0

    base = {
        "family": family,
        "primary": "assess_only",
        "steps": [],
        "max_online_pins": 3,
        "pixie_allowed": False,
        "pmkid_preferred": True,
        "web_audit_useful": True,
        "warnings": [],
        "tools": ["iw", "wpa_supplicant", "pixiewps"],
        "notes": [],
    }

    if family == "ralink_mtk":
        base.update({
            "primary": "pixie_then_verify",
            "steps": [
                "confirm_signal_ge_-80",
                "pixie_probe_mode1",
                "verify_pin_online",
                "store_psk_if_verified",
            ],
            "pixie_allowed": True,
            "pmkid_preferred": False,
            "max_online_pins": 2,
            "tools": ["pixiewps", "wpa_supplicant", "reaver"],
            "notes": [
                "Ralink/RT28xx is a classic Pixie family when WPS is open.",
                "Always verify recovered PIN online to obtain WPA-PSK.",
            ],
        })
    elif family == "isp_ont":
        base.update({
            "primary": "pmkid_or_isp_wordlist",
            "steps": [
                "skip_pixie_default",
                "isp_password_candidates_offline",
                "managed_pmkid_probe",
                "passive_handshake_wait",
                "router_web_audit_optional",
            ],
            "pixie_allowed": False,
            "pmkid_preferred": True,
            "max_online_pins": 2,
            "tools": ["hcxdumptool", "hashcat", "wpa_supplicant"],
            "warnings": [
                "Modern ISP ONT (HG6145/F6xx class): classic pixiewps almost never works.",
            ],
            "notes": [
                "Prefer offline ISP password patterns + PMKID over WPS spam.",
            ],
        })
    elif family == "zte_cpe":
        base.update({
            "primary": "pmkid_and_careful_web",
            "steps": [
                "managed_pmkid_probe",
                "router_web_audit_max_3_creds",
                "limited_pin_only_if_known_db",
            ],
            "pixie_allowed": False,
            "max_online_pins": 3,
            "tools": ["hcxdumptool", "browser", "router_audit"],
            "warnings": ["ZTE web UI often lockouts after ~3 wrong passwords (~60s)."],
        })
    elif family == "known_pin_oui":
        base.update({
            "primary": "known_pin_sweep",
            "steps": [
                "known_pin_sweep_budget",
                "one_pixie_if_tier_high",
                "pmkid_fallback",
            ],
            "pixie_allowed": bool(assessment.get("pixie_tier") == "high"),
            "max_online_pins": int(assessment.get("max_online_pins") or 8),
            "pmkid_preferred": False,
            "notes": ["High-confidence OUI PIN database hit — start there."],
        })
    elif family == "huawei_cpe":
        base.update({
            "primary": "pmkid_first",
            "steps": ["managed_pmkid_probe", "passive_handshake_wait", "limited_pin_if_any"],
            "pixie_allowed": False,
            "max_online_pins": 3,
        })
    else:
        # generic
        order = list(assessment.get("attack_order") or [])
        if assessment.get("known_pin_count"):
            primary = "known_pin_sweep"
        elif assessment.get("pmkid_candidate"):
            primary = "managed_pmkid_probe"
        elif assessment.get("pixie_tier") == "high":
            primary = "pixie_then_verify"
        else:
            primary = "pmkid_or_limited_pin"
        base.update({
            "primary": primary,
            "steps": order[:6] or ["managed_pmkid_probe", "passive_handshake_wait"],
            "pixie_allowed": str(assessment.get("pixie_tier") or "") in ("high", "medium"),
            "max_online_pins": int(assessment.get("max_online_pins") or 3),
            "pmkid_preferred": "pmkid" in primary or "pmkid" in "".join(order),
        })

    if rssi and rssi <= -85:
        base["warnings"].append(
            "Signal {rssi} dBm is poor — move closer before online tests.".format(rssi=rssi)
        )
        if base["primary"] in ("pixie_then_verify", "known_pin_sweep"):
            base["notes"].append("Defer online WPS until signal improves.")

    if assessment.get("pixie_tier") == "none" or assessment.get("modern_resistant"):
        base["pixie_allowed"] = False

    base["label"] = {
        "ralink_mtk": "Ralink/MediaTek (Pixie-friendly profile)",
        "isp_ont": "ISP ONT / fibre CPE (Pixie-resistant profile)",
        "zte_cpe": "ZTE CPE profile",
        "huawei_cpe": "Huawei CPE profile",
        "known_pin_oui": "Known-default OUI PIN profile",
        "isp_generic": "ISP ESSID profile",
        "generic": "Generic profile",
    }.get(family, family)

    return base
