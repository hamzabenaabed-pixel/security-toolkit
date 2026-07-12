#!/usr/bin/env python3
"""
Hard safety gates for online WPS / Pixie actions.

Policy goals:
  - refuse very weak signal by default
  - refuse locked WPS
  - refuse repeat Pixie on known-resistant BSSIDs unless forced
  - produce clear human messages (EN + short AR hints)
"""

from __future__ import annotations


# dBm thresholds
SIGNAL_BLOCK = -88          # refuse online WPS/Pixie
SIGNAL_WARN = -80           # allow with strong warning
SIGNAL_OK = -70


def evaluate_signal(rssi):
    try:
        rssi = int(rssi or 0)
    except (TypeError, ValueError):
        rssi = 0
    if rssi == 0:
        return {
            "level": "unknown",
            "rssi": 0,
            "allow": True,
            "force_required": False,
            "message": "Signal unknown — run a fresh scan near the AP.",
            "message_ar": "الإشارة غير معروفة — أعد المسح قرب الراوتر.",
        }
    if rssi <= SIGNAL_BLOCK:
        return {
            "level": "block",
            "rssi": rssi,
            "allow": False,
            "force_required": True,
            "message": (
                "Signal {rssi} dBm is too weak for reliable WPS. "
                "Move much closer (target better than -80 dBm)."
            ).format(rssi=rssi),
            "message_ar": "الإشارة ضعيفة جداً — اقترب من الراوتر قبل أي WPS/Pixie.",
        }
    if rssi <= SIGNAL_WARN:
        return {
            "level": "warn",
            "rssi": rssi,
            "allow": True,
            "force_required": True,
            "message": (
                "Signal {rssi} dBm is weak — timeouts and false Wrong-PIN are likely."
            ).format(rssi=rssi),
            "message_ar": "إشارة ضعيفة — احتمال انقطاع أو نتائج مضللة.",
        }
    if rssi <= SIGNAL_OK:
        return {
            "level": "fair",
            "rssi": rssi,
            "allow": True,
            "force_required": False,
            "message": "Signal fair ({rssi} dBm).".format(rssi=rssi),
            "message_ar": "إشارة مقبولة.",
        }
    return {
        "level": "ok",
        "rssi": rssi,
        "allow": True,
        "force_required": False,
        "message": "Signal OK ({rssi} dBm).".format(rssi=rssi),
        "message_ar": "إشارة جيدة.",
    }


def evaluate_wps_lock(wps_locked, has_wps=True):
    locked = str(wps_locked or "Unknown").strip().lower()
    if not has_wps:
        return {
            "allow": False,
            "force_required": False,
            "message": "WPS not detected on this target.",
            "message_ar": "WPS غير مكتشف على هذا الهدف.",
        }
    if locked in ("yes", "1", "true", "locked"):
        return {
            "allow": False,
            "force_required": False,
            "message": "WPS is locked — do not start online PIN/Pixie attempts.",
            "message_ar": "WPS مقفول — لا تبدأ محاولات PIN الآن.",
        }
    if locked in ("unknown", "?", ""):
        return {
            "allow": True,
            "force_required": False,
            "message": "WPS lock state unknown — watch for rate-limit / M2D.",
            "message_ar": "حالة القفل غير معروفة — راقب الحظر.",
        }
    return {
        "allow": True,
        "force_required": False,
        "message": "WPS appears unlocked.",
        "message_ar": "WPS يبدو مفتوحاً.",
    }


def evaluate_pixie_history(history=None, modern_resistant=False, pixie_tier="none"):
    history = history or {}
    if history.get("pixie_success"):
        return {
            "allow": True,
            "force_required": False,
            "block_reason": None,
            "message": "Prior Pixie success recorded for this BSSID.",
        }
    if history.get("pixie_failed"):
        return {
            "allow": False,
            "force_required": True,
            "block_reason": "history_pixie_failed",
            "message": (
                "History: Pixie already failed with full data on this BSSID. "
                "Do not spam Pixie — use PMKID/passive/ISP wordlist."
            ),
            "message_ar": "Pixie فشل سابقاً على هذا BSSID — لا تكرره.",
        }
    if modern_resistant or str(pixie_tier).lower() in ("none", "low"):
        return {
            "allow": False,
            "force_required": True,
            "block_reason": "planner_low_confidence",
            "message": (
                "Planner marks Pixie as low/none confidence for this model/profile."
            ),
            "message_ar": "المخطط لا يوصي بـ Pixie لهذا الموديل.",
        }
    return {
        "allow": True,
        "force_required": False,
        "block_reason": None,
        "message": "Pixie allowed by history/planner.",
    }


def gate_online_wps(
    rssi=0,
    wps_locked="Unknown",
    has_wps=True,
    action="pin",
    history=None,
    modern_resistant=False,
    pixie_tier="none",
):
    """
    Combined gate for online WPS actions: pin | pixie | bruteforce | smart.

    Returns dict:
      allowed, force_required, reasons[], signal, lock, pixie
    """
    signal = evaluate_signal(rssi)
    lock = evaluate_wps_lock(wps_locked, has_wps=has_wps)
    reasons = []
    allowed = True
    force_required = False

    if not lock["allow"]:
        allowed = False
        reasons.append(lock["message"])
    else:
        reasons.append(lock["message"])

    if not signal["allow"]:
        allowed = False
        force_required = True
        reasons.append(signal["message"])
    else:
        if signal.get("force_required"):
            force_required = True
        reasons.append(signal["message"])

    pixie = None
    if str(action).lower() in ("pixie", "smart"):
        pixie = evaluate_pixie_history(
            history=history,
            modern_resistant=modern_resistant,
            pixie_tier=pixie_tier if str(action).lower() == "pixie" else "medium",
        )
        if str(action).lower() == "pixie":
            if not pixie["allow"]:
                allowed = False
                force_required = True
                reasons.append(pixie["message"])
            else:
                reasons.append(pixie["message"])

    return {
        "allowed": allowed,
        "force_required": force_required or (not allowed),
        "reasons": reasons,
        "signal": signal,
        "lock": lock,
        "pixie": pixie,
        "summary": " | ".join(reasons[:3]),
    }
