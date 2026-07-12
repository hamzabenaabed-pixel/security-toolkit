#!/usr/bin/env python3
"""
Offline-first target assessment and method planner (v2).

Combines:
  - scan fields (WPS version/lock, signal, encryption)
  - versioned PIN intelligence + manufacturer algorithms
  - model vulnerability classification
  - ISP / modern-CPE heuristics
  - optional history (prior Pixie failures, attempted PINs)

Does not transmit attack traffic.
"""

from __future__ import annotations

import re

from modules.playbooks import build_playbook
from modules.wps_pins import (
    classify_model_vulnerability,
    classify_pixie_resistance,
    detect_manufacturer,
    get_database_pins,
    get_pin_database_info,
    suggest_pins,
)

# ESSID tokens that usually mean ISP-managed modern CPE (Pixie rarely works)
ISP_ESSID_PATTERNS = [
    r"\binwi\b",
    r"\biam\b",
    r"\bmaroc\s*telecom\b",
    r"\borange\b",
    r"\bfibre[_-]?",
    r"\bfiber[_-]?",
    r"\blivebox\b",
    r"\bbox\b",
    r"\bont\b",
    r"\bgpon\b",
    r"\bftth\b",
    r"\bwana\b",
]

# Brands / models historically more associated with weak WPS RNGs (not a guarantee)
PIXIE_FRIENDLY_HINTS = [
    "Ralink", "RT-", "Broadcom", "BCM", "Realtek", "RTL",
    "MediaTek", "MT76", "Atheros", "AR92",
]


def _field(network, key, default=None):
    try:
        value = network[key]
    except (KeyError, IndexError, TypeError):
        return default
    return default if value is None else value


def _is_isp_essid(essid):
    text = str(essid or "")
    for pattern in ISP_ESSID_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            return True
    return False


def _wps_version_score(version):
    text = str(version or "").strip()
    if not text:
        return 0, "unknown"
    if text.startswith("1") or text in ("0x10", "1.0", "1"):
        return 25, "1.x"
    if text.startswith("2") or text in ("0x20", "2.0", "2"):
        return -15, "2.x"
    return 0, text


class TargetAssessor:
    """Build a repeatable assessment report for one scanned access point."""

    def __init__(self, internal_monitor=True, internal_injection=False, history=None):
        self.internal_monitor = bool(internal_monitor)
        self.internal_injection = bool(internal_injection)
        # Optional history dict from DB:
        # {
        #   "pixie_failed": bool,
        #   "pixie_success": bool,
        #   "attempted_pin_count": int,
        #   "last_pixie_status": str,
        # }
        self.history = history or {}

    @staticmethod
    def _signal_grade(rssi):
        if rssi == 0:
            return "unknown"
        if rssi >= -60:
            return "excellent"
        if rssi >= -70:
            return "good"
        if rssi >= -80:
            return "fair"
        if rssi >= -85:
            return "weak"
        return "very_weak"

    def _score_pixie(
        self,
        wps_available,
        wps_version,
        vulnerable_model,
        vendor_heuristic,
        database_pins,
        algorithm,
        algorithm_confidence,
        essid,
        manufacturer,
        model,
        device,
        modern_resistant=False,
        resistant_match=None,
    ):
        """
        Return (is_candidate, confidence 0-100, reasons[], tier).

        tier: high | medium | low | none
        """
        reasons = []
        if not wps_available:
            return False, 0, ["WPS unavailable or locked"], "none"

        conf = 35  # base if WPS open-ish
        reasons.append("WPS appears available")

        ver_delta, ver_label = _wps_version_score(wps_version)
        conf += ver_delta
        if ver_label == "1.x":
            reasons.append("WPS 1.x historically more Pixie-prone")
        elif ver_label == "2.x":
            reasons.append("WPS 2.0 — many modern APs resist offline Pixie")

        if vulnerable_model:
            conf += 25
            reasons.append("Exact vulnerable model family match")
        elif vendor_heuristic:
            conf += 5
            reasons.append("Vendor heuristic only (not confirmed vulnerable)")

        if database_pins:
            conf += 10
            reasons.append("Known-default PIN DB hit for OUI (not the same as Pixie)")
        else:
            conf -= 8
            reasons.append("No known-default PINs for this OUI")

        algo = (algorithm or "generic").lower()
        if algo != "generic" and int(algorithm_confidence or 0) >= 70:
            conf += 8
            reasons.append(
                "Manufacturer algorithm mapped ({algo}, {c}%)".format(
                    algo=algo, c=algorithm_confidence
                )
            )
        else:
            conf -= 10
            reasons.append("Unknown/generic OUI algorithm mapping")

        blob = " ".join([str(manufacturer or ""), str(model or ""), str(device or "")])
        if any(h.lower() in blob.lower() for h in PIXIE_FRIENDLY_HINTS):
            conf += 10
            reasons.append("Chipset/vendor string sometimes seen in older Pixie cases")

        if _is_isp_essid(essid):
            conf -= 25
            reasons.append(
                "ISP/fibre-style ESSID — usually modern CPE with hardened WPS RNG"
            )

        if modern_resistant:
            conf -= 45
            reasons.append(
                "Modern ISP ONT/CPE model ({match}) — classic pixiewps almost never works".format(
                    match=resistant_match or "known-family"
                )
            )

        # History: prior offline Pixie failure with full data is strong negative
        if self.history.get("pixie_success"):
            conf = 95
            reasons.append("Prior verified Pixie success on this BSSID")
        elif self.history.get("pixie_failed"):
            conf -= 40
            reasons.append(
                "Prior Pixie run collected data but found no PIN — treat as resistant"
            )

        conf = max(0, min(100, conf))

        if conf >= 65:
            tier = "high"
            candidate = True
        elif conf >= 40:
            tier = "medium"
            candidate = True
        elif conf >= 20:
            tier = "low"
            candidate = True  # still listed, but last resort
        else:
            tier = "none"
            candidate = False

        return candidate, conf, reasons, tier

    def _score_pin_path(self, wps_available, database_pins, suggestions, wps_locked):
        if not wps_available:
            return False, 0, "WPS unavailable"
        if str(wps_locked).lower() == "yes":
            return False, 0, "WPS locked"
        high = [
            s for s in (suggestions or [])
            if int(s.get("confidence") or 0) >= 70
            or str(s.get("method", "")).startswith("known_db")
            or str(s.get("method", "")).startswith("static")
        ]
        if database_pins or high:
            return True, 80 if database_pins else 65, "High-confidence PIN candidates exist"
        mid = [
            s for s in (suggestions or [])
            if int(s.get("confidence") or 0) >= 30
        ]
        if mid:
            return True, 40, "Only generic/calculated PINs (low confidence)"
        return True, 15, "Fallback PINs only — high false-effort risk"

    def assess(self, network):
        bssid = str(_field(network, "bssid", "")).upper()
        essid = str(_field(network, "essid", "Hidden"))
        encryption = str(_field(network, "encryption", "Unknown"))
        encryption_upper = encryption.upper()
        wps_locked = str(_field(network, "wps_locked", "Unknown"))
        wps_version = str(_field(network, "wps_version", "") or "")
        raw_wps = _field(network, "has_wps", 0)
        if isinstance(raw_wps, str):
            has_wps = raw_wps.strip().lower() in ("1", "yes", "true", "on")
        else:
            has_wps = bool(raw_wps)
        model = str(_field(network, "wps_model", "") or "")
        device = str(_field(network, "wps_device", "") or "")

        try:
            channel = int(_field(network, "channel", 0) or 0)
        except (TypeError, ValueError):
            channel = 0
        try:
            rssi = int(_field(network, "rssi", 0) or 0)
        except (TypeError, ValueError):
            rssi = 0

        manufacturer, algorithm, algorithm_confidence = detect_manufacturer(bssid)
        manufacturer = manufacturer or "Unknown"
        vulnerability = classify_model_vulnerability(model, device)
        vulnerable_model = vulnerability["status"] == "known_vulnerable"
        vulnerable_match = vulnerability["match"]
        vendor_heuristic = vulnerability["status"] == "vendor_heuristic"
        vendor_match = vulnerability["match"]
        database_pins = get_database_pins(bssid, limit=16)
        suggestions = suggest_pins(bssid, wps_version, wps_locked)
        database_info = get_pin_database_info()

        is_wpa2 = "WPA2" in encryption_upper or "WPA/WPA2" in encryption_upper
        is_wpa3_only = "WPA3" in encryption_upper and "WPA2" not in encryption_upper
        is_open_or_wep = encryption_upper in ("OPEN", "WEP")
        wps_available = has_wps and wps_locked.lower() != "yes"
        isp_essid = _is_isp_essid(essid)
        modern_resistant, resistant_match, resistant_reason = classify_pixie_resistance(
            model, device, manufacturer=manufacturer, essid=essid
        )

        warnings = []
        if rssi == 0:
            warnings.append("Signal level is unavailable; run a fresh scan before testing")
        elif rssi <= -85:
            warnings.append("Signal is too weak for reliable WPS/EAPOL exchanges")
        elif rssi <= -80:
            warnings.append("Signal is weak; move closer before online testing")
        if wps_locked.lower() == "yes":
            warnings.append("WPS is locked; do not start online PIN attempts")
        if not has_wps:
            warnings.append("WPS was not detected in the latest scan")
        if is_open_or_wep:
            warnings.append("PMKID and WPA EAPOL handshakes do not apply to Open/WEP")
        if is_wpa3_only:
            warnings.append("WPA3-only target is not compatible with PMKID/WPA2 cracking")
        if essid.lower() == "hidden":
            warnings.append("Hidden ESSID requires the exact network name")
        if vendor_heuristic:
            warnings.append(
                "Vendor heuristic matched {match}, but vulnerability is not confirmed without an exact model/firmware match".format(
                    match=vendor_match
                )
            )
        if not self.internal_injection:
            warnings.append(
                "Internal QCACLD interface is receive-only; injection methods are unavailable"
            )
        if isp_essid:
            warnings.append(
                "ISP/fibre ESSID pattern detected — prefer PMKID/passive or known-PIN paths over Pixie"
            )
        if modern_resistant:
            warnings.append(
                "Model looks like modern ISP ONT ({match}) — skip Pixie; use PMKID/passive".format(
                    match=resistant_match or "?"
                )
            )
        if self.history.get("pixie_failed"):
            warnings.append(
                "History: previous Pixie probe did not recover a PIN for this BSSID"
            )

        # Readiness score (general testability, not "will crack")
        score = 10
        if rssi == 0:
            score += 0
        elif rssi >= -60:
            score += 30
        elif rssi >= -70:
            score += 24
        elif rssi >= -80:
            score += 16
        elif rssi >= -85:
            score += 8

        if is_wpa2:
            score += 15
        elif is_wpa3_only:
            score += 5
        elif is_open_or_wep:
            score -= 10

        if wps_available:
            score += 15
        elif has_wps:
            score -= 5
        if database_pins:
            score += 18
        if vulnerable_model:
            score += 10
        if isp_essid and not database_pins:
            score -= 5
        if self.history.get("pixie_failed") and not database_pins:
            score -= 5
        score = max(0, min(100, score))

        pmkid_candidate = bool(is_wpa2)
        passive_candidate = bool(is_wpa2 and self.internal_monitor)

        pixie_candidate, pixie_confidence, pixie_reasons, pixie_tier = self._score_pixie(
            wps_available=wps_available,
            wps_version=wps_version,
            vulnerable_model=vulnerable_model,
            vendor_heuristic=vendor_heuristic,
            database_pins=database_pins,
            algorithm=algorithm,
            algorithm_confidence=algorithm_confidence,
            essid=essid,
            manufacturer=manufacturer,
            model=model,
            device=device,
            modern_resistant=modern_resistant,
            resistant_match=resistant_match,
        )

        pin_ok, pin_confidence, pin_reason = self._score_pin_path(
            wps_available, database_pins, suggestions, wps_locked
        )

        # Build ordered methods (least waste / least lockout risk first)
        attack_order = []
        method_scores = {}

        if wps_available and database_pins:
            attack_order.append("known_pin_sweep")
            method_scores["known_pin_sweep"] = 90
        if wps_available and pin_ok and pin_confidence >= 30 and not database_pins:
            attack_order.append("calculated_pin_sweep")
            method_scores["calculated_pin_sweep"] = pin_confidence
        if pmkid_candidate:
            attack_order.append("managed_pmkid_probe")
            method_scores["managed_pmkid_probe"] = 70 if is_wpa2 else 40
        if passive_candidate:
            attack_order.append("passive_handshake_wait")
            method_scores["passive_handshake_wait"] = 55

        # Pixie only if candidate; position by tier
        if pixie_candidate and pixie_tier == "high":
            # insert near front after known pins
            if "known_pin_sweep" in attack_order:
                idx = attack_order.index("known_pin_sweep") + 1
                attack_order.insert(idx, "pixie_probe")
            else:
                attack_order.insert(0, "pixie_probe")
            method_scores["pixie_probe"] = pixie_confidence
        elif pixie_candidate and pixie_tier == "medium":
            # after pin paths / with pmkid
            attack_order.append("pixie_probe")
            method_scores["pixie_probe"] = pixie_confidence
        elif pixie_candidate and pixie_tier == "low":
            attack_order.append("pixie_probe_last_resort")
            method_scores["pixie_probe_last_resort"] = pixie_confidence
            warnings.append(
                "Pixie confidence is LOW ({c}%) — one probe max; modern/ISP CPE often immune".format(
                    c=pixie_confidence
                )
            )

        if not self.internal_injection:
            attack_order.append("external_adapter_if_active_capture_required")

        # Human recommended string
        if wps_available and database_pins:
            recommended = "Suggested PIN Sweep (versioned known-default database)"
        elif pixie_tier == "high":
            recommended = "Pixie Dust probe (high confidence), then limited PIN sweep"
        elif pmkid_candidate and (pixie_tier in ("low", "none") or not wps_available):
            recommended = "Managed PMKID probe; passive handshake if a client reconnects"
        elif wps_available and pin_confidence >= 30:
            recommended = (
                "Limited calculated PIN sweep (low/medium confidence), "
                "then PMKID/passive — Pixie only as last resort"
            )
        elif wps_available and pixie_tier == "medium":
            recommended = "One Pixie probe, then stop if no PIN; prefer PMKID/passive next"
        elif passive_candidate:
            recommended = "Passive handshake wait"
        elif wps_available:
            recommended = "Avoid bulk WPS online tries — intelligence too weak for this OUI"
        else:
            recommended = "No compatible internal Wi-Fi method"

        # Rank pin candidates: prefer high confidence; cap pure fallback noise
        top_candidates = []
        for suggestion in suggestions:
            conf = int(suggestion.get("confidence") or 0)
            method = str(suggestion.get("method") or "")
            if conf < 10 and method == "common_fallback" and len(top_candidates) >= 3:
                continue
            top_candidates.append({
                "pin": suggestion.get("pin", ""),
                "method": method,
                "confidence": conf,
                "priority": suggestion.get("priority", 99),
            })
            if len(top_candidates) >= 12:
                break

        # Suggested max online PIN tries for UI
        if database_pins:
            max_online_pins = min(8, max(3, len(database_pins)))
        elif pin_confidence >= 40:
            max_online_pins = 5
        else:
            max_online_pins = 3

        return {
            "bssid": bssid,
            "essid": essid,
            "channel": channel,
            "rssi": rssi,
            "signal_grade": self._signal_grade(rssi),
            "encryption": encryption,
            "has_wps": has_wps,
            "wps_locked": wps_locked,
            "wps_version": wps_version,
            "manufacturer": manufacturer,
            "algorithm": algorithm or "generic",
            "algorithm_confidence": algorithm_confidence,
            "model": model,
            "device": device,
            "vulnerable_model": vulnerable_model,
            "vulnerable_match": vulnerable_match,
            "vendor_heuristic": vendor_heuristic,
            "vendor_match": vendor_match,
            "vulnerability_status": vulnerability["status"],
            "known_pin_count": len(database_pins),
            "best_pin": top_candidates[0]["pin"] if top_candidates else "",
            "pin_candidates": top_candidates,
            "pin_path_confidence": pin_confidence,
            "pin_path_reason": pin_reason,
            "max_online_pins": max_online_pins,
            "pixie_candidate": bool(pixie_candidate),
            "pixie_confidence": pixie_confidence,
            "pixie_tier": pixie_tier,
            "pixie_reasons": pixie_reasons,
            "pmkid_candidate": pmkid_candidate,
            "passive_candidate": passive_candidate,
            "isp_essid": isp_essid,
            "modern_resistant": modern_resistant,
            "resistant_match": resistant_match,
            "internal_monitor": self.internal_monitor,
            "internal_injection": self.internal_injection,
            "readiness_score": score,
            "recommended_method": recommended,
            "attack_order": attack_order,
            "method_scores": method_scores,
            "warnings": warnings,
            "history": dict(self.history or {}),
            "intelligence_version": database_info.get("database_version", "unavailable"),
            "intelligence_prefixes": database_info.get("prefix_count", 0),
            "intelligence_pins": database_info.get("pin_count", 0),
            "playbook": build_playbook(
                {"bssid": bssid, "essid": essid, "wps_model": model,
                 "wps_device": device, "manufacturer": manufacturer, "rssi": rssi},
                {"manufacturer": manufacturer, "model": model, "essid": essid,
                 "rssi": rssi, "known_pin_count": len(database_pins),
                 "max_online_pins": max_online_pins, "pixie_tier": pixie_tier,
                 "modern_resistant": modern_resistant, "isp_essid": isp_essid,
                 "attack_order": attack_order, "pmkid_candidate": pmkid_candidate},
            ),
        }


def history_from_db(db, bssid):
    """Build assessment history hints from sessions / attempts if DB available."""
    history = {
        "pixie_failed": False,
        "pixie_success": False,
        "attempted_pin_count": 0,
        "last_pixie_status": "",
    }
    if db is None or not bssid:
        return history
    try:
        history["attempted_pin_count"] = len(db.get_attempted_wps_pins(bssid) or [])
    except Exception:
        pass
    try:
        rows = db.fetch_all(
            """SELECT attack_type,status,pin_found,psk_found,start_time
               FROM sessions
               WHERE bssid=?
               ORDER BY start_time DESC LIMIT 40""",
            (bssid,),
        )
        for row in rows or []:
            atype = str(row["attack_type"] or "").lower()
            status = str(row["status"] or "").lower()
            if "pixie" not in atype:
                continue
            if status == "success" and row["psk_found"]:
                history["pixie_success"] = True
                history["last_pixie_status"] = "success"
                break
            if status in (
                "completed", "failed", "pixie_not_vulnerable", "no_pin", "not_vulnerable"
            ) or (status != "success" and not row["psk_found"]):
                # treat non-success finished pixie as failed probe
                history["pixie_failed"] = True
                history["last_pixie_status"] = status or "failed"
                # keep scanning for a later success
    except Exception:
        pass
    return history
