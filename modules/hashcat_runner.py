#!/usr/bin/env python3
"""Hashcat Integration"""
import os, shutil, subprocess, re, time
from pathlib import Path

HANDSHAKE_DIR = Path(__file__).parent.parent / "data" / "handshakes"

class HashcatRunner:
    def __init__(self):
        self.process = None
        self.output = []
        self.callback = None

    def is_installed(self):
        return shutil.which("hashcat") is not None

    def list_captures(self):
        caps = []
        for f in sorted(HANDSHAKE_DIR.glob("*.hc22000"), key=os.path.getmtime, reverse=True):
            caps.append({"file": str(f), "name": f.name, "size": f.stat().st_size})
        return caps

    def crack(self, capture_file, wordlist, rules=None, callback=None):
        self.output = []
        self.callback = callback

        try:
            with open(wordlist, "r", errors="ignore") as f:
                total = sum(1 for line in f if line.strip())
        except Exception:
            total = 0

        self._log("Capture: " + os.path.basename(capture_file))
        self._log("Wordlist: " + os.path.basename(wordlist) + " (" + str(total) + " passwords)")

        # Try hashcat first
        if shutil.which("hashcat"):
            self._log("\nTrying hashcat -m 22000...")
            cmd = ["hashcat", "-m", "22000", "--force", capture_file, wordlist]
            if rules:
                cmd.extend(["-r", rules])
            try:
                self.process = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, bufsize=1)
                no_devices = False
                for line in iter(self.process.stdout.readline, ""):
                    line = line.rstrip("\n")
                    self.output.append(line)
                    if self.callback:
                        self.callback(line)
                    if "No devices" in line:
                        no_devices = True
                self.process.wait()
                if not no_devices and self.process.returncode == 0:
                    result = self._parse_result()
                    if result["status"] == "cracked":
                        return result
                self._log("\n[hashcat: No CPU/GPU on this device]")
            except FileNotFoundError:
                self._log("hashcat not found")
            except KeyboardInterrupt:
                self.stop()
                return {"status": "stopped"}
            except Exception as e:
                self._log("hashcat error: " + str(e))

        # Fallback: Python cracker
        self._log("\nRunning Python cracker...")
        return self._python_crack(capture_file, wordlist)

    def _python_crack(self, capture_file, wordlist):
        try:
            with open(capture_file, "r") as f:
                content = f.read().strip()
        except Exception as e:
            return {"status": "error", "message": str(e)}

        lines = content.split("\n")
        first = lines[0].strip()

        if first.startswith("PMKID:"):
            return self._crack_pmkid(first, wordlist)
        elif first.startswith("WPA*"):
            self._log("[Full handshake - needs hashcat for real cracking]")
            self._log("[Transfer .hc22000 to PC with hashcat/GPU]")
            return {"status": "error", "message": "Full handshake needs hashcat"}
        else:
            self._log("[Unknown format: " + first[:50] + "]")
            return {"status": "error", "message": "Unknown format"}

    def _crack_pmkid(self, content, wordlist):
        import hashlib, hmac as hmac_mod

        if ":" not in content:
            return {"status": "error", "message": "Invalid PMKID"}

        parts = content.split(":", 1)[1].strip().split("*")
        if len(parts) < 4:
            return {"status": "error", "message": "Invalid PMKID format"}

        target_pmkid = parts[0].upper()
        try:
            bssid = bytes.fromhex(parts[1])
            sta = bytes.fromhex(parts[2])
            essid = bytes.fromhex(parts[3])
        except ValueError as e:
            return {"status": "error", "message": "Bad hex: " + str(e)}

        self._log("Target PMKID: " + target_pmkid)
        self._log("ESSID: " + essid.decode("utf-8", errors="replace"))
        self._log("Attacking...\n")

        count = 0
        start_time = time.time()
        try:
            with open(wordlist, "r", errors="ignore") as f:
                for line in f:
                    password = line.strip()
                    if not password or len(password) < 8:
                        continue
                    count += 1
                    pmk = hashlib.pbkdf2_hmac("sha1", password.encode("utf-8"), essid, 4096, dklen=32)
                    msg = b"PMK Name" + bssid + sta
                    pmkid = hmac_mod.new(pmk, msg, hashlib.sha1).digest()[:16].hex().upper()
                    if pmkid == target_pmkid:
                        elapsed = time.time() - start_time
                        self._log("\n" + "=" * 50)
                        self._log("KEY FOUND! [" + password + "]")
                        self._log("Tested: " + str(count) + " in " + str(int(elapsed)) + "s")
                        self._log("=" * 50)
                        return {"status": "cracked", "password": password}
                    if count % 100 == 0:
                        elapsed = time.time() - start_time
                        speed = count / elapsed if elapsed > 0 else 0
                        self._log("  Tested: " + str(count) + " (" + str(int(speed)) + "/s)")

            self._log("\nTested " + str(count) + " - not found")
            return {"status": "exhausted"}
        except KeyboardInterrupt:
            self._log("\nStopped at " + str(count))
            return {"status": "stopped"}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def stop(self):
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
            except Exception:
                try: self.process.kill()
                except: pass

    def _parse_result(self):
        for line in self.output:
            if "Exhausted" in line:
                return {"status": "exhausted"}
        for line in reversed(self.output):
            line = line.strip()
            if not line or line.startswith(" ") or line.startswith("["):
                continue
            skip = ["Started:", "Stopped:", "hashcat", "Session", "Status:",
                    "Progress:", "Speed:", "Time:", "Running:", "Recovered",
                    "Input:", "Hardware", "Initializing", "No devices",
                    "Approaching", "Cracked"]
            if any(w in line for w in skip):
                continue
            if ":" in line:
                parts = line.rstrip().split(":")
                if len(parts) >= 2:
                    candidate = parts[-1].strip()
                    if len(candidate) >= 8 and not candidate.startswith("0x"):
                        return {"status": "cracked", "password": candidate}
        return {"status": "completed"}

    def _log(self, msg):
        self.output.append(msg)
        if self.callback:
            self.callback(msg)
