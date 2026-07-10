#!/usr/bin/env python3
"""Network Reconnaissance"""
import re, subprocess

class NetworkRecon:
    def __init__(self, interface=None):
        self.interface = interface

    def get_gateway(self):
        try:
            r = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True, timeout=5)
            m = re.search(r"default via ([0-9.]+)", r.stdout)
            if m: return m.group(1)
        except: pass
        return "192.168.1.1"

    def get_local_ip(self):
        try:
            r = subprocess.run(["hostname", "-I"], capture_output=True, text=True, timeout=5)
            ips = r.stdout.strip().split()
            return ips[0] if ips else "0.0.0.0"
        except: return "0.0.0.0"

    def get_subnet(self):
        ip = self.get_local_ip()
        parts = ip.split(".")
        if len(parts) == 4:
            return "{}.{}.{}.0/24".format(parts[0], parts[1], parts[2])
        return "192.168.1.0/24"

    def ping_scan(self, target=None, timeout=60):
        if not target: target = self.get_subnet()
        hosts = []
        try:
            r = subprocess.run(["nmap", "-sn", "-T4", target], capture_output=True, text=True, timeout=timeout)
            cur = {}
            for line in r.stdout.split("\n"):
                m = re.match(r"Nmap scan report for (.+)", line)
                if m:
                    if cur.get("ip"): hosts.append(cur)
                    addr = m.group(1).strip()
                    if "(" in addr:
                        parts = addr.split("(")
                        cur = {"ip": parts[1].rstrip(")"), "hostname": parts[0].strip(), "mac": "", "vendor": ""}
                    else:
                        cur = {"ip": addr, "hostname": "", "mac": "", "vendor": ""}
                m2 = re.search(r"MAC Address: ([0-9A-F:]{17}) \((.+?)\)", line)
                if m2:
                    cur["mac"] = m2.group(1)
                    cur["vendor"] = m2.group(2)
            if cur.get("ip"): hosts.append(cur)
        except FileNotFoundError:
            return {"error": "nmap not found"}
        except: pass
        return hosts

    def port_scan(self, target, ports=None, timeout=60):
        if not ports: ports = "21,22,23,80,443,8080,8443"
        try:
            r = subprocess.run(["nmap", "-sV", "-T4", "-p", ports, target], capture_output=True, text=True, timeout=timeout)
            results = []
            for line in r.stdout.split("\n"):
                m = re.match(r"(\d+)/tcp\s+open\s+(\S+)\s*(.*)", line)
                if m:
                    results.append({"port": int(m.group(1)), "service": m.group(2), "version": m.group(3).strip(), "state": "open"})
            return results
        except FileNotFoundError:
            return {"error": "nmap not found"}
        except: return []

    def os_detect(self, target, timeout=30):
        try:
            r = subprocess.run(["nmap", "-O", "-T4", target], capture_output=True, text=True, timeout=timeout)
            info = {"detected": []}
            for line in r.stdout.split("\n"):
                m = re.match(r"OS details:\s*(.+)", line)
                if m: info["detected"].append(m.group(1))
                m = re.match(r"Running:\s*(.+)", line)
                if m: info["detected"].append(m.group(1))
            return info
        except: return {"error": "failed"}

    def traceroute(self, target, timeout=30):
        try:
            r = subprocess.run(["traceroute", "-m", "15", "-w", "2", target], capture_output=True, text=True, timeout=timeout)
            hops = []
            for line in r.stdout.split("\n")[1:]:
                m = re.match(r"\s*(\d+)\s+(.+)", line)
                if m: hops.append({"hop": int(m.group(1)), "info": m.group(2).strip()})
            return hops
        except: return []

    def wifi_scan(self, interface=None):
        iface = interface or self.interface or "wlan0"
        try:
            r = subprocess.run(["iw", "dev", iface, "scan"], capture_output=True, text=True, timeout=20)
            if r.returncode != 0: return []
            nets = []
            cur = None
            for line in r.stdout.split("\n"):
                line = line.strip().lstrip("\t")
                m = re.match(r"BSS ([0-9a-fA-F:]{17})", line)
                if m:
                    if cur: nets.append(cur)
                    cur = {"bssid": m.group(1).upper(), "essid": "", "channel": 0, "rssi": 0}
                    continue
                if not cur: continue
                m2 = re.match(r"SSID: (.*)", line)
                if m2: cur["essid"] = m2.group(1).strip() or "Hidden"
                m2 = re.match(r"signal: ([+-]?[0-9.]+) dBm", line)
                if m2: cur["rssi"] = int(float(m2.group(1)))
                m2 = re.match(r"freq: (\d+)", line)
                if m2:
                    f = int(m2.group(1))
                    if 2412 <= f <= 2484: cur["channel"] = 14 if f == 2484 else (f - 2412) // 5 + 1
            if cur: nets.append(cur)
            return sorted(nets, key=lambda x: x["rssi"], reverse=True)
        except: return []
