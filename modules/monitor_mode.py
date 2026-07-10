#!/usr/bin/env python3
"""Monitor Mode Manager"""

import re
import subprocess
import time

def get_mode(iface):
    try:
        r = subprocess.run(["iw", "dev", iface, "info"],
                          capture_output=True, text=True, timeout=5)
        m = re.search(r"type\s+(\w+)", r.stdout)
        return m.group(1) if m else "unknown"
    except Exception:
        return "unknown"

def enable_monitor(iface):
    try:
        subprocess.run(["airmon-ng", "check", "kill"],
                      capture_output=True, timeout=15)
    except Exception:
        pass
    time.sleep(1)

    try:
        r = subprocess.run(["airmon-ng", "start", iface],
                          capture_output=True, text=True, timeout=15)
        out = r.stdout + r.stderr
        mons = re.findall(r"(\w+mon\w*)", out)
        if mons:
            return mons[0]
    except Exception:
        pass

    # Manual method
    try:
        subprocess.run(["ip", "link", "set", iface, "down"],
                      capture_output=True, timeout=5)
        subprocess.run(["iw", "dev", iface, "set", "type", "monitor"],
                      capture_output=True, timeout=5)
        subprocess.run(["ip", "link", "set", iface, "up"],
                      capture_output=True, timeout=5)
        time.sleep(1)
        if get_mode(iface) == "monitor":
            return iface
    except Exception:
        pass

    return None

def disable_monitor(iface):
    try:
        subprocess.run(["airmon-ng", "stop", iface],
                      capture_output=True, timeout=15)
    except Exception:
        pass
    time.sleep(1)

    # Manual fallback
    try:
        subprocess.run(["ip", "link", "set", iface, "down"],
                      capture_output=True, timeout=5)
        subprocess.run(["iw", "dev", iface, "set", "type", "managed"],
                      capture_output=True, timeout=5)
        subprocess.run(["ip", "link", "set", iface, "up"],
                      capture_output=True, timeout=5)
    except Exception:
        pass

def kill_processes():
    try:
        r = subprocess.run(["airmon-ng", "check", "kill"],
                          capture_output=True, text=True, timeout=15)
        return r.stdout
    except Exception:
        return ""

def set_channel(iface, channel):
    try:
        r = subprocess.run(["iw", "dev", iface, "set", "channel", str(channel)],
                          capture_output=True, text=True, timeout=5)
        return r.returncode == 0
    except Exception:
        return False

def iface_up(iface):
    try:
        subprocess.run(["ip", "link", "set", iface, "up"],
                      capture_output=True, timeout=5)
        return True
    except Exception:
        return False

def iface_down(iface):
    try:
        subprocess.run(["ip", "link", "set", iface, "down"],
                      capture_output=True, timeout=5)
        return True
    except Exception:
        return False

def get_iw_dev():
    try:
        r = subprocess.run(["iw", "dev"],
                          capture_output=True, text=True, timeout=5)
        return r.stdout
    except Exception:
        return "Error"
