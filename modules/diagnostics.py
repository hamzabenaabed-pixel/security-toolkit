#!/usr/bin/env python3
"""
Offline system diagnostics for WPS Toolkit.

Checks tools, interfaces, intelligence snapshot, and data integrity.
Does not transmit any attack traffic.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

from config import APP_DIR, CFG_PATH, DB_PATH, LOGS_DIR, REPORTS_DIR
from modules.wps_pins import get_pin_database_info

# Tools that improve reliability when present. Missing tools are warnings,
# not hard failures — the toolkit still works in reduced mode.
CORE_TOOLS = [
    ("python3", "Python runtime"),
    ("iw", "Wireless scan / interface info"),
    ("ip", "Interface configuration"),
    ("wpa_supplicant", "WPS engine backend"),
    ("wpa_cli", "wpa_supplicant control"),
]

OPTIONAL_TOOLS = [
    ("wash", "WPS survey (lock/version)"),
    ("reaver", "WPS PIN verify / attack backend"),
    ("hcxdumptool", "PMKID capture"),
    ("hcxpcapngtool", "Handshake/PMKID conversion"),
    ("aircrack-ng", "Legacy capture/crack helpers"),
    ("pixiewps", "Pixie Dust offline cracker"),
    ("airmon-ng", "Monitor mode helper"),
    ("airodump-ng", "Capture helper"),
    ("wash", "WPS survey helper"),
    ("reaver", "External WPS helper"),
    ("hashcat", "GPU/CPU password cracker"),
    ("hcxpcapngtool", "Handshake conversion"),
    ("hostapd", "Evil Twin AP"),
    ("dnsmasq", "Evil Twin DHCP/DNS"),
    ("tcpdump", "Passive capture helper"),
    ("macchanger", "MAC spoofing helper"),
]


def _run_cmd(command, timeout=5):
    """Safe short command runner with timeout + capture."""
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result
    except FileNotFoundError:
        return None
    except subprocess.TimeoutExpired:
        return None
    except Exception:
        return None


def _tool_status(name):
    path = shutil.which(name)
    return {
        "name": name,
        "installed": bool(path),
        "path": path or "",
    }


def list_wireless_interfaces():
    """Return wireless interface names via `iw dev` when available."""
    result = _run_cmd(["iw", "dev"], timeout=5)
    if result is None or result.returncode != 0:
        return []
    interfaces = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if line.startswith("Interface "):
            interfaces.append(line.split()[1])
    return interfaces


def interface_mode(iface):
    """Return interface type (managed/monitor/...) or unknown."""
    result = _run_cmd(["iw", "dev", iface, "info"], timeout=5)
    if result is None or result.returncode != 0:
        return "unknown"
    for line in result.stdout.splitlines():
        line = line.strip()
        if line.startswith("type "):
            return line.split()[1]
    return "unknown"


def check_pin_database():
    """Report status of the bundled offline PIN intelligence snapshot."""
    info = get_pin_database_info()
    path = APP_DIR / "data" / "wps_pin_database.json"
    status = "ok"
    notes = []
    version = info.get("database_version", "unavailable")
    prefixes = int(info.get("prefix_count", 0) or 0)
    pins = int(info.get("pin_count", 0) or 0)

    if not path.exists():
        status = "missing"
        notes.append("data/wps_pin_database.json is missing")
    elif version in ("unavailable", "unknown") or prefixes == 0:
        status = "empty"
        notes.append("PIN database loaded but contains no usable prefixes")
    elif prefixes < 100:
        status = "partial"
        notes.append("PIN database looks unusually small")

    return {
        "status": status,
        "path": str(path),
        "exists": path.exists(),
        "version": version,
        "prefixes": prefixes,
        "pins": pins,
        "source": info.get("source", {}),
        "notes": notes,
    }


def check_paths():
    """Verify expected project directories/files exist."""
    items = []
    expected_dirs = [
        ("data", APP_DIR / "data"),
        ("reports", REPORTS_DIR),
        ("logs", LOGS_DIR),
        ("modules", APP_DIR / "modules"),
    ]
    for label, path in expected_dirs:
        items.append({
            "name": label,
            "path": str(path),
            "ok": path.exists() and path.is_dir(),
            "kind": "directory",
        })

    expected_files = [
        ("config", CFG_PATH if CFG_PATH.exists() else APP_DIR / "config.py"),
        ("database module", APP_DIR / "database.py"),
        ("main", APP_DIR / "main.py"),
        ("vulnwsc models", APP_DIR / "vulnwsc.txt"),
        ("pin database", APP_DIR / "data" / "wps_pin_database.json"),
        ("sqlite db", DB_PATH),
    ]
    for label, path in expected_files:
        items.append({
            "name": label,
            "path": str(path),
            "ok": path.exists(),
            "kind": "file",
        })
    return items


def check_database(db=None):
    """Lightweight SQLite integrity / stats check."""
    report = {
        "status": "unknown",
        "stats": {},
        "intelligence": {},
        "notes": [],
    }
    if db is None:
        report["status"] = "skipped"
        report["notes"].append("No database handle provided")
        return report

    try:
        stats = db.get_stats()
        intel = db.get_intelligence_stats()
        report["stats"] = dict(stats)
        report["intelligence"] = dict(intel)
        # Integrity pragma
        row = db.fetch_one("PRAGMA integrity_check")
        integrity = row[0] if row is not None else "unknown"
        report["integrity"] = integrity
        if integrity == "ok":
            report["status"] = "ok"
        else:
            report["status"] = "error"
            report["notes"].append("SQLite integrity_check failed: {val}".format(
                val=integrity
            ))
    except Exception as exc:
        report["status"] = "error"
        report["notes"].append(str(exc))
    return report


def run_diagnostics(db=None, interface=None):
    """
    Full offline diagnostic report.

    Returns a dict suitable for UI display and JSON export.
    """
    core = [_tool_status(name) for name, _desc in CORE_TOOLS]
    optional = [_tool_status(name) for name, _desc in OPTIONAL_TOOLS]
    interfaces = list_wireless_interfaces()
    iface_details = []
    for iface in interfaces:
        iface_details.append({
            "name": iface,
            "mode": interface_mode(iface),
        })

    pin_db = check_pin_database()
    paths = check_paths()
    database = check_database(db)

    warnings = []
    errors = []

    if os.geteuid() != 0:
        warnings.append("Not running as root — monitor mode and scans may fail")

    missing_core = [t["name"] for t in core if not t["installed"]]
    if missing_core:
        warnings.append(
            "Missing core tools: {tools}".format(tools=", ".join(missing_core))
        )

    if not interfaces:
        warnings.append("No wireless interfaces detected via `iw dev`")

    if interface:
        if interface not in interfaces:
            warnings.append(
                "Configured interface '{iface}' was not detected".format(
                    iface=interface
                )
            )
        else:
            mode = interface_mode(interface)
            if mode not in ("managed", "monitor"):
                warnings.append(
                    "Interface '{iface}' mode is '{mode}'".format(
                        iface=interface, mode=mode
                    )
                )

    if pin_db["status"] == "missing":
        errors.append(
            "WPS PIN intelligence file is missing — rebuild with "
            "tools/build_pin_database.py"
        )
    elif pin_db["status"] in ("empty", "partial"):
        warnings.append(
            "WPS PIN intelligence is {status} (prefixes={prefixes})".format(
                status=pin_db["status"],
                prefixes=pin_db["prefixes"],
            )
        )

    if database["status"] == "error":
        errors.append("Database check failed")

    bad_paths = [p["name"] for p in paths if not p["ok"] and p["name"] not in (
        "config",  # config.json may not exist yet
        "sqlite db",  # created on first Database()
    )]
    # Only treat critical missing files as errors
    critical_missing = [
        p["name"] for p in paths
        if (not p["ok"]) and p["name"] in (
            "database module", "main", "modules", "data", "reports", "logs"
        )
    ]
    if critical_missing:
        errors.append(
            "Missing project paths: {items}".format(
                items=", ".join(critical_missing)
            )
        )

    if errors:
        overall = "error"
    elif warnings:
        overall = "warn"
    else:
        overall = "ok"

    return {
        "overall": overall,
        "python": sys.version.split()[0],
        "platform": os.uname().sysname + " " + os.uname().release,
        "machine": os.uname().machine,
        "is_root": os.geteuid() == 0,
        "project_root": str(APP_DIR),
        "core_tools": core,
        "optional_tools": optional,
        "interfaces": iface_details,
        "configured_interface": interface or "",
        "pin_database": pin_db,
        "paths": paths,
        "database": database,
        "warnings": warnings,
        "errors": errors,
        "tool_catalog": {
            "core": [{"name": n, "description": d} for n, d in CORE_TOOLS],
            "optional": [{"name": n, "description": d} for n, d in OPTIONAL_TOOLS],
        },
    }


def format_summary(report):
    """One-line human summary."""
    return (
        "Diagnostics: {overall} | root={root} | ifaces={ifaces} | "
        "pin_db={pin_status} ({prefixes} prefixes) | warnings={warns} errors={errs}"
    ).format(
        overall=report.get("overall", "?"),
        root="yes" if report.get("is_root") else "no",
        ifaces=len(report.get("interfaces") or []),
        pin_status=(report.get("pin_database") or {}).get("status", "?"),
        prefixes=(report.get("pin_database") or {}).get("prefixes", 0),
        warns=len(report.get("warnings") or []),
        errs=len(report.get("errors") or []),
    )
