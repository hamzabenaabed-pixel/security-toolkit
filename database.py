#!/usr/bin/env python3
"""Thread-safe SQLite database for WPS Toolkit"""

import sqlite3
import threading
import shutil
from datetime import datetime
from config import DB_PATH

class Database:
    SCHEMA = """
    CREATE TABLE IF NOT EXISTS networks(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        bssid TEXT UNIQUE NOT NULL,
        essid TEXT,
        channel INTEGER DEFAULT 0,
        frequency INTEGER DEFAULT 0,
        rssi INTEGER DEFAULT 0,
        has_wps INTEGER DEFAULT 0,
        wps_locked TEXT DEFAULT 'Unknown',
        wps_version TEXT,
        wps_device TEXT,
        wps_model TEXT,
        encryption TEXT,
        cipher TEXT,
        auth TEXT,
        first_seen TEXT DEFAULT (datetime('now','localtime')),
        last_seen TEXT DEFAULT (datetime('now','localtime')),
        scan_count INTEGER DEFAULT 1,
        scan_source TEXT,
        notes TEXT,
        is_target INTEGER DEFAULT 0,
        status TEXT DEFAULT 'new'
    );
    CREATE TABLE IF NOT EXISTS sessions(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        bssid TEXT,
        essid TEXT,
        attack_type TEXT,
        start_time TEXT DEFAULT (datetime('now','localtime')),
        end_time TEXT,
        status TEXT DEFAULT 'running',
        pin_found TEXT,
        psk_found TEXT,
        attempts INTEGER DEFAULT 0,
        log_path TEXT
    );
    CREATE TABLE IF NOT EXISTS credentials(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        bssid TEXT,
        essid TEXT,
        pin TEXT,
        psk TEXT,
        method TEXT,
        captured_at TEXT DEFAULT (datetime('now','localtime'))
    );
    CREATE TABLE IF NOT EXISTS activity_log(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT DEFAULT (datetime('now','localtime')),
        event_type TEXT,
        category TEXT,
        message TEXT,
        severity TEXT DEFAULT 'info'
    );
    CREATE TABLE IF NOT EXISTS scan_history(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_time TEXT DEFAULT (datetime('now','localtime')),
        interface TEXT,
        method TEXT,
        duration INTEGER,
        found INTEGER DEFAULT 0,
        new_count INTEGER DEFAULT 0
    );
    """

    def __init__(self):
        self.conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.lock = threading.Lock()
        with self.lock:
            cur = self.conn.cursor()
            cur.executescript(self.SCHEMA)
            self.conn.commit()

    def execute(self, query, params=()):
        with self.lock:
            cur = self.conn.cursor()
            cur.execute(query, params)
            self.conn.commit()
            return cur

    def fetch_one(self, query, params=()):
        with self.lock:
            cur = self.conn.cursor()
            cur.execute(query, params)
            return cur.fetchone()

    def fetch_all(self, query, params=()):
        with self.lock:
            cur = self.conn.cursor()
            cur.execute(query, params)
            return cur.fetchall()

    # ── Networks ──
    def add_network(self, net):
        existing = self.fetch_one("SELECT id FROM networks WHERE bssid=?", (net["bssid"],))
        if existing:
            self.execute(
                """UPDATE networks SET essid=?,channel=?,frequency=?,rssi=?,
                   has_wps=?,wps_locked=?,wps_version=?,wps_device=?,wps_model=?,
                   encryption=?,cipher=?,auth=?,last_seen=datetime('now','localtime'),
                   scan_count=scan_count+1,scan_source=? WHERE bssid=?""",
                (net.get("essid"),net.get("channel"),net.get("frequency"),
                 net.get("rssi"),net.get("has_wps",0),net.get("wps_locked","Unknown"),
                 net.get("wps_version"),net.get("wps_device"),net.get("wps_model"),
                 net.get("encryption"),net.get("cipher"),net.get("auth"),
                 net.get("source",""),net["bssid"]))
            return existing["id"]
        cur = self.execute(
            """INSERT INTO networks(bssid,essid,channel,frequency,rssi,has_wps,
               wps_locked,wps_version,wps_device,wps_model,encryption,cipher,auth,scan_source)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (net["bssid"],net.get("essid"),net.get("channel"),net.get("frequency"),
             net.get("rssi"),net.get("has_wps",0),net.get("wps_locked","Unknown"),
             net.get("wps_version"),net.get("wps_device"),net.get("wps_model"),
             net.get("encryption"),net.get("cipher"),net.get("auth"),net.get("source","")))
        return cur.lastrowid

    def get_all_networks(self):
        return self.fetch_all("SELECT * FROM networks ORDER BY last_seen DESC")

    def get_network(self, bssid):
        return self.fetch_one("SELECT * FROM networks WHERE bssid=?", (bssid,))

    def get_targets(self):
        return self.fetch_all("SELECT * FROM networks WHERE is_target=1 ORDER BY last_seen DESC")

    def set_target(self, nid, val=True):
        self.execute("UPDATE networks SET is_target=? WHERE id=?", (1 if val else 0, nid))

    def search_networks(self, q):
        return self.fetch_all(
            "SELECT * FROM networks WHERE essid LIKE ? OR bssid LIKE ? OR notes LIKE ?",
            (f"%{q}%",f"%{q}%",f"%{q}%"))

    def get_stats(self):
        s = {}
        s["total"] = self.fetch_one("SELECT COUNT(*) c FROM networks")["c"]
        s["wps"] = self.fetch_one("SELECT COUNT(*) c FROM networks WHERE has_wps=1")["c"]
        s["wps_open"] = self.fetch_one("SELECT COUNT(*) c FROM networks WHERE has_wps=1 AND wps_locked='No'")["c"]
        s["wps_locked"] = self.fetch_one("SELECT COUNT(*) c FROM networks WHERE has_wps=1 AND wps_locked='Yes'")["c"]
        s["targets"] = self.fetch_one("SELECT COUNT(*) c FROM networks WHERE is_target=1")["c"]
        s["compromised"] = self.fetch_one("SELECT COUNT(*) c FROM networks WHERE status='compromised'")["c"]
        return s

    # ── Sessions ──
    def create_session(self, bssid, essid, attack_type):
        cur = self.execute("INSERT INTO sessions(bssid,essid,attack_type) VALUES(?,?,?)",
                          (bssid,essid,attack_type))
        return cur.lastrowid

    def update_session(self, sid, **kwargs):
        sets = ",".join(k+"=?" for k in kwargs)
        self.execute(f"UPDATE sessions SET {sets} WHERE id=?", (*kwargs.values(),sid))

    def get_sessions(self, limit=50):
        return self.fetch_all("SELECT * FROM sessions ORDER BY start_time DESC LIMIT ?",(limit,))

    def get_active_sessions(self):
        return self.fetch_all("SELECT * FROM sessions WHERE status='running'")

    # ── Credentials ──
    def add_credential(self, bssid, essid, pin, psk, method):
        self.execute("INSERT INTO credentials(bssid,essid,pin,psk,method) VALUES(?,?,?,?,?)",
                    (bssid,essid,pin,psk,method))

    def get_credentials(self):
        return self.fetch_all("SELECT * FROM credentials ORDER BY captured_at DESC")

    # ── Activity Log ──
    def log(self, event_type, category, message, severity="info"):
        self.execute("INSERT INTO activity_log(event_type,category,message,severity) VALUES(?,?,?,?)",
                    (event_type,category,message,severity))

    def get_log(self, limit=50):
        return self.fetch_all("SELECT * FROM activity_log ORDER BY timestamp DESC LIMIT ?",(limit,))

    # ── Scan History ──
    def add_scan_record(self, iface, method, duration, found, new):
        self.execute("INSERT INTO scan_history(interface,method,duration,found,new_count) VALUES(?,?,?,?,?)",
                    (iface,method,duration,found,new))

    # ── Maintenance ──
    def backup(self):
        fname = f"bk_{datetime.now():%Y%m%d_%H%M%S}.db"
        dest = DB_PATH.parent.parent / "reports" / fname
        shutil.copy2(DB_PATH, dest)
        return str(dest)

    def close(self):
        self.conn.close()
