#!/usr/bin/env python3
"""Thread-safe SQLite database for WPS Toolkit"""

import json
import sqlite3
import threading
import shutil
from datetime import datetime
from config import DB_PATH

WPS_PIN_DB_PATH = DB_PATH.parent / "wps_pin_database.json"

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
    CREATE TABLE IF NOT EXISTS intelligence_meta(
        key TEXT PRIMARY KEY,
        value TEXT,
        updated_at TEXT DEFAULT (datetime('now','localtime'))
    );
    CREATE TABLE IF NOT EXISTS wps_pin_database(
        prefix TEXT NOT NULL,
        pin TEXT NOT NULL,
        source TEXT NOT NULL,
        confidence INTEGER DEFAULT 80,
        version TEXT,
        PRIMARY KEY(prefix,pin,source)
    );
    CREATE INDEX IF NOT EXISTS idx_wps_pin_prefix
        ON wps_pin_database(prefix);
    CREATE TABLE IF NOT EXISTS target_assessments(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        bssid TEXT NOT NULL,
        essid TEXT,
        assessed_at TEXT DEFAULT (datetime('now','localtime')),
        channel INTEGER DEFAULT 0,
        rssi INTEGER DEFAULT 0,
        encryption TEXT,
        has_wps INTEGER DEFAULT 0,
        wps_locked TEXT,
        manufacturer TEXT,
        model TEXT,
        known_pin_count INTEGER DEFAULT 0,
        best_pin TEXT,
        pixie_candidate INTEGER DEFAULT 0,
        pmkid_candidate INTEGER DEFAULT 0,
        passive_candidate INTEGER DEFAULT 0,
        readiness_score INTEGER DEFAULT 0,
        recommended_method TEXT,
        warnings TEXT,
        intelligence_version TEXT,
        report_json TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_assessment_bssid_time
        ON target_assessments(bssid,assessed_at DESC);
    CREATE TABLE IF NOT EXISTS wps_pin_attempts(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        bssid TEXT NOT NULL,
        pin TEXT NOT NULL,
        attempted_at TEXT DEFAULT (datetime('now','localtime')),
        status TEXT,
        response TEXT,
        duration REAL DEFAULT 0,
        session_id INTEGER,
        UNIQUE(bssid,pin)
    );
    CREATE INDEX IF NOT EXISTS idx_wps_attempt_bssid
        ON wps_pin_attempts(bssid,attempted_at DESC);
    """

    def __init__(self):
        self.conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.lock = threading.Lock()
        with self.lock:
            cur = self.conn.cursor()
            cur.executescript(self.SCHEMA)
            self.conn.commit()
        self.sync_wps_intelligence()

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

    # ── WPS Intelligence ──
    def sync_wps_intelligence(self):
        """Import the bundled versioned OUI/PIN snapshot into SQLite."""
        try:
            with open(WPS_PIN_DB_PATH, "r") as handle:
                payload = json.load(handle)
        except (OSError, ValueError, TypeError):
            return {"status": "unavailable", "prefixes": 0, "pins": 0}

        version = str(payload.get("database_version", "unknown"))
        source_data = payload.get("source", {})
        source_name = str(source_data.get("name", "bundled_wps_db"))
        prefixes = payload.get("prefixes", {})
        rows = []
        if isinstance(prefixes, dict):
            for prefix, pins in prefixes.items():
                clean_prefix = str(prefix).replace(":", "").upper()[:6]
                if len(clean_prefix) != 6:
                    continue
                for index, pin in enumerate(pins if isinstance(pins, list) else []):
                    pin_text = str(pin)
                    if not pin_text.isdigit() or len(pin_text) != 8:
                        continue
                    confidence = max(70, 90 - index)
                    rows.append((clean_prefix, pin_text, source_name, confidence, version))

        with self.lock:
            cur = self.conn.cursor()
            cur.execute(
                "SELECT value FROM intelligence_meta WHERE key='wps_database_version'"
            )
            current = cur.fetchone()
            cur.execute("SELECT COUNT(*) c FROM wps_pin_database")
            current_count = cur.fetchone()["c"]
            if current and current["value"] == version and current_count == len(rows):
                return {
                    "status": "current",
                    "version": version,
                    "prefixes": len(prefixes),
                    "pins": len(rows),
                }

            cur.execute("DELETE FROM wps_pin_database")
            cur.executemany(
                """INSERT OR REPLACE INTO wps_pin_database
                   (prefix,pin,source,confidence,version) VALUES(?,?,?,?,?)""",
                rows,
            )
            metadata = {
                "wps_database_version": version,
                "wps_database_source": source_name,
                "wps_database_prefixes": str(len(prefixes)),
                "wps_database_pins": str(len(rows)),
            }
            for key, value in metadata.items():
                cur.execute(
                    """INSERT OR REPLACE INTO intelligence_meta(key,value,updated_at)
                       VALUES(?,?,datetime('now','localtime'))""",
                    (key, value),
                )
            self.conn.commit()

        return {
            "status": "updated",
            "version": version,
            "prefixes": len(prefixes),
            "pins": len(rows),
        }

    def get_intelligence_stats(self):
        with self.lock:
            cur = self.conn.cursor()
            cur.execute("SELECT key,value FROM intelligence_meta")
            metadata = {row["key"]: row["value"] for row in cur.fetchall()}
            cur.execute("SELECT COUNT(DISTINCT prefix) c FROM wps_pin_database")
            prefix_count = cur.fetchone()["c"]
            cur.execute("SELECT COUNT(*) c FROM wps_pin_database")
            pin_count = cur.fetchone()["c"]
        return {
            "version": metadata.get("wps_database_version", "unavailable"),
            "source": metadata.get("wps_database_source", ""),
            "prefixes": prefix_count,
            "pins": pin_count,
        }

    def get_known_wps_pins(self, bssid, limit=16):
        prefix = (bssid or "").replace(":", "").replace("-", "").upper()[:6]
        return self.fetch_all(
            """SELECT pin,source,confidence,version FROM wps_pin_database
               WHERE prefix=? ORDER BY confidence DESC,pin LIMIT ?""",
            (prefix, int(limit)),
        )

    # ── Target Assessments ──
    def save_assessment(self, report):
        warnings = report.get("warnings", [])
        warnings_text = json.dumps(warnings, ensure_ascii=False)
        report_text = json.dumps(report, ensure_ascii=False, sort_keys=True)
        cur = self.execute(
            """INSERT INTO target_assessments(
               bssid,essid,channel,rssi,encryption,has_wps,wps_locked,
               manufacturer,model,known_pin_count,best_pin,pixie_candidate,
               pmkid_candidate,passive_candidate,readiness_score,
               recommended_method,warnings,intelligence_version,report_json
               ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                report.get("bssid"), report.get("essid"), report.get("channel", 0),
                report.get("rssi", 0), report.get("encryption", ""),
                1 if report.get("has_wps") else 0, report.get("wps_locked", "Unknown"),
                report.get("manufacturer", "Unknown"), report.get("model", ""),
                report.get("known_pin_count", 0), report.get("best_pin", ""),
                1 if report.get("pixie_candidate") else 0,
                1 if report.get("pmkid_candidate") else 0,
                1 if report.get("passive_candidate") else 0,
                report.get("readiness_score", 0),
                report.get("recommended_method", ""), warnings_text,
                report.get("intelligence_version", ""), report_text,
            ),
        )
        return cur.lastrowid

    def get_latest_assessment(self, bssid):
        return self.fetch_one(
            """SELECT * FROM target_assessments WHERE bssid=?
               ORDER BY assessed_at DESC,id DESC LIMIT 1""",
            (bssid,),
        )

    # ── WPS Attempt Resume State ──
    def record_wps_attempt(self, bssid, pin, status, response="", duration=0, session_id=None):
        self.execute(
            """INSERT OR REPLACE INTO wps_pin_attempts
               (bssid,pin,attempted_at,status,response,duration,session_id)
               VALUES(?,?,datetime('now','localtime'),?,?,?,?)""",
            (bssid, pin, status, response, float(duration), session_id),
        )

    def get_attempted_wps_pins(self, bssid):
        rows = self.fetch_all(
            "SELECT pin FROM wps_pin_attempts WHERE bssid=? ORDER BY attempted_at",
            (bssid,),
        )
        return {row["pin"] for row in rows}

    def get_wps_attempt_progress(self, bssid):
        total = self.fetch_one(
            "SELECT COUNT(*) c FROM wps_pin_attempts WHERE bssid=?",
            (bssid,),
        )["c"]
        latest = self.fetch_one(
            """SELECT pin,status,attempted_at FROM wps_pin_attempts
               WHERE bssid=? ORDER BY attempted_at DESC,id DESC LIMIT 1""",
            (bssid,),
        )
        return {"attempted": total, "latest": dict(latest) if latest else None}

    # ── Maintenance ──
    def backup(self):
        fname = f"bk_{datetime.now():%Y%m%d_%H%M%S}.db"
        dest = DB_PATH.parent.parent / "reports" / fname
        shutil.copy2(DB_PATH, dest)
        return str(dest)

    def close(self):
        with self.lock:
            self.conn.close()
