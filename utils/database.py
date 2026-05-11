"""
utils/database.py — SQLite database layer for PCGuard / SecureNova
"""
import sqlite3
import threading
import logging
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Any

logger = logging.getLogger(__name__)

DB_PATH = Path("data") / "securenova.db"


class DatabaseManager:
    """Thread-safe SQLite manager with connection pooling via threading.local."""

    _local = threading.local()

    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    # ------------------------------------------------------------------ #
    #  Connection helpers                                                   #
    # ------------------------------------------------------------------ #
    def _get_conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
            self._local.conn.row_factory = sqlite3.Row
            self._local.conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn.execute("PRAGMA foreign_keys=ON")
        return self._local.conn

    def _execute(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        conn = self._get_conn()
        try:
            cur = conn.execute(sql, params)
            conn.commit()
            return cur
        except Exception as e:
            conn.rollback()
            logger.error(f"DB error: {e} | SQL: {sql[:100]}")
            raise

    def _executemany(self, sql: str, data: List[tuple]) -> None:
        conn = self._get_conn()
        try:
            conn.executemany(sql, data)
            conn.commit()
        except Exception as e:
            conn.rollback()
            logger.error(f"DB executemany error: {e}")
            raise

    # ------------------------------------------------------------------ #
    #  Schema init                                                          #
    # ------------------------------------------------------------------ #
    def _init_db(self) -> None:
        conn = sqlite3.connect(str(self.db_path))
        conn.execute("PRAGMA journal_mode=WAL")
        cur = conn.cursor()

        cur.executescript("""
        CREATE TABLE IF NOT EXISTS threat_log (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp     TEXT    NOT NULL DEFAULT (datetime('now')),
            type          TEXT    NOT NULL,
            severity      TEXT    NOT NULL DEFAULT 'medium',
            path          TEXT,
            details       TEXT,
            action_taken  TEXT,
            read          INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS scan_history (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp  TEXT    NOT NULL DEFAULT (datetime('now')),
            path       TEXT    NOT NULL,
            result     TEXT    NOT NULL,
            engine     TEXT,
            file_hash  TEXT,
            threat_name TEXT
        );

        CREATE TABLE IF NOT EXISTS known_hashes (
            sha256      TEXT PRIMARY KEY,
            md5         TEXT,
            signature   TEXT,
            file_type   TEXT,
            source      TEXT,
            added_date  TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS blocked_domains (
            domain      TEXT PRIMARY KEY,
            source      TEXT,
            added_date  TEXT NOT NULL DEFAULT (datetime('now')),
            hits        INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS quarantine (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            original_path   TEXT NOT NULL,
            quarantine_path TEXT NOT NULL,
            timestamp       TEXT NOT NULL DEFAULT (datetime('now')),
            threat_name     TEXT,
            threat_type     TEXT,
            restored        INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS startup_baseline (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT    NOT NULL,
            path        TEXT,
            location    TEXT    NOT NULL,
            file_hash   TEXT,
            first_seen  TEXT    NOT NULL DEFAULT (datetime('now')),
            trusted     INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS process_baseline (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT    NOT NULL UNIQUE,
            path        TEXT,
            first_seen  TEXT    NOT NULL DEFAULT (datetime('now')),
            trusted     INTEGER NOT NULL DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS network_log (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp       TEXT NOT NULL DEFAULT (datetime('now')),
            pid             INTEGER,
            process_name    TEXT,
            local_addr      TEXT,
            remote_ip       TEXT,
            remote_host     TEXT,
            remote_port     INTEGER,
            protocol        TEXT,
            status          TEXT,
            risk_level      TEXT DEFAULT 'low'
        );

        CREATE TABLE IF NOT EXISTS vt_cache (
            sha256          TEXT PRIMARY KEY,
            malicious_count INTEGER DEFAULT 0,
            suspicious_count INTEGER DEFAULT 0,
            engine_results  TEXT,
            threat_label    TEXT,
            queried_at      TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE INDEX IF NOT EXISTS idx_threat_log_time  ON threat_log(timestamp);
        CREATE INDEX IF NOT EXISTS idx_scan_history_path ON scan_history(path);
        CREATE INDEX IF NOT EXISTS idx_known_hashes_md5  ON known_hashes(md5);
        CREATE INDEX IF NOT EXISTS idx_network_log_time  ON network_log(timestamp);

        -- App reputation scan results
        CREATE TABLE IF NOT EXISTS app_reputation_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_date TEXT NOT NULL DEFAULT (datetime('now')),
            app_name TEXT,
            publisher TEXT,
            install_date TEXT,
            exe_path TEXT,
            signature_status TEXT,
            suspicion_score INTEGER,
            risk_level TEXT,
            flags TEXT,
            vt_result TEXT,
            yara_match TEXT,
            recommended_action TEXT,
            user_action TEXT,
            action_date TEXT
        );

        -- Full scan run history
        CREATE TABLE IF NOT EXISTS full_scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT UNIQUE,
            scan_type TEXT,
            start_time TEXT,
            end_time TEXT,
            duration_seconds INTEGER,
            drives_scanned TEXT,
            total_files INTEGER,
            files_scanned INTEGER,
            files_skipped INTEGER,
            threats_found INTEGER,
            threats_cleaned INTEGER,
            status TEXT,
            report_json TEXT
        );

        -- Per-threat details from scans
        CREATE TABLE IF NOT EXISTS scan_threats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT,
            file_path TEXT,
            threat_name TEXT,
            severity TEXT,
            detection_engine TEXT,
            confidence INTEGER,
            action_taken TEXT,
            cleaned INTEGER DEFAULT 0,
            clean_timestamp TEXT,
            requires_reboot INTEGER DEFAULT 0,
            FOREIGN KEY (scan_id) REFERENCES full_scan_history(scan_id)
        );

        -- Memory scan results
        CREATE TABLE IF NOT EXISTS memory_scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_date TEXT NOT NULL DEFAULT (datetime('now')),
            pid INTEGER,
            process_name TEXT,
            exe_path TEXT,
            suspicious_strings TEXT,
            yara_match TEXT,
            risk_level TEXT,
            action_taken TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_app_rep_risk ON app_reputation_scans(risk_level);
        CREATE INDEX IF NOT EXISTS idx_full_scan_type ON full_scan_history(scan_type);
        CREATE INDEX IF NOT EXISTS idx_scan_threats_id ON scan_threats(scan_id);
        """)

        conn.commit()
        conn.close()
        logger.info(f"Database initialised at {self.db_path}")

    # ------------------------------------------------------------------ #
    #  Threat log                                                           #
    # ------------------------------------------------------------------ #
    def log_threat(self, type_: str, severity: str, path: str = "",
                   details: str = "", action: str = "") -> int:
        cur = self._execute(
            "INSERT INTO threat_log (type, severity, path, details, action_taken) VALUES (?,?,?,?,?)",
            (type_, severity, path, details, action)
        )
        return cur.lastrowid

    def get_threats(self, limit: int = 100, unread_only: bool = False) -> List[Dict]:
        sql = "SELECT * FROM threat_log"
        if unread_only:
            sql += " WHERE read=0"
        sql += " ORDER BY timestamp DESC LIMIT ?"
        return [dict(r) for r in self._execute(sql, (limit,)).fetchall()]

    def mark_threats_read(self) -> None:
        self._execute("UPDATE threat_log SET read=1 WHERE read=0")

    def get_unread_count(self) -> int:
        return self._execute("SELECT COUNT(*) FROM threat_log WHERE read=0").fetchone()[0]

    # ------------------------------------------------------------------ #
    #  Scan history                                                         #
    # ------------------------------------------------------------------ #
    def log_scan(self, path: str, result: str, engine: str = "",
                 file_hash: str = "", threat_name: str = "") -> None:
        self._execute(
            "INSERT INTO scan_history (path, result, engine, file_hash, threat_name) VALUES (?,?,?,?,?)",
            (path, result, engine, file_hash, threat_name)
        )

    def get_scan_history(self, limit: int = 200) -> List[Dict]:
        return [dict(r) for r in self._execute(
            "SELECT * FROM scan_history ORDER BY timestamp DESC LIMIT ?", (limit,)
        ).fetchall()]

    def get_scan_stats(self) -> Dict:
        today = datetime.now().strftime("%Y-%m-%d")
        total = self._execute("SELECT COUNT(*) FROM scan_history").fetchone()[0]
        today_threats = self._execute(
            "SELECT COUNT(*) FROM threat_log WHERE timestamp LIKE ?", (f"{today}%",)
        ).fetchone()[0]
        blocked = self._execute("SELECT COUNT(*) FROM blocked_domains").fetchone()[0]
        return {"total_scanned": total, "threats_today": today_threats, "blocked_domains": blocked}

    # ------------------------------------------------------------------ #
    #  Known hashes                                                         #
    # ------------------------------------------------------------------ #
    def hash_exists(self, sha256: str = "", md5: str = "") -> Optional[Dict]:
        if sha256:
            row = self._execute("SELECT * FROM known_hashes WHERE sha256=?", (sha256,)).fetchone()
        elif md5:
            row = self._execute("SELECT * FROM known_hashes WHERE md5=?", (md5,)).fetchone()
        else:
            return None
        return dict(row) if row else None

    def bulk_insert_hashes(self, hashes: List[Dict]) -> int:
        data = [(h.get("sha256", ""), h.get("md5", ""), h.get("signature", ""),
                 h.get("file_type", ""), h.get("source", "MalwareBazaar"))
                for h in hashes if h.get("sha256")]
        self._executemany(
            "INSERT OR IGNORE INTO known_hashes (sha256,md5,signature,file_type,source) VALUES (?,?,?,?,?)",
            data
        )
        return len(data)

    def get_hash_count(self) -> int:
        return self._execute("SELECT COUNT(*) FROM known_hashes").fetchone()[0]

    # ------------------------------------------------------------------ #
    #  Blocked domains                                                      #
    # ------------------------------------------------------------------ #
    def bulk_insert_domains(self, domains: List[str], source: str = "feed") -> int:
        data = [(d, source) for d in domains if d]
        self._executemany(
            "INSERT OR IGNORE INTO blocked_domains (domain, source) VALUES (?,?)", data
        )
        return len(data)

    def is_domain_blocked(self, domain: str) -> bool:
        row = self._execute("SELECT 1 FROM blocked_domains WHERE domain=?", (domain,)).fetchone()
        if row:
            self._execute("UPDATE blocked_domains SET hits=hits+1 WHERE domain=?", (domain,))
            return True
        return False

    def get_blocked_domains(self, limit: int = 500) -> List[Dict]:
        return [dict(r) for r in self._execute(
            "SELECT * FROM blocked_domains ORDER BY hits DESC LIMIT ?", (limit,)
        ).fetchall()]

    def add_custom_domain(self, domain: str) -> None:
        self._execute(
            "INSERT OR IGNORE INTO blocked_domains (domain, source) VALUES (?, 'custom')", (domain,)
        )

    def remove_domain(self, domain: str) -> None:
        self._execute("DELETE FROM blocked_domains WHERE domain=?", (domain,))

    # ------------------------------------------------------------------ #
    #  Quarantine                                                           #
    # ------------------------------------------------------------------ #
    def add_quarantine_entry(self, original: str, quarantined: str,
                              threat_name: str = "", threat_type: str = "") -> int:
        cur = self._execute(
            "INSERT INTO quarantine (original_path, quarantine_path, threat_name, threat_type) VALUES (?,?,?,?)",
            (original, quarantined, threat_name, threat_type)
        )
        return cur.lastrowid

    def get_quarantine(self) -> List[Dict]:
        return [dict(r) for r in self._execute(
            "SELECT * FROM quarantine WHERE restored=0 ORDER BY timestamp DESC"
        ).fetchall()]

    def mark_restored(self, id_: int) -> None:
        self._execute("UPDATE quarantine SET restored=1 WHERE id=?", (id_,))

    # ------------------------------------------------------------------ #
    #  Startup baseline                                                     #
    # ------------------------------------------------------------------ #
    def snapshot_startup_item(self, name: str, path: str, location: str,
                               file_hash: str = "") -> None:
        self._execute(
            "INSERT OR IGNORE INTO startup_baseline (name,path,location,file_hash) VALUES (?,?,?,?)",
            (name, path, location, file_hash)
        )

    def get_startup_baseline(self) -> List[Dict]:
        return [dict(r) for r in self._execute("SELECT * FROM startup_baseline").fetchall()]

    def startup_item_known(self, name: str, location: str) -> bool:
        row = self._execute(
            "SELECT 1 FROM startup_baseline WHERE name=? AND location=?", (name, location)
        ).fetchone()
        return row is not None

    # ------------------------------------------------------------------ #
    #  Process baseline                                                     #
    # ------------------------------------------------------------------ #
    def snapshot_process(self, name: str, path: str = "") -> None:
        self._execute(
            "INSERT OR IGNORE INTO process_baseline (name, path) VALUES (?,?)", (name, path)
        )

    def is_process_trusted(self, name: str) -> bool:
        row = self._execute(
            "SELECT trusted FROM process_baseline WHERE name=?", (name,)
        ).fetchone()
        return bool(row and row[0])

    def trust_process(self, name: str, path: str = "") -> None:
        self._execute(
            "INSERT OR REPLACE INTO process_baseline (name, path, trusted) VALUES (?,?,1)", (name, path)
        )

    # ------------------------------------------------------------------ #
    #  Network log                                                          #
    # ------------------------------------------------------------------ #
    def log_connection(self, pid: int, process_name: str, local_addr: str,
                       remote_ip: str, remote_host: str, remote_port: int,
                       protocol: str, status: str, risk: str = "low") -> None:
        self._execute(
            """INSERT INTO network_log
               (pid,process_name,local_addr,remote_ip,remote_host,remote_port,protocol,status,risk_level)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (pid, process_name, local_addr, remote_ip, remote_host,
             remote_port, protocol, status, risk)
        )

    def get_network_log(self, limit: int = 200) -> List[Dict]:
        return [dict(r) for r in self._execute(
            "SELECT * FROM network_log ORDER BY timestamp DESC LIMIT ?", (limit,)
        ).fetchall()]

    # ------------------------------------------------------------------ #
    #  VirusTotal cache                                                     #
    # ------------------------------------------------------------------ #
    def get_vt_cache(self, sha256: str) -> Optional[Dict]:
        row = self._execute("SELECT * FROM vt_cache WHERE sha256=?", (sha256,)).fetchone()
        return dict(row) if row else None

    def save_vt_result(self, sha256: str, malicious: int, suspicious: int,
                        engines: str, label: str) -> None:
        self._execute(
            """INSERT OR REPLACE INTO vt_cache
               (sha256,malicious_count,suspicious_count,engine_results,threat_label)
               VALUES (?,?,?,?,?)""",
            (sha256, malicious, suspicious, engines, label)
        )

    # ------------------------------------------------------------------ #
    #  App reputation scans                                                 #
    # ------------------------------------------------------------------ #
    def save_app_scan(self, results_list: List[Dict]) -> None:
        """Save a batch of app reputation scan results."""
        import json as _json
        data = [
            (r.get("app_name", ""), r.get("publisher", ""),
             r.get("install_date", ""), r.get("exe_path", ""),
             r.get("signature_status", ""), r.get("suspicion_score", 0),
             r.get("risk_level", ""), _json.dumps(r.get("flags", [])),
             _json.dumps(r.get("vt_result")) if r.get("vt_result") else None,
             r.get("yara_match"), r.get("recommended_action", ""))
            for r in results_list
        ]
        self._executemany(
            """INSERT INTO app_reputation_scans
               (app_name,publisher,install_date,exe_path,signature_status,
                suspicion_score,risk_level,flags,vt_result,yara_match,recommended_action)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            data
        )

    def get_app_scan_results(self, risk_level_filter: Optional[str] = None) -> List[Dict]:
        """Get app reputation scan results with optional risk filter."""
        sql = "SELECT * FROM app_reputation_scans"
        params = ()
        if risk_level_filter:
            sql += " WHERE risk_level=?"
            params = (risk_level_filter,)
        sql += " ORDER BY suspicion_score DESC"
        return [dict(r) for r in self._execute(sql, params).fetchall()]

    def update_app_user_action(self, app_id: int, action: str) -> None:
        """Record user action on a flagged app."""
        self._execute(
            "UPDATE app_reputation_scans SET user_action=?, action_date=datetime('now') WHERE id=?",
            (action, app_id)
        )

    # ------------------------------------------------------------------ #
    #  Full scan history                                                    #
    # ------------------------------------------------------------------ #
    def save_scan_run(self, report: Dict) -> str:
        """Save a scan run report. Returns the scan_id."""
        import json as _json
        scan_id = report.get("scan_id", "")
        self._execute(
            """INSERT OR REPLACE INTO full_scan_history
               (scan_id,scan_type,start_time,end_time,duration_seconds,
                drives_scanned,total_files,files_scanned,files_skipped,
                threats_found,threats_cleaned,status,report_json)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (scan_id, report.get("scan_type", ""),
             report.get("start_time", ""), report.get("end_time", ""),
             report.get("duration_seconds", 0),
             _json.dumps(report.get("drives_scanned", [])),
             report.get("total_files", 0), report.get("files_scanned", 0),
             report.get("files_skipped", 0), report.get("threats_found", 0),
             report.get("threats_cleaned", 0), report.get("scan_status", ""),
             _json.dumps(report))
        )
        # Save individual threats
        for threat in report.get("threat_list", []):
            self.save_scan_threat(scan_id, threat)
        return scan_id

    def get_full_scan_history(self, limit: int = 30) -> List[Dict]:
        """Get recent scan run history."""
        return [dict(r) for r in self._execute(
            "SELECT * FROM full_scan_history ORDER BY start_time DESC LIMIT ?", (limit,)
        ).fetchall()]

    def get_scan_report(self, scan_id: str) -> Optional[Dict]:
        """Get a full scan report by scan_id."""
        import json as _json
        row = self._execute(
            "SELECT report_json FROM full_scan_history WHERE scan_id=?", (scan_id,)
        ).fetchone()
        if row:
            try:
                return _json.loads(row[0])
            except Exception:
                return None
        return None

    # ------------------------------------------------------------------ #
    #  Scan threats                                                         #
    # ------------------------------------------------------------------ #
    def save_scan_threat(self, scan_id: str, threat: Dict) -> None:
        """Save a single threat record linked to a scan."""
        self._execute(
            """INSERT INTO scan_threats
               (scan_id,file_path,threat_name,severity,detection_engine,
                confidence,action_taken,cleaned,requires_reboot)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (scan_id, threat.get("path", ""), threat.get("threat_name", ""),
             threat.get("severity", ""), threat.get("engine", ""),
             threat.get("confidence", 0), threat.get("action", ""),
             1 if threat.get("cleaned") else 0,
             1 if threat.get("requires_reboot") else 0)
        )

    def get_scan_threats(self, scan_id: str) -> List[Dict]:
        """Get all threats for a specific scan."""
        return [dict(r) for r in self._execute(
            "SELECT * FROM scan_threats WHERE scan_id=? ORDER BY severity DESC", (scan_id,)
        ).fetchall()]

    def mark_threat_cleaned(self, threat_id: int) -> None:
        """Mark a threat as cleaned."""
        self._execute(
            "UPDATE scan_threats SET cleaned=1, clean_timestamp=datetime('now') WHERE id=?",
            (threat_id,)
        )

    def get_threat_stats_by_type(self) -> Dict:
        """Get threat counts grouped by detection engine."""
        rows = self._execute(
            "SELECT detection_engine, COUNT(*) as cnt FROM scan_threats GROUP BY detection_engine"
        ).fetchall()
        return {r["detection_engine"]: r["cnt"] for r in rows}

    # ------------------------------------------------------------------ #
    #  Enhanced scan stats                                                  #
    # ------------------------------------------------------------------ #
    def get_enhanced_scan_stats(self) -> Dict:
        """Extended stats including new tables."""
        base = self.get_scan_stats()
        try:
            cleaned_today = self._execute(
                "SELECT COUNT(*) FROM scan_threats WHERE cleaned=1 AND "
                "clean_timestamp LIKE ?",
                (datetime.now().strftime("%Y-%m-%d") + "%",)
            ).fetchone()[0]
            base["threats_cleaned_today"] = cleaned_today
        except Exception:
            base["threats_cleaned_today"] = 0
        try:
            total_scans = self._execute(
                "SELECT COUNT(*) FROM full_scan_history"
            ).fetchone()[0]
            base["total_scan_runs"] = total_scans
        except Exception:
            base["total_scan_runs"] = 0
        return base


# Global singleton
_db_instance: Optional[DatabaseManager] = None


def get_db() -> DatabaseManager:
    global _db_instance
    if _db_instance is None:
        _db_instance = DatabaseManager()
    return _db_instance
