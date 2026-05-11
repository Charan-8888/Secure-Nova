"""
utils/scan_cache.py — mtime+size based scan result cache

Avoids re-scanning unchanged files. Cache entries are invalidated when
a file's mtime or size changes.
"""
import logging
import os
import sqlite3
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict

logger = logging.getLogger(__name__)

CACHE_DB = Path("data") / "scan_cache.db"
DEFAULT_VALIDITY_DAYS = 7


class ScanCache:
    """Thread-safe file scan result cache backed by SQLite."""

    _local = threading.local()

    def __init__(self, db_path: Path = CACHE_DB, validity_days: int = DEFAULT_VALIDITY_DAYS):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.validity_days = validity_days
        self._init_db()
        self._stats = {"hits": 0, "misses": 0}

    def _get_conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
            self._local.conn.row_factory = sqlite3.Row
            self._local.conn.execute("PRAGMA journal_mode=WAL")
        return self._local.conn

    def _init_db(self):
        conn = self._get_conn()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_cache (
                path       TEXT PRIMARY KEY,
                mtime      REAL NOT NULL,
                size       INTEGER NOT NULL,
                sha256     TEXT,
                result     TEXT NOT NULL DEFAULT 'clean',
                threat_name TEXT DEFAULT '',
                engine     TEXT DEFAULT '',
                confidence INTEGER DEFAULT 0,
                cached_at  TEXT NOT NULL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_cache_cached ON scan_cache(cached_at)")
        conn.commit()

    def is_cached(self, file_path: str) -> Optional[Dict]:
        """Check if a file has a valid cache entry.
        Returns cached result dict if valid, None if cache miss."""
        try:
            stat = os.stat(file_path)
        except OSError:
            return None

        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM scan_cache WHERE path = ?", (file_path,)
        ).fetchone()

        if not row:
            self._stats["misses"] += 1
            return None

        # Check mtime + size match
        if abs(row["mtime"] - stat.st_mtime) > 0.01 or row["size"] != stat.st_size:
            self._stats["misses"] += 1
            return None

        # Check age
        try:
            cached_at = datetime.fromisoformat(row["cached_at"])
            if datetime.now() - cached_at > timedelta(days=self.validity_days):
                self._stats["misses"] += 1
                return None
        except (ValueError, TypeError):
            self._stats["misses"] += 1
            return None

        self._stats["hits"] += 1
        return {
            "path": row["path"],
            "result": row["result"],
            "sha256": row["sha256"],
            "threat_name": row["threat_name"] or "",
            "engine": row["engine"] or "",
            "confidence": row["confidence"] or 0,
            "cached": True,
        }

    def store(self, file_path: str, result: str, sha256: str = "",
              threat_name: str = "", engine: str = "", confidence: int = 0) -> None:
        """Store a scan result in cache."""
        try:
            stat = os.stat(file_path)
        except OSError:
            return

        conn = self._get_conn()
        try:
            conn.execute("""
                INSERT OR REPLACE INTO scan_cache
                (path, mtime, size, sha256, result, threat_name, engine, confidence, cached_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (file_path, stat.st_mtime, stat.st_size, sha256, result,
                  threat_name, engine, confidence, datetime.now().isoformat()))
            conn.commit()
        except Exception as e:
            logger.error(f"Cache store error: {e}")

    def invalidate(self, file_path: str) -> None:
        """Remove a specific cache entry."""
        conn = self._get_conn()
        conn.execute("DELETE FROM scan_cache WHERE path = ?", (file_path,))
        conn.commit()

    def invalidate_older_than(self, days: int) -> int:
        """Remove entries older than N days. Returns count removed."""
        cutoff = (datetime.now() - timedelta(days=days)).isoformat()
        conn = self._get_conn()
        cursor = conn.execute("DELETE FROM scan_cache WHERE cached_at < ?", (cutoff,))
        conn.commit()
        return cursor.rowcount

    def clear(self) -> None:
        """Clear entire cache."""
        conn = self._get_conn()
        conn.execute("DELETE FROM scan_cache")
        conn.commit()

    def get_stats(self) -> Dict:
        """Return cache hit/miss stats."""
        total = self._stats["hits"] + self._stats["misses"]
        hit_rate = (self._stats["hits"] / max(total, 1)) * 100
        conn = self._get_conn()
        size = conn.execute("SELECT COUNT(*) FROM scan_cache").fetchone()[0]
        return {
            "hits": self._stats["hits"],
            "misses": self._stats["misses"],
            "hit_rate": round(hit_rate, 1),
            "cached_files": size,
        }
