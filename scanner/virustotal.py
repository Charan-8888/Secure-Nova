"""
scanner/virustotal.py — VirusTotal API v3 integration with rate limiting & caching
"""
import hashlib
import json
import logging
import os
import time
import threading
from pathlib import Path
from typing import Optional, Dict

import requests

logger = logging.getLogger(__name__)

VT_API_BASE = "https://www.virustotal.com/api/v3"

SENSITIVE_EXTENSIONS = {".docx", ".xlsx", ".pdf", ".doc", ".xls", ".pptx", ".ppt"}


class VirusTotalChecker:
    """
    Rate-limited VirusTotal API client.
    Free tier: 500 lookups/day, 4 requests/minute → 15 seconds between calls.
    """

    def __init__(self, api_key: str, db=None, rate_limit_seconds: float = 15.0,
                 malicious_threshold: int = 3):
        self.api_key = api_key
        self.db = db
        self.rate_limit = rate_limit_seconds
        self.threshold = malicious_threshold
        self._last_call = 0.0
        self._lock = threading.Lock()

    @property
    def _headers(self) -> dict:
        return {"x-apikey": self.api_key, "Accept": "application/json"}

    def _rate_wait(self) -> None:
        with self._lock:
            elapsed = time.time() - self._last_call
            if elapsed < self.rate_limit:
                time.sleep(self.rate_limit - elapsed)
            self._last_call = time.time()

    # ------------------------------------------------------------------ #
    #  Hash lookup                                                          #
    # ------------------------------------------------------------------ #
    def check_hash(self, sha256: str) -> Optional[Dict]:
        if not self.api_key:
            return None

        # Check cache first
        if self.db:
            cached = self.db.get_vt_cache(sha256)
            if cached:
                logger.debug(f"VT cache hit: {sha256[:16]}…")
                return cached

        self._rate_wait()
        try:
            url = f"{VT_API_BASE}/files/{sha256}"
            resp = requests.get(url, headers=self._headers, timeout=30)

            if resp.status_code == 404:
                return None
            if resp.status_code == 429:
                logger.warning("VT rate limit hit — waiting 60s")
                time.sleep(60)
                return None
            resp.raise_for_status()

            data = resp.json()
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            results = attrs.get("last_analysis_results", {})
            label = attrs.get("popular_threat_classification", {}).get("suggested_threat_label", "")

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            engines_str = json.dumps(results)

            result = {
                "sha256": sha256,
                "malicious_count": malicious,
                "suspicious_count": suspicious,
                "engine_results": engines_str,
                "threat_label": label
            }

            if self.db:
                self.db.save_vt_result(sha256, malicious, suspicious, engines_str, label)

            return result
        except Exception as e:
            logger.error(f"VT check_hash error: {e}")
            return None

    # ------------------------------------------------------------------ #
    #  File submission                                                      #
    # ------------------------------------------------------------------ #
    def submit_file(self, path: str, max_size_mb: int = 32) -> Optional[Dict]:
        if not self.api_key:
            return None

        p = Path(path)
        if p.suffix.lower() in SENSITIVE_EXTENSIONS:
            logger.warning(f"Skipping sensitive file type: {p.suffix}")
            return None

        size_mb = p.stat().st_size / (1024 * 1024)
        if size_mb > max_size_mb:
            logger.warning(f"File too large for VT: {size_mb:.1f} MB")
            return None

        self._rate_wait()
        try:
            with open(path, "rb") as f:
                resp = requests.post(
                    f"{VT_API_BASE}/files",
                    headers=self._headers,
                    files={"file": (p.name, f)},
                    timeout=120
                )
            resp.raise_for_status()
            analysis_id = resp.json().get("data", {}).get("id", "")
            if analysis_id:
                return self._poll_analysis(analysis_id)
        except Exception as e:
            logger.error(f"VT submit_file error: {e}")
        return None

    def _poll_analysis(self, analysis_id: str, max_retries: int = 10) -> Optional[Dict]:
        url = f"{VT_API_BASE}/analyses/{analysis_id}"
        for attempt in range(max_retries):
            delay = min(15 * (2 ** attempt), 120)
            time.sleep(delay)
            try:
                resp = requests.get(url, headers=self._headers, timeout=30)
                resp.raise_for_status()
                data = resp.json().get("data", {})
                if data.get("attributes", {}).get("status") == "completed":
                    stats = data["attributes"].get("stats", {})
                    return {
                        "malicious_count": stats.get("malicious", 0),
                        "suspicious_count": stats.get("suspicious", 0),
                        "engine_results": json.dumps(data["attributes"].get("results", {})),
                        "threat_label": ""
                    }
            except Exception as e:
                logger.error(f"VT poll error: {e}")
        return None

    # ------------------------------------------------------------------ #
    #  Convenience: check file by hash, submit if unknown                   #
    # ------------------------------------------------------------------ #
    def check_file(self, path: str) -> Optional[Dict]:
        sha256 = self._sha256(path)
        if not sha256:
            return None
        result = self.check_hash(sha256)
        if result is None:
            result = self.submit_file(path)
        return result

    @staticmethod
    def _sha256(path: str) -> str:
        h = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return ""

    def is_malicious(self, vt_result: Dict) -> bool:
        if not vt_result:
            return False
        return vt_result.get("malicious_count", 0) >= self.threshold
