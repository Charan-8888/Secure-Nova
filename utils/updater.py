"""
utils/updater.py — Background updater for YARA rules, blocklists, and hashes
"""
import logging
import threading
import time
import requests
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional

logger = logging.getLogger(__name__)

YARA_RULES_INDEX = "https://api.github.com/repos/Yara-Rules/rules/git/trees/master?recursive=1"
YARA_RAW_BASE = "https://raw.githubusercontent.com/Yara-Rules/rules/master/"
URLHAUS_HOSTS = "https://urlhaus.abuse.ch/downloads/hostfile/"
MALWARE_DOMAINS_HOSTS = "https://malware-filter.pages.dev/hosts.txt"
MALWAREBAZAAR_API = "https://mb-api.abuse.ch/api/v1/"


class Updater:
    """Handles scheduled updates in background threads."""

    def __init__(self, config: dict, db=None):
        self.config = config
        self.db = db
        self._stop_event = threading.Event()
        self._threads: list[threading.Thread] = []

    def start(self) -> None:
        tasks = [
            (self._hash_updater_loop, "HashUpdater"),
            (self._blocklist_updater_loop, "BlocklistUpdater"),
            (self._yara_updater_loop, "YaraUpdater"),
        ]
        for fn, name in tasks:
            t = threading.Thread(target=fn, name=name, daemon=True)
            t.start()
            self._threads.append(t)
        logger.info("Updater started all background tasks")

    def stop(self) -> None:
        self._stop_event.set()

    # ------------------------------------------------------------------ #
    #  MalwareBazaar hash feed                                              #
    # ------------------------------------------------------------------ #
    def _hash_updater_loop(self) -> None:
        interval = self.config.get("hash_db_refresh_hours", 24) * 3600
        while not self._stop_event.is_set():
            try:
                self.update_hashes()
            except Exception as e:
                logger.error(f"Hash update failed: {e}")
            self._stop_event.wait(interval)

    def update_hashes(self) -> int:
        logger.info("Fetching hashes from MalwareBazaar…")
        try:
            resp = requests.post(MALWAREBAZAAR_API, data={"query": "get_recent", "selector": "100"},
                                 timeout=30)
            resp.raise_for_status()
            data = resp.json()
            if data.get("query_status") != "ok":
                logger.warning(f"MalwareBazaar returned: {data.get('query_status')}")
                return 0
            hashes = data.get("data", [])
            rows = [{
                "sha256": h.get("sha256_hash", ""),
                "md5": h.get("md5_hash", ""),
                "signature": h.get("signature") or "",
                "file_type": h.get("file_type", ""),
                "source": "MalwareBazaar"
            } for h in hashes]
            if self.db:
                added = self.db.bulk_insert_hashes(rows)
                logger.info(f"Added {added} hashes to DB")
                return added
        except Exception as e:
            logger.error(f"MalwareBazaar fetch error: {e}")
        return 0

    # ------------------------------------------------------------------ #
    #  Domain blocklist feeds                                               #
    # ------------------------------------------------------------------ #
    def _blocklist_updater_loop(self) -> None:
        interval = self.config.get("blocklist_refresh_hours", 6) * 3600
        while not self._stop_event.is_set():
            try:
                self.update_blocklists()
            except Exception as e:
                logger.error(f"Blocklist update failed: {e}")
            self._stop_event.wait(interval)

    def update_blocklists(self) -> int:
        total = 0
        feeds = [
            (URLHAUS_HOSTS, "URLhaus"),
            (MALWARE_DOMAINS_HOSTS, "MalwareDomains"),
        ]
        for url, source in feeds:
            try:
                resp = requests.get(url, timeout=30)
                resp.raise_for_status()
                domains = self._parse_hosts_file(resp.text)
                if self.db and domains:
                    added = self.db.bulk_insert_domains(domains, source)
                    total += added
                    logger.info(f"[{source}] Added {added} domains")
            except Exception as e:
                logger.error(f"Blocklist fetch failed ({source}): {e}")
        return total

    @staticmethod
    def _parse_hosts_file(content: str) -> list[str]:
        domains = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1"):
                d = parts[1].lower()
                if d not in ("localhost", "0.0.0.0", "broadcasthost") and "." in d:
                    domains.append(d)
        return domains

    # ------------------------------------------------------------------ #
    #  YARA rules updater                                                   #
    # ------------------------------------------------------------------ #
    def _yara_updater_loop(self) -> None:
        # Run once at startup, then daily
        try:
            self.update_yara_rules()
        except Exception as e:
            logger.error(f"YARA update failed: {e}")
        interval = 86400  # 24h
        while not self._stop_event.is_set():
            self._stop_event.wait(interval)
            try:
                self.update_yara_rules()
            except Exception as e:
                logger.error(f"YARA update failed: {e}")

    def update_yara_rules(self, rules_dir: str = "rules") -> None:
        rules_path = Path(rules_dir)
        rules_path.mkdir(parents=True, exist_ok=True)
        logger.info("Checking YARA rules from GitHub…")
        try:
            resp = requests.get(YARA_RULES_INDEX, timeout=30)
            resp.raise_for_status()
            tree = resp.json().get("tree", [])
            yar_files = [item for item in tree
                         if item["path"].endswith(".yar") and item["type"] == "blob"]
            updated = 0
            for item in yar_files[:50]:  # limit to 50 files on auto-update
                rel_path = item["path"]
                local_file = rules_path / Path(rel_path).name
                if not local_file.exists():
                    try:
                        r = requests.get(YARA_RAW_BASE + rel_path, timeout=15)
                        if r.status_code == 200:
                            local_file.write_text(r.text, encoding="utf-8", errors="ignore")
                            updated += 1
                    except Exception:
                        pass
            logger.info(f"YARA rules: {updated} new files downloaded")
        except Exception as e:
            logger.error(f"YARA GitHub fetch error: {e}")
