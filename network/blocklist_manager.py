"""
network/blocklist_manager.py — Domain blocklist manager (hosts file method)
"""
import logging
import shutil
import threading
import time
from pathlib import Path
from typing import List, Optional

import requests

logger = logging.getLogger(__name__)

HOSTS_FILE = Path(r"C:\Windows\System32\drivers\etc\hosts")
HOSTS_BACKUP = Path(r"C:\Windows\System32\drivers\etc\hosts.securenova.bak")
MARKER_START = "# === SecureNova Blocklist Start ==="
MARKER_END   = "# === SecureNova Blocklist End ==="

FEED_URLS = [
    ("https://urlhaus.abuse.ch/downloads/hostfile/", "URLhaus"),
    ("https://malware-filter.pages.dev/hosts.txt", "MalwareDomains"),
]


class BlocklistManager:
    def __init__(self, config: dict, db=None):
        self.config = config
        self.db = db
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._interval = config.get("blocklist_refresh_hours", 6) * 3600

    def start(self) -> None:
        if not HOSTS_FILE.exists():
            logger.warning("hosts file not found — blocklist manager disabled")
            return
        if not HOSTS_BACKUP.exists():
            try:
                shutil.copy2(HOSTS_FILE, HOSTS_BACKUP)
                logger.info(f"hosts backup created: {HOSTS_BACKUP}")
            except Exception as e:
                logger.error(f"hosts backup failed: {e}")

        self._running = True
        self._thread = threading.Thread(target=self._run, name="BlocklistManager", daemon=True)
        self._thread.start()
        logger.info("Blocklist manager started")

    def stop(self) -> None:
        self._running = False

    def _run(self) -> None:
        while self._running:
            try:
                self.refresh()
            except Exception as e:
                logger.error(f"Blocklist refresh error: {e}")
            self._running and time.sleep(self._interval)

    def refresh(self) -> int:
        all_domains = []
        for url, source in FEED_URLS:
            try:
                resp = requests.get(url, timeout=30)
                resp.raise_for_status()
                domains = self._parse_hosts(resp.text)
                all_domains.extend(domains)
                if self.db:
                    self.db.bulk_insert_domains(domains, source)
                logger.info(f"[{source}] {len(domains)} domains fetched")
            except Exception as e:
                logger.error(f"Feed fetch failed ({source}): {e}")

        # Deduplicate
        unique = list(dict.fromkeys(all_domains))
        self._write_to_hosts(unique)
        return len(unique)

    @staticmethod
    def _parse_hosts(content: str) -> List[str]:
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

    def _write_to_hosts(self, domains: List[str]) -> None:
        try:
            original = HOSTS_FILE.read_text(encoding="utf-8", errors="ignore")
            # Strip existing SecureNova block
            lines = original.splitlines()
            filtered = []
            skip = False
            for line in lines:
                if line.strip() == MARKER_START:
                    skip = True
                elif line.strip() == MARKER_END:
                    skip = False
                elif not skip:
                    filtered.append(line)

            block = [MARKER_START]
            block += [f"0.0.0.0 {d}" for d in domains[:50000]]
            block.append(MARKER_END)

            new_content = "\n".join(filtered) + "\n" + "\n".join(block) + "\n"
            HOSTS_FILE.write_text(new_content, encoding="utf-8")
            logger.info(f"hosts file updated: {len(domains)} blocked domains")
        except PermissionError:
            logger.error("Cannot write hosts file — run as Administrator")
        except Exception as e:
            logger.error(f"hosts write error: {e}")

    def restore_hosts(self) -> bool:
        try:
            if HOSTS_BACKUP.exists():
                shutil.copy2(HOSTS_BACKUP, HOSTS_FILE)
                logger.info("hosts file restored from backup")
                return True
        except Exception as e:
            logger.error(f"hosts restore failed: {e}")
        return False

    def add_custom_domain(self, domain: str) -> None:
        if self.db:
            self.db.add_custom_domain(domain)
        self._append_to_hosts(domain)

    def _append_to_hosts(self, domain: str) -> None:
        try:
            with open(HOSTS_FILE, "a", encoding="utf-8") as f:
                f.write(f"\n0.0.0.0 {domain}  # SecureNova custom\n")
        except Exception as e:
            logger.error(f"Could not append to hosts: {e}")
