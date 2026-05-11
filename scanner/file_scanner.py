"""
scanner/file_scanner.py — YARA + hash-based file scanner
"""
import hashlib
import logging
import os
import shutil
import threading
from pathlib import Path
from typing import Optional, Callable

from utils.safety import ConfidenceScorer
from utils.logger import audit_log

try:
    from utils.scan_cache import ScanCache
    CACHE_AVAILABLE = True
except ImportError:
    CACHE_AVAILABLE = False

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    logging.warning("yara-python not installed — YARA scanning disabled")

logger = logging.getLogger(__name__)


class ScanResult:
    def __init__(self, path: str, clean: bool, threat_name: str = "",
                 threat_type: str = "", engine: str = "", file_hash: str = "",
                 confidence: int = 0):
        self.path = path
        self.clean = clean
        self.threat_name = threat_name
        self.threat_type = threat_type
        self.engine = engine
        self.file_hash = file_hash
        self.confidence = confidence

    def __repr__(self):
        status = "CLEAN" if self.clean else f"THREAT({self.threat_name})"
        return f"<ScanResult {status} path={self.path}>"


class FileScanner:
    """
    Scans files using YARA rules and local MD5/SHA256 hash database.
    Emits signals/callbacks when threats are found.
    """

    def __init__(self, config: dict, db=None,
                 on_threat: Optional[Callable[[ScanResult], None]] = None):
        self.config = config
        self.db = db
        self.on_threat = on_threat
        self.rules_dir = Path("rules")
        self.quarantine_dir = Path(config.get("quarantine_path", "quarantine"))
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        self._rules = None
        self._lock = threading.Lock()
        self._cache = ScanCache() if CACHE_AVAILABLE else None
        self.load_rules()

    # ------------------------------------------------------------------ #
    #  Rule loading                                                         #
    # ------------------------------------------------------------------ #
    def load_rules(self) -> None:
        if not YARA_AVAILABLE:
            return
        yar_files = list(self.rules_dir.rglob("*.yar")) + list(self.rules_dir.rglob("*.yara"))
        if not yar_files:
            logger.warning(f"No YARA rules found in {self.rules_dir}")
            return
        filepaths = {}
        for i, f in enumerate(yar_files):
            ns = f"rule_{i}_{f.stem}"
            filepaths[ns] = str(f)
        try:
            with self._lock:
                self._rules = yara.compile(filepaths=filepaths)
            logger.info(f"Loaded {len(yar_files)} YARA rule files")
        except Exception as e:
            logger.error(f"YARA compile error: {e}")
            self._rules = None

    # ------------------------------------------------------------------ #
    #  Hashing                                                              #
    # ------------------------------------------------------------------ #
    @staticmethod
    def hash_file(path: str) -> dict:
        md5 = hashlib.md5()
        sha256 = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    md5.update(chunk)
                    sha256.update(chunk)
            return {"md5": md5.hexdigest(), "sha256": sha256.hexdigest()}
        except Exception as e:
            logger.error(f"Hash error for {path}: {e}")
            return {"md5": "", "sha256": ""}

    # ------------------------------------------------------------------ #
    #  Core scan                                                            #
    # ------------------------------------------------------------------ #
    def scan_file(self, path: str) -> ScanResult:
        path = str(path)
        if not os.path.isfile(path):
            return ScanResult(path, True, engine="skip")

        try:
            file_size = os.path.getsize(path)
        except OSError:
            return ScanResult(path, True, engine="skip")

        # Skip very large files (>512 MB)
        if file_size > 512 * 1024 * 1024:
            return ScanResult(path, True, engine="skip_large")

        # 0. Check scan cache — skip hashing if file unchanged
        if self._cache:
            cached = self._cache.is_cached(path)
            if cached:
                return ScanResult(
                    path, cached["result"] == "clean",
                    threat_name=cached.get("threat_name", ""),
                    engine=cached.get("engine", "cache"),
                    file_hash=cached.get("sha256", ""),
                    confidence=cached.get("confidence", 0),
                )

        hashes = self.hash_file(path)
        sha256 = hashes["sha256"]
        md5 = hashes["md5"]

        # 1. Hash check against local DB
        if self.db and sha256:
            hit = self.db.hash_exists(sha256=sha256) or self.db.hash_exists(md5=md5)
            if hit:
                confidence = ConfidenceScorer.score(["hash_match"])
                result = ScanResult(
                    path, False,
                    threat_name=hit.get("signature", "KnownMalware"),
                    threat_type="hash_match",
                    engine="HashDB",
                    file_hash=sha256,
                    confidence=confidence,
                )
                self._handle_threat(result)
                return result

        # 2. YARA scan
        if YARA_AVAILABLE and self._rules:
            try:
                with self._lock:
                    matches = self._rules.match(path, timeout=30)
                if matches:
                    threat_name = matches[0].rule
                    confidence = ConfidenceScorer.score(["yara_match"])
                    result = ScanResult(
                        path, False,
                        threat_name=threat_name,
                        threat_type="yara_match",
                        engine="YARA",
                        file_hash=sha256,
                        confidence=confidence,
                    )
                    self._handle_threat(result)
                    return result
            except yara.TimeoutError:
                logger.warning(f"YARA timeout on {path}")
            except Exception as e:
                logger.error(f"YARA scan error on {path}: {e}")

        result = ScanResult(path, True, engine="YARA+HashDB", file_hash=sha256)

        # Cache clean result
        if self._cache:
            self._cache.store(path, "clean", sha256)

        # Log to DB
        if self.db:
            self.db.log_scan(path, "clean", result.engine, sha256)

        return result

    def _handle_threat(self, result: ScanResult) -> None:
        logger.warning(f"THREAT: {result.threat_name} in {result.path} "
                       f"(confidence={result.confidence})")
        audit_log("threat_detected", "high", "file_scanner",
                  path=result.path, threat_name=result.threat_name,
                  engine=result.engine, confidence=result.confidence)

        # Cache threat result
        if self._cache:
            self._cache.store(result.path, "threat", result.file_hash,
                              result.threat_name, result.engine, result.confidence)

        if self.db:
            self.db.log_scan(result.path, "threat", result.engine,
                             result.file_hash, result.threat_name)
            self.db.log_threat(
                result.threat_type, "high",
                result.path, result.threat_name, ""
            )

        # Only auto-quarantine with sufficient confidence
        if (self.config.get("auto_quarantine", True)
                and ConfidenceScorer.should_auto_clean(result.confidence)):
            self.quarantine(result.path, result.threat_name, result.threat_type)
        elif not ConfidenceScorer.should_auto_clean(result.confidence):
            logger.info(f"Low confidence ({result.confidence}) — skipping auto-quarantine "
                        f"for {result.path}")

        if self.on_threat:
            self.on_threat(result)

    # ------------------------------------------------------------------ #
    #  Quarantine                                                           #
    # ------------------------------------------------------------------ #
    def quarantine(self, path: str, threat_name: str = "", threat_type: str = "") -> Optional[str]:
        try:
            src = Path(path)
            if not src.exists():
                return None
            dest = self.quarantine_dir / (src.name + ".quarantine")
            # Handle collisions
            counter = 0
            while dest.exists():
                counter += 1
                dest = self.quarantine_dir / f"{src.stem}_{counter}{src.suffix}.quarantine"
            shutil.move(str(src), str(dest))
            if self.db:
                self.db.add_quarantine_entry(str(src), str(dest), threat_name, threat_type)
            logger.info(f"Quarantined: {src} → {dest}")
            return str(dest)
        except Exception as e:
            logger.error(f"Quarantine failed for {path}: {e}")
            return None

    def restore_from_quarantine(self, quarantine_path: str, original_path: str,
                                 entry_id: int = 0) -> bool:
        try:
            shutil.move(quarantine_path, original_path)
            if self.db and entry_id:
                self.db.mark_restored(entry_id)
            logger.info(f"Restored: {quarantine_path} → {original_path}")
            return True
        except Exception as e:
            logger.error(f"Restore failed: {e}")
            return False

    def update_hashes(self) -> None:
        """Trigger hash update via Updater (called externally)."""
        pass  # Delegated to utils/updater.py
