"""
tests/test_cleaner.py — Threat cleaner tests

Covers: quarantine, restore, safety guards, rollback snapshots,
registry cleanup safety, and protected process checks.
"""
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from scanner.threat_cleaner import ThreatCleaner, CleaningResult
from utils.safety import (
    is_system_critical, is_protected_process,
    ConfidenceScorer, RollbackSnapshot
)


class TestSafetyGuards:
    def test_system32_is_protected(self):
        assert is_system_critical(r"C:\Windows\System32\kernel32.dll")

    def test_syswow64_is_protected(self):
        assert is_system_critical(r"C:\Windows\SysWOW64\ntdll.dll")

    def test_user_file_not_protected(self):
        assert not is_system_critical(r"C:\Users\test\Downloads\malware.exe")

    def test_temp_file_not_protected(self):
        assert not is_system_critical(r"C:\Users\test\AppData\Local\Temp\bad.exe")

    def test_csrss_is_protected(self):
        assert is_protected_process("csrss.exe")

    def test_lsass_is_protected(self):
        assert is_protected_process("lsass.exe")

    def test_svchost_is_protected(self):
        assert is_protected_process("svchost.exe")

    def test_explorer_is_protected(self):
        assert is_protected_process("explorer.exe")

    def test_random_process_not_protected(self):
        assert not is_protected_process("suspicious_app.exe")

    def test_case_insensitive(self):
        assert is_protected_process("CSRSS.EXE")
        assert is_system_critical(r"c:\WINDOWS\system32\kernel32.dll")


class TestConfidenceScorer:
    def test_hash_match_high_confidence(self):
        score = ConfidenceScorer.score(["hash_match"])
        assert score >= 90

    def test_yara_match_medium_confidence(self):
        score = ConfidenceScorer.score(["yara_match"])
        assert 60 <= score <= 85

    def test_heuristic_low_confidence(self):
        score = ConfidenceScorer.score(["heuristic"])
        assert score < 50

    def test_multi_engine_bonus(self):
        single = ConfidenceScorer.score(["yara_match"])
        double = ConfidenceScorer.score(["yara_match", "hash_match"])
        assert double > single

    def test_should_auto_clean_threshold(self):
        assert ConfidenceScorer.should_auto_clean(95)
        assert ConfidenceScorer.should_auto_clean(70)
        assert not ConfidenceScorer.should_auto_clean(40)
        assert not ConfidenceScorer.should_auto_clean(0)


class TestQuarantine:
    def test_quarantine_normal_file(self, mock_config, tmp_path):
        test_file = tmp_path / "threat.exe"
        test_file.write_bytes(b"MALICIOUS_CONTENT")

        cleaner = ThreatCleaner(mock_config)
        result = cleaner.quarantine_file(str(test_file), "TestThreat")
        assert result.success
        assert not test_file.exists()

    def test_quarantine_system_file_blocked(self, mock_config):
        cleaner = ThreatCleaner(mock_config)
        result = cleaner.quarantine_file(
            r"C:\Windows\System32\kernel32.dll", "FakeDetection"
        )
        assert not result.success
        assert result.failure_reason == "system_protected"

    def test_quarantine_nonexistent_file(self, mock_config):
        cleaner = ThreatCleaner(mock_config)
        result = cleaner.quarantine_file("/nonexistent/path", "Test")
        assert not result.success
        assert result.failure_reason == "File not found"

    def test_quarantine_and_restore(self, mock_config, tmp_path):
        content = b"ORIGINAL_CONTENT_12345"
        test_file = tmp_path / "restorable.bin"
        test_file.write_bytes(content)

        cleaner = ThreatCleaner(mock_config)
        result = cleaner.quarantine_file(str(test_file), "Test")
        assert result.success
        assert not test_file.exists()

        # Find quarantined file
        quar_dir = Path(mock_config["quarantine_path"])
        quar_files = list(quar_dir.rglob("*.quar"))
        assert len(quar_files) >= 1

        # Restore
        restored = cleaner.restore_quarantined(str(quar_files[0]), str(test_file))
        assert restored
        assert test_file.exists()


class TestCleanThreat:
    def test_clean_threat_pipeline(self, mock_config, mock_db, tmp_path):
        threat_file = tmp_path / "threat_to_clean.exe"
        threat_file.write_bytes(b"THREAT_DATA")

        cleaner = ThreatCleaner(mock_config, mock_db)
        result = cleaner.clean_threat({
            "path": str(threat_file),
            "threat_name": "TestMalware.Clean",
            "severity": "high",
            "engine": "TestEngine",
        })
        assert result.success
        assert not threat_file.exists()

    def test_clean_system_file_refused(self, mock_config, mock_db):
        cleaner = ThreatCleaner(mock_config, mock_db)
        result = cleaner.clean_threat({
            "path": r"C:\Windows\System32\ntdll.dll",
            "threat_name": "FakeDetection",
            "severity": "high",
        })
        assert not result.success
        assert "system_protected" in (result.failure_reason or "")


class TestRollbackSnapshot:
    def test_capture_and_list(self, tmp_path):
        rollback = RollbackSnapshot(str(tmp_path / "rollback"))

        test_file = tmp_path / "to_snapshot.bin"
        test_file.write_bytes(b"SNAPSHOT_CONTENT")

        snap_id = rollback.capture_file(str(test_file))
        assert snap_id is not None

        snapshots = rollback.list_snapshots()
        assert len(snapshots) >= 1
        assert snapshots[0]["original_path"] == str(test_file)

    def test_registry_capture(self, tmp_path):
        rollback = RollbackSnapshot(str(tmp_path / "rollback"))
        snap_id = rollback.capture_registry(
            r"HKCU\SOFTWARE\Test", "TestValue", "TestData"
        )
        assert snap_id is not None

        snapshots = rollback.list_snapshots()
        reg_snaps = [s for s in snapshots if s.get("type") == "registry"]
        assert len(reg_snaps) >= 1


class TestCleaningResult:
    def test_to_dict(self):
        r = CleaningResult("/test/path", "TestMalware")
        r.success = True
        r.action_taken = "quarantined"
        d = r.to_dict()
        assert d["success"] is True
        assert d["threat_path"] == "/test/path"
        assert d["action_taken"] == "quarantined"
