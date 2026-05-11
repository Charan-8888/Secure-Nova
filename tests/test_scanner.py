"""
tests/test_scanner.py — File scanner tests

Covers: EICAR detection, hash lookup, clean file verification,
scan cache integration, and false positive testing.
"""
import hashlib
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from scanner.file_scanner import FileScanner, ScanResult


class TestScanResult:
    def test_clean_result(self):
        r = ScanResult("/test", True)
        assert r.clean
        assert r.confidence == 0

    def test_threat_result(self):
        r = ScanResult("/test", False, threat_name="EICAR", confidence=95)
        assert not r.clean
        assert r.confidence == 95

    def test_repr(self):
        r = ScanResult("/test", True)
        assert "CLEAN" in repr(r)


class TestFileScanner:
    def test_scan_nonexistent_file(self, mock_config, mock_db):
        scanner = FileScanner(mock_config, mock_db)
        result = scanner.scan_file("/nonexistent/path/file.exe")
        assert result.clean
        assert result.engine == "skip"

    def test_scan_clean_text_file(self, mock_config, mock_db, tmp_path):
        clean = tmp_path / "clean.txt"
        clean.write_text("Hello, this is a perfectly normal text file.")

        scanner = FileScanner(mock_config, mock_db)
        result = scanner.scan_file(str(clean))
        assert result.clean

    def test_scan_large_file_skipped(self, mock_config, mock_db, tmp_path):
        large = tmp_path / "large.bin"
        large.write_bytes(b"\x00")  # Create small file first

        scanner = FileScanner(mock_config, mock_db)
        # Monkey-patch size check
        original_getsize = os.path.getsize
        os.path.getsize = lambda p: 600 * 1024 * 1024  # 600 MB
        try:
            result = scanner.scan_file(str(large))
            assert result.clean
            assert result.engine == "skip_large"
        finally:
            os.path.getsize = original_getsize

    def test_hash_detection(self, mock_config, mock_db, tmp_path):
        content = b"KNOWN_MALWARE_CONTENT_TEST"
        malware = tmp_path / "malware.bin"
        malware.write_bytes(content)

        sha256 = hashlib.sha256(content).hexdigest()
        mock_db.inject_hash(sha256, "TestMalware.HashTest")

        scanner = FileScanner(mock_config, mock_db)
        result = scanner.scan_file(str(malware))
        assert not result.clean
        assert "HashDB" in result.engine
        assert result.confidence > 0


class TestFalsePositives:
    """Verify common legitimate files are not flagged."""

    def test_empty_file_is_clean(self, mock_config, mock_db, tmp_path):
        empty = tmp_path / "empty.exe"
        empty.write_bytes(b"")
        scanner = FileScanner(mock_config, mock_db)
        result = scanner.scan_file(str(empty))
        assert result.clean

    def test_plain_text_is_clean(self, mock_config, mock_db, tmp_path):
        text = tmp_path / "readme.txt"
        text.write_text("SecureNova Security Suite\nVersion 2.0")
        scanner = FileScanner(mock_config, mock_db)
        result = scanner.scan_file(str(text))
        assert result.clean

    def test_json_config_is_clean(self, mock_config, mock_db, tmp_path):
        cfg = tmp_path / "config.json"
        cfg.write_text('{"setting": "value", "enabled": true}')
        scanner = FileScanner(mock_config, mock_db)
        result = scanner.scan_file(str(cfg))
        assert result.clean


class TestScanCache:
    def test_cache_hit_on_unchanged_file(self, mock_config, mock_db, tmp_path):
        test_file = tmp_path / "cached.bin"
        test_file.write_bytes(b"CACHE_TEST_CONTENT")

        scanner = FileScanner(mock_config, mock_db)
        if not scanner._cache:
            pytest.skip("Scan cache not available")

        # First scan — cache miss
        r1 = scanner.scan_file(str(test_file))
        stats1 = scanner._cache.get_stats()

        # Second scan — should be cache hit
        r2 = scanner.scan_file(str(test_file))
        stats2 = scanner._cache.get_stats()

        assert stats2["hits"] > stats1["hits"]

    def test_cache_miss_on_modified_file(self, mock_config, mock_db, tmp_path):
        test_file = tmp_path / "modified.bin"
        test_file.write_bytes(b"ORIGINAL")

        scanner = FileScanner(mock_config, mock_db)
        if not scanner._cache:
            pytest.skip("Scan cache not available")

        scanner.scan_file(str(test_file))

        # Modify file
        test_file.write_bytes(b"MODIFIED_CONTENT")

        stats_before = scanner._cache.get_stats()
        scanner.scan_file(str(test_file))
        stats_after = scanner._cache.get_stats()

        assert stats_after["misses"] > stats_before["misses"]
