"""
tests/conftest.py — Shared pytest fixtures for SecureNova tests
"""
import os
import sys
import tempfile
import shutil
from pathlib import Path

import pytest

# Add project root to path
ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))


@pytest.fixture
def tmp_scan_dir(tmp_path):
    """Temporary directory with test files for scanning."""
    d = tmp_path / "scan_target"
    d.mkdir()
    # Clean file
    (d / "clean.txt").write_text("This is a harmless text file.")
    # Clean binary
    (d / "clean.bin").write_bytes(b"\x00" * 256)
    return d


@pytest.fixture
def eicar_file(tmp_path):
    """Create EICAR test file (standard AV test string)."""
    eicar = (
        r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR"
        r"-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    )
    path = tmp_path / "eicar.com"
    path.write_text(eicar)
    yield path
    if path.exists():
        path.unlink()


@pytest.fixture
def mock_config():
    """Minimal config dict for testing."""
    return {
        "scan_paths": [],
        "quarantine_path": tempfile.mkdtemp(prefix="sn_test_quar_"),
        "auto_quarantine": False,
        "virustotal_api_key": "",
        "whitelist_processes": ["explorer.exe", "svchost.exe"],
        "log_level": "DEBUG",
        "process_poll_interval": 2,
        "network_poll_interval": 5,
    }


@pytest.fixture
def mock_db():
    """Mock database that tracks calls without real SQLite."""

    class MockDB:
        def __init__(self):
            self.calls = []
            self._hashes = {}

        def log_scan(self, *args, **kwargs):
            self.calls.append(("log_scan", args, kwargs))

        def log_threat(self, *args, **kwargs):
            self.calls.append(("log_threat", args, kwargs))

        def hash_exists(self, sha256=None, md5=None):
            key = sha256 or md5
            return self._hashes.get(key)

        def add_quarantine_entry(self, *args, **kwargs):
            self.calls.append(("add_quarantine_entry", args, kwargs))

        def save_scan_run(self, *args, **kwargs):
            self.calls.append(("save_scan_run", args, kwargs))

        def snapshot_process(self, *args, **kwargs):
            pass

        def is_process_trusted(self, name):
            return False

        def snapshot_startup_item(self, *args, **kwargs):
            pass

        def _execute(self, sql, params=()):
            self.calls.append(("_execute", sql, params))

        def inject_hash(self, sha256, signature="TestMalware"):
            self._hashes[sha256] = {"sha256": sha256, "signature": signature}

    return MockDB()
