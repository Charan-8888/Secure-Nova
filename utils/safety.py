"""
utils/safety.py — System-file protection, confidence scoring, rollback snapshots

Prevents accidental deletion of critical Windows files/processes.
All cleaning operations MUST check safety before acting.
"""
import json
import logging
import os
import shutil
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, Set

logger = logging.getLogger(__name__)

# ─── Protected paths: NEVER quarantine/delete files under these ──────────
PROTECTED_PATHS: Set[str] = {
    r"c:\windows\system32",
    r"c:\windows\syswow64",
    r"c:\windows\winsxs",
    r"c:\windows\servicing",
    r"c:\windows\assembly",
    r"c:\windows\microsoft.net",
    r"c:\windows\inf",
    r"c:\windows\boot",
    r"c:\windows\fonts",
    r"c:\windows\globalization",
    r"c:\windows\immersivecontrolpanel",
    r"c:\windows\installer",
    r"c:\windows\logs",
    r"c:\windows\resources",
    r"c:\windows\security",
    r"c:\windows\systemapps",
    r"c:\program files\windows defender",
    r"c:\program files (x86)\windows defender",
    r"c:\programdata\microsoft\windows defender",
}

# ─── Protected processes: NEVER terminate these ──────────────────────────
PROTECTED_PROCESSES: Set[str] = {
    "system", "system idle process", "registry", "smss.exe",
    "csrss.exe", "wininit.exe", "services.exe", "lsass.exe",
    "lsaiso.exe", "svchost.exe", "winlogon.exe", "dwm.exe",
    "fontdrvhost.exe", "sihost.exe", "taskhostw.exe",
    "explorer.exe", "runtimebroker.exe", "searchhost.exe",
    "startmenuexperiencehost.exe", "textinputhost.exe",
    "shellexperiencehost.exe", "securityhealthservice.exe",
    "securityhealthsystray.exe", "msmpeng.exe", "nissrv.exe",
    "mrt.exe", "spoolsv.exe", "wudfhost.exe", "conhost.exe",
    "dllhost.exe", "taskeng.exe", "audiodg.exe", "ctfmon.exe",
    "dashost.exe", "devicecensus.exe", "msiexec.exe",
    "trustedinstaller.exe", "tiworker.exe", "wermgr.exe",
    "wmiprvse.exe", "searchindexer.exe", "searchprotocolhost.exe",
}

# ─── Protected file extensions in system directories ─────────────────────
SYSTEM_CRITICAL_FILES: Set[str] = {
    "ntoskrnl.exe", "hal.dll", "ntdll.dll", "kernel32.dll",
    "kernelbase.dll", "advapi32.dll", "user32.dll", "gdi32.dll",
    "shell32.dll", "ole32.dll", "combase.dll", "rpcrt4.dll",
    "secur32.dll", "crypt32.dll", "bcrypt.dll", "ncrypt.dll",
    "winhttp.dll", "urlmon.dll", "wininet.dll", "ws2_32.dll",
    "mswsock.dll", "dnsapi.dll", "iphlpapi.dll", "netapi32.dll",
    "samlib.dll", "wintrust.dll", "msvcrt.dll", "ucrtbase.dll",
    "clbcatq.dll", "setupapi.dll", "cfgmgr32.dll", "devobj.dll",
    "powrprof.dll", "profapi.dll", "sspicli.dll", "lsasrv.dll",
    "bootmgr", "winload.exe", "winresume.exe", "ci.dll",
}


def is_system_critical(path: str) -> bool:
    """Check if a file path is under a protected Windows directory."""
    if not path:
        return False
    normalized = os.path.normpath(path).lower()
    for protected in PROTECTED_PATHS:
        if normalized.startswith(protected):
            return True
    basename = os.path.basename(normalized)
    if basename in SYSTEM_CRITICAL_FILES:
        return True
    return False


def is_protected_process(name: str) -> bool:
    """Check if a process name is a protected Windows process."""
    if not name:
        return False
    return name.lower() in PROTECTED_PROCESSES


class ConfidenceScorer:
    """Assigns 0–100 confidence score to a detection result."""

    WEIGHTS = {
        "hash_match": 95,
        "yara_match": 75,
        "virustotal": 90,
        "heuristic": 40,
        "behavioral": 55,
        "reputation": 35,
        "signature_unsigned": 20,
        "pup_pattern": 30,
    }

    @classmethod
    def score(cls, engines_matched: list, details: dict = None) -> int:
        """Calculate confidence from list of detection engine names."""
        if not engines_matched:
            return 0
        details = details or {}
        total = 0
        count = 0
        for engine in engines_matched:
            key = engine.lower().replace(" ", "_")
            for weight_key, weight_val in cls.WEIGHTS.items():
                if weight_key in key:
                    total += weight_val
                    count += 1
                    break
            else:
                total += 50
                count += 1

        base = total / max(count, 1)

        # Multi-engine bonus
        if count >= 3:
            base = min(base + 15, 100)
        elif count >= 2:
            base = min(base + 8, 100)

        # VT detection count bonus
        vt_count = details.get("vt_detections", 0)
        if vt_count >= 10:
            base = min(base + 10, 100)
        elif vt_count >= 5:
            base = min(base + 5, 100)

        return int(min(base, 100))

    @classmethod
    def should_auto_clean(cls, confidence: int) -> bool:
        """Only auto-clean with high confidence (>=70)."""
        return confidence >= 70


class RollbackSnapshot:
    """Captures file/registry state before cleaning for undo capability."""

    def __init__(self, snapshot_dir: str = "data/rollback"):
        self.snapshot_dir = Path(snapshot_dir)
        self.snapshot_dir.mkdir(parents=True, exist_ok=True)

    def capture_file(self, file_path: str) -> Optional[str]:
        """Capture file metadata + first 4KB before cleaning. Returns snapshot ID."""
        try:
            src = Path(file_path)
            if not src.exists():
                return None

            snap_id = f"{int(time.time())}_{src.name}"
            snap_dir = self.snapshot_dir / snap_id
            snap_dir.mkdir(parents=True, exist_ok=True)

            stat = src.stat()
            meta = {
                "original_path": str(src),
                "file_name": src.name,
                "size": stat.st_size,
                "mtime": stat.st_mtime,
                "captured_at": datetime.now().isoformat(),
                "permissions": oct(stat.st_mode),
            }

            # Save metadata
            with open(snap_dir / "metadata.json", "w") as f:
                json.dump(meta, f, indent=2)

            # Save first 4KB preview
            with open(src, "rb") as f:
                preview = f.read(4096)
            with open(snap_dir / "preview.bin", "wb") as f:
                f.write(preview)

            logger.debug(f"Rollback snapshot captured: {snap_id}")
            return snap_id

        except Exception as e:
            logger.error(f"Failed to capture rollback snapshot for {file_path}: {e}")
            return None

    def capture_registry(self, key_path: str, value_name: str,
                         value_data: str) -> Optional[str]:
        """Capture a registry value before deletion."""
        try:
            snap_id = f"reg_{int(time.time())}_{value_name}"
            snap_dir = self.snapshot_dir / snap_id
            snap_dir.mkdir(parents=True, exist_ok=True)

            meta = {
                "type": "registry",
                "key_path": key_path,
                "value_name": value_name,
                "value_data": value_data,
                "captured_at": datetime.now().isoformat(),
            }
            with open(snap_dir / "metadata.json", "w") as f:
                json.dump(meta, f, indent=2)

            logger.debug(f"Registry rollback captured: {snap_id}")
            return snap_id

        except Exception as e:
            logger.error(f"Failed to capture registry snapshot: {e}")
            return None

    def list_snapshots(self) -> list:
        """List all available rollback snapshots."""
        snapshots = []
        if not self.snapshot_dir.exists():
            return snapshots
        for d in sorted(self.snapshot_dir.iterdir(), reverse=True):
            if d.is_dir():
                meta_path = d / "metadata.json"
                if meta_path.exists():
                    try:
                        with open(meta_path) as f:
                            meta = json.load(f)
                        meta["snapshot_id"] = d.name
                        snapshots.append(meta)
                    except Exception:
                        pass
        return snapshots

    def cleanup_old(self, max_age_days: int = 30) -> int:
        """Remove snapshots older than max_age_days."""
        cutoff = time.time() - (max_age_days * 86400)
        removed = 0
        for d in list(self.snapshot_dir.iterdir()):
            if d.is_dir():
                try:
                    parts = d.name.split("_", 1)
                    ts = int(parts[0]) if parts[0].isdigit() else 0
                    if ts and ts < cutoff:
                        shutil.rmtree(str(d), ignore_errors=True)
                        removed += 1
                except Exception:
                    pass
        return removed
