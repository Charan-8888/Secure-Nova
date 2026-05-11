"""
scanner/behavior_engine.py — Rule-based behavioral detection engine

Detects: parent-child anomalies, encoded PowerShell, LOLBin abuse,
mass file modification, suspicious startup persistence, abnormal network
activity, credential access attempts, and defense evasion.

Uses intel/behavior_rules.json for externalized patterns.
No AI/ML — pure rule logic.
"""
import json
import logging
import os
import re
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Dict, List, Optional, Set, Callable

logger = logging.getLogger(__name__)

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

RULES_FILE = Path("intel") / "behavior_rules.json"


def _load_rules() -> Dict:
    try:
        with open(RULES_FILE, encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Failed to load behavior rules: {e}")
        return {}


class BehaviorAlert:
    """Single behavioral detection alert."""

    __slots__ = ("rule_name", "severity", "pid", "process_name",
                 "detail", "timestamp", "confidence")

    def __init__(self, rule_name: str, severity: str, pid: int,
                 process_name: str, detail: str, confidence: int = 60):
        self.rule_name = rule_name
        self.severity = severity
        self.pid = pid
        self.process_name = process_name
        self.detail = detail
        self.timestamp = time.time()
        self.confidence = confidence

    def to_dict(self) -> Dict:
        return {
            "rule_name": self.rule_name,
            "severity": self.severity,
            "pid": self.pid,
            "process_name": self.process_name,
            "detail": self.detail,
            "confidence": self.confidence,
            "timestamp": self.timestamp,
        }

    def to_alert(self) -> Dict:
        return {
            "type": "behavior_alert",
            "severity": self.severity,
            "source": "behavior_engine",
            "detail": f"[{self.rule_name}] {self.process_name} (PID {self.pid}): {self.detail}",
            "pid": self.pid,
            "path": "",
        }


class BehaviorEngine:
    """Rule-based behavioral detection engine.

    Call `analyze_process(proc_info)` per-process during each poll cycle.
    Call `check_file_ops(pid, op_type)` when file operations are observed.
    """

    def __init__(self, on_alert: Optional[Callable] = None, event_bus=None):
        self.on_alert = on_alert
        self.event_bus = event_bus
        self.rules = _load_rules()
        self._alerted: Dict[int, Set[str]] = defaultdict(set)
        self._file_ops: Dict[int, deque] = defaultdict(lambda: deque(maxlen=500))
        self._alerts: List[BehaviorAlert] = []

        # Parse LOLBin rules
        self._lolbins = {}
        lolbin_data = self.rules.get("lolbins", {}).get("binaries", {})
        for binary, info in lolbin_data.items():
            self._lolbins[binary.lower()] = {
                "args": [a.lower() for a in info.get("suspicious_args", [])],
                "severity": info.get("severity", "medium"),
            }

        # Parse parent-child rules
        self._parent_child = {}
        for rule in self.rules.get("parent_child_violations", {}).get("rules", []):
            parent = rule["parent"].lower()
            children = {c.lower() for c in rule["child"]}
            self._parent_child[parent] = children

        # Parse defense evasion patterns
        self._evasion_patterns = []
        for pat in self.rules.get("defense_evasion_patterns", {}).get("patterns", []):
            try:
                self._evasion_patterns.append(re.compile(pat, re.IGNORECASE))
            except re.error:
                self._evasion_patterns.append(re.compile(re.escape(pat), re.IGNORECASE))

        # Mass modification thresholds
        mass = self.rules.get("mass_modification_thresholds", {})
        self._mass_count = mass.get("file_count", 50)
        self._mass_window = mass.get("window_seconds", 30)
        self._ransom_exts = set(mass.get("rename_extensions", []))

        # Credential target paths
        cred = self.rules.get("credential_targets", {})
        self._cred_paths = [p.lower() for p in cred.get("paths", [])]
        self._cred_procs = {p.lower() for p in cred.get("processes", [])}

    def analyze_process(self, proc_info: Dict) -> List[BehaviorAlert]:
        """Run all behavioral rules against a single process.

        proc_info keys: pid, name, exe, cmdline (str), parent_name (optional)
        """
        alerts = []
        pid = proc_info.get("pid", 0)
        name = (proc_info.get("name") or "").lower()
        cmdline = proc_info.get("cmdline", "")
        if isinstance(cmdline, list):
            cmdline = " ".join(cmdline)
        cmdline_lower = cmdline.lower()
        parent = (proc_info.get("parent_name") or "").lower()

        # Rule 1: Parent-child anomaly
        if parent and parent in self._parent_child:
            if name in self._parent_child[parent]:
                alerts.append(self._flag(pid, name, "ParentChildAnomaly", "high",
                    f"{parent} spawned {name}", 75))

        # Rule 2: Encoded PowerShell
        if name in ("powershell.exe", "pwsh.exe"):
            encoded_patterns = [
                r'(?i)(-encodedcommand|-enc\s|-e\s)\s*[A-Za-z0-9+/=]{20,}',
                r'(?i)(frombase64string|convert.*base64)',
            ]
            for pat in encoded_patterns:
                if re.search(pat, cmdline):
                    alerts.append(self._flag(pid, name, "EncodedPowerShell", "high",
                        f"Encoded payload detected in cmdline", 80))
                    break

        # Rule 3: LOLBin abuse
        if name in self._lolbins:
            lol = self._lolbins[name]
            for arg in lol["args"]:
                if arg in cmdline_lower:
                    alerts.append(self._flag(pid, name, "LOLBinAbuse", lol["severity"],
                        f"{name} with suspicious arg: {arg}", 70))
                    break

        # Rule 4: Defense evasion
        for pattern in self._evasion_patterns:
            if pattern.search(cmdline):
                alerts.append(self._flag(pid, name, "DefenseEvasion", "critical",
                    f"Security disabling: {pattern.pattern[:60]}", 85))
                break

        # Rule 5: Credential access
        exe = (proc_info.get("exe") or "").lower()
        if name not in self._cred_procs:
            for cred_path in self._cred_paths:
                if cred_path in cmdline_lower or cred_path in exe:
                    alerts.append(self._flag(pid, name, "CredentialAccess", "critical",
                        f"Accessing credential store: {cred_path}", 80))
                    break

        return alerts

    def check_file_ops(self, pid: int, process_name: str, op_type: str = "modify",
                       file_path: str = "") -> Optional[BehaviorAlert]:
        """Track file operations per process for mass-modification detection.

        Args:
            op_type: 'modify', 'rename', 'delete', 'create'
        """
        now = time.time()
        self._file_ops[pid].append((now, op_type, file_path))

        # Count recent ops within window
        recent = [(t, op, fp) for t, op, fp in self._file_ops[pid]
                  if now - t < self._mass_window]

        if len(recent) >= self._mass_count:
            # Check for ransomware-like rename patterns
            rename_to_encrypted = sum(
                1 for _, op, fp in recent
                if op == "rename" and any(fp.lower().endswith(ext) for ext in self._ransom_exts)
            )
            if rename_to_encrypted > 10:
                return self._flag(pid, process_name, "RansomwareBehavior", "critical",
                    f"{len(recent)} file ops in {self._mass_window}s, "
                    f"{rename_to_encrypted} encrypted renames", 90)
            else:
                return self._flag(pid, process_name, "MassFileModification", "high",
                    f"{len(recent)} file modifications in {self._mass_window}s", 65)

        return None

    def check_network(self, pid: int, process_name: str,
                      remote_host: str, remote_port: int) -> Optional[BehaviorAlert]:
        """Check outbound connections for suspicious TLDs/ports."""
        suspicious_tlds = self.rules.get("suspicious_tlds", {}).get("tlds", [])
        host_lower = remote_host.lower()

        for tld in suspicious_tlds:
            if host_lower.endswith(tld):
                return self._flag(pid, process_name, "AbnormalNetworkActivity", "medium",
                    f"Connection to suspicious TLD: {remote_host}:{remote_port}", 55)

        # Unusual high ports with non-browser processes
        if remote_port not in (80, 443, 8080, 8443, 53) and remote_port > 1024:
            browser_procs = {"chrome.exe", "firefox.exe", "msedge.exe", "brave.exe",
                             "opera.exe", "iexplore.exe"}
            if process_name.lower() not in browser_procs:
                if remote_port in (4444, 5555, 6666, 7777, 8888, 9999,
                                   1234, 31337, 12345, 54321):
                    return self._flag(pid, process_name, "AbnormalNetworkActivity", "high",
                        f"Suspicious port: {remote_host}:{remote_port}", 70)

        return None

    def check_startup_persistence(self, entry_name: str, entry_path: str,
                                   registry_key: str) -> Optional[BehaviorAlert]:
        """Check if a new startup entry is suspicious."""
        path_lower = entry_path.lower()
        suspicious_dirs = ["\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\",
                           "\\downloads\\", "\\public\\"]
        for d in suspicious_dirs:
            if d in path_lower:
                return self._flag(0, entry_name, "SuspiciousStartupPersistence", "high",
                    f"Startup entry from temp directory: {entry_path}", 75)

        # Encoded or obfuscated commands in startup
        if re.search(r'(?i)(-enc|-encodedcommand|powershell.*-e\s)', entry_path):
            return self._flag(0, entry_name, "SuspiciousStartupPersistence", "critical",
                f"Encoded startup command: {entry_path[:80]}", 85)

        return None

    def _flag(self, pid: int, name: str, rule: str, severity: str,
              detail: str, confidence: int) -> BehaviorAlert:
        """Create alert, deduplicate, and emit."""
        # Deduplicate per process
        key = f"{pid}_{rule}"
        if key in self._alerted.get(pid, set()):
            return BehaviorAlert(rule, severity, pid, name, detail, confidence)

        self._alerted[pid].add(key)

        alert = BehaviorAlert(rule, severity, pid, name, detail, confidence)
        self._alerts.append(alert)
        logger.warning(f"[BEHAVIOR] [{severity.upper()}] {rule} | {name} (PID {pid}) | {detail}")

        if self.on_alert:
            self.on_alert(alert.to_alert())

        if self.event_bus:
            self.event_bus.emit(
                "behavior_alert", severity, "behavior_engine",
                rule_name=rule, pid=pid, process_name=name,
                detail=detail, confidence=confidence,
            )

        return alert

    def get_alerts(self, limit: int = 100) -> List[Dict]:
        """Get recent behavioral alerts."""
        return [a.to_dict() for a in self._alerts[-limit:]]

    def clear_process(self, pid: int) -> None:
        """Clear tracking data for a terminated process."""
        self._alerted.pop(pid, None)
        self._file_ops.pop(pid, None)

    def reload_rules(self) -> None:
        """Reload rules from disk."""
        self.rules = _load_rules()
        self.__init__(on_alert=self.on_alert, event_bus=self.event_bus)
        logger.info("Behavior rules reloaded")
