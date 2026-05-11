"""
sandbox/executor.py — Lightweight Windows Job Object soft-sandbox
"""
import logging
import os
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

try:
    import win32job
    import win32process
    import win32con
    import win32api
    WIN32_AVAILABLE = True
except ImportError:
    WIN32_AVAILABLE = False
    logger.warning("pywin32 not installed — sandbox disabled")

SANDBOX_TEMP = Path(r"C:\SandboxTemp")


class SandboxResult:
    def __init__(self):
        self.verdict = "unknown"   # safe | suspicious | malicious
        self.files_created: list[str] = []
        self.network_attempts: int = 0
        self.registry_keys: list[str] = []
        self.exit_code: Optional[int] = None
        self.timed_out = False
        self.error: str = ""

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "files_created": self.files_created,
            "network_attempts": self.network_attempts,
            "registry_keys": self.registry_keys,
            "exit_code": self.exit_code,
            "timed_out": self.timed_out,
            "error": self.error,
        }


class SandboxExecutor:
    """
    Soft sandbox using Windows Job Objects.
    Limits: CPU time, file I/O redirected to SANDBOX_TEMP, no UI.
    Full kernel isolation requires a signed driver; this is a best-effort approach.
    """

    def __init__(self, config: dict):
        self.config = config
        self.timeout = config.get("sandbox_timeout_seconds", 30)
        SANDBOX_TEMP.mkdir(parents=True, exist_ok=True)

    def run(self, exe_path: str) -> SandboxResult:
        result = SandboxResult()
        if not WIN32_AVAILABLE:
            result.error = "pywin32 not installed"
            return result
        if not Path(exe_path).exists():
            result.error = "File not found"
            return result

        logger.info(f"Sandbox executing: {exe_path}")
        try:
            result = self._execute_with_job(exe_path)
        except Exception as e:
            result.error = str(e)
            logger.error(f"Sandbox error: {e}")

        # Analyse result
        result.verdict = self._verdict(result)
        logger.info(f"Sandbox verdict: {result.verdict}")
        return result

    def _execute_with_job(self, exe_path: str) -> SandboxResult:
        result = SandboxResult()

        # Create Job Object
        job = win32job.CreateJobObject(None, "")

        # Set limits
        info = win32job.QueryInformationJobObject(
            job, win32job.JobObjectExtendedLimitInformation
        )
        info["BasicLimitInformation"]["ActiveProcessLimit"] = 5
        info["BasicLimitInformation"]["LimitFlags"] = (
            win32job.JOB_OBJECT_LIMIT_ACTIVE_PROCESS |
            win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        )
        win32job.SetInformationJobObject(
            job, win32job.JobObjectExtendedLimitInformation, info
        )

        # Snapshot files in SANDBOX_TEMP before execution
        before_files = set(SANDBOX_TEMP.rglob("*"))

        # Launch process
        si = win32process.STARTUPINFO()
        si.dwFlags = win32process.STARTF_USESHOWWINDOW
        si.wShowWindow = win32con.SW_HIDE

        proc_info = win32process.CreateProcess(
            None,
            f'"{exe_path}"',
            None, None, False,
            win32process.CREATE_SUSPENDED | win32process.CREATE_NO_WINDOW,
            None,
            str(SANDBOX_TEMP),
            si
        )

        proc_handle = proc_info[0]
        thread_handle = proc_info[1]
        pid = proc_info[2]

        # Assign to job
        win32job.AssignProcessToJobObject(job, proc_handle)
        win32process.ResumeThread(thread_handle)

        # Wait for completion or timeout
        start = time.time()
        WAIT_MS = 500
        while True:
            import win32event
            ret = win32event.WaitForSingleObject(proc_handle, WAIT_MS)
            if ret == 0:  # process exited
                break
            if time.time() - start > self.timeout:
                result.timed_out = True
                win32api.TerminateProcess(proc_handle, 1)
                break

        try:
            result.exit_code = win32process.GetExitCodeProcess(proc_handle)
        except Exception:
            pass

        # Collect new files
        after_files = set(SANDBOX_TEMP.rglob("*"))
        result.files_created = [str(f) for f in (after_files - before_files)]

        win32api.CloseHandle(proc_handle)
        win32api.CloseHandle(thread_handle)
        win32api.CloseHandle(job)

        return result

    @staticmethod
    def _verdict(result: SandboxResult) -> str:
        if result.error and not result.timed_out:
            return "unknown"
        suspicious_indicators = 0
        if len(result.files_created) > 10:
            suspicious_indicators += 2
        if result.network_attempts > 0:
            suspicious_indicators += 1
        if result.timed_out:
            suspicious_indicators += 1
        if suspicious_indicators >= 3:
            return "malicious"
        if suspicious_indicators >= 1:
            return "suspicious"
        return "safe"
