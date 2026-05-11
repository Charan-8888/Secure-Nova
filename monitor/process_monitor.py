"""
monitor/process_monitor.py — Behavioral process monitor
"""
import logging
import os
import threading
import time
from collections import defaultdict, deque
from typing import Callable, Dict, List, Optional, Set

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    logging.warning("psutil not installed — process monitor disabled")

logger = logging.getLogger(__name__)

try:
    from scanner.behavior_engine import BehaviorEngine
    BEHAVIOR_AVAILABLE = True
except ImportError:
    BEHAVIOR_AVAILABLE = False

# ─── Behavior thresholds ───────────────────────────────────────────────────
RANSOMWARE_FILE_RATE   = 30    # files/min
RANSOMWARE_CPU         = 60.0  # %
CRYPTOMINER_CPU        = 85.0  # %
CRYPTOMINER_SUSTAINED  = 60    # seconds
MASS_DELETE_COUNT      = 10
MASS_DELETE_WINDOW     = 5     # seconds
CPU_HISTORY_LEN        = 60    # samples (2s each → 2 min)


class ProcessRecord:
    def __init__(self, pid: int, name: str, path: str, start_time: float):
        self.pid = pid
        self.name = name
        self.path = path
        self.start_time = start_time
        self.cpu_history: deque = deque(maxlen=CPU_HISTORY_LEN)
        self.file_ops_per_min: deque = deque(maxlen=60)
        self.delete_events: deque = deque(maxlen=200)   # timestamps
        self.connections: List[dict] = []
        self.alerts_raised: Set[str] = set()
        self.suspicious_score: int = 0


class ProcessMonitor:
    """
    Polls all running processes every 2 seconds and applies heuristic
    behavior rules to detect ransomware, cryptominers, mass-deletion, etc.
    """

    def __init__(self, config: dict, db=None,
                 on_alert: Optional[Callable[[dict], None]] = None):
        self.config = config
        self.db = db
        self.on_alert = on_alert
        self._records: Dict[int, ProcessRecord] = {}
        self._whitelist: Set[str] = set(config.get("whitelist_processes", []))
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._poll_interval = config.get("process_poll_interval", 2)
        self._baseline_taken = False
        self._behavior: Optional[BehaviorEngine] = None
        if BEHAVIOR_AVAILABLE:
            self._behavior = BehaviorEngine(on_alert=on_alert)

    # ------------------------------------------------------------------ #
    #  Control                                                              #
    # ------------------------------------------------------------------ #
    def start(self) -> None:
        if not PSUTIL_AVAILABLE:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run, name="ProcessMonitor", daemon=True)
        self._thread.start()
        logger.info("Process monitor started")

    def stop(self) -> None:
        self._running = False

    # ------------------------------------------------------------------ #
    #  Main loop                                                            #
    # ------------------------------------------------------------------ #
    def _run(self) -> None:
        while self._running:
            try:
                self._poll()
            except Exception as e:
                logger.error(f"Process monitor error: {e}")
            time.sleep(self._poll_interval)

    def _poll(self) -> None:
        now = time.time()
        current_pids: Set[int] = set()

        for proc in psutil.process_iter(["pid", "name", "exe", "create_time", "cpu_percent",
                                          "memory_info", "connections", "status"]):
            try:
                info = proc.info
                pid = info["pid"]
                current_pids.add(pid)

                if pid not in self._records:
                    rec = ProcessRecord(
                        pid, info["name"] or "", info["exe"] or "",
                        info["create_time"] or now
                    )
                    self._records[pid] = rec
                    if not self._baseline_taken:
                        self._take_baseline(rec)
                    else:
                        self._check_new_process(rec)

                rec = self._records[pid]
                cpu = proc.cpu_percent(interval=None)
                rec.cpu_history.append(cpu)
                try:
                    rec.connections = [
                        {"laddr": str(c.laddr), "raddr": str(c.raddr),
                         "status": c.status, "type": c.type}
                        for c in (info.get("connections") or [])
                    ]
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass

                self._apply_rules(rec, now)

                # Behavioral analysis (advanced rules)
                if self._behavior:
                    try:
                        proc_obj = psutil.Process(pid)
                        parent_name = ""
                        try:
                            parent = proc_obj.parent()
                            parent_name = parent.name() if parent else ""
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass
                        cmdline = " ".join(proc_obj.cmdline()) if proc_obj.cmdline() else ""
                        self._behavior.analyze_process({
                            "pid": pid,
                            "name": rec.name,
                            "exe": rec.path,
                            "cmdline": cmdline,
                            "parent_name": parent_name,
                        })
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        # Remove stale records
        stale = set(self._records.keys()) - current_pids
        for pid in stale:
            if self._behavior:
                self._behavior.clear_process(pid)
            del self._records[pid]

        if not self._baseline_taken:
            self._baseline_taken = True

    def _take_baseline(self, rec: ProcessRecord) -> None:
        if self.db:
            self.db.snapshot_process(rec.name, rec.path)

    def _check_new_process(self, rec: ProcessRecord) -> None:
        if rec.name.lower() in {w.lower() for w in self._whitelist}:
            return
        if self.db and not self.db.is_process_trusted(rec.name):
            self._emit_alert({
                "type": "new_process",
                "severity": "low",
                "pid": rec.pid,
                "name": rec.name,
                "path": rec.path,
                "detail": "New process not in trusted baseline",
            })

    # ------------------------------------------------------------------ #
    #  Behavioral rules                                                     #
    # ------------------------------------------------------------------ #
    def _apply_rules(self, rec: ProcessRecord, now: float) -> None:
        name_lower = rec.name.lower()
        if name_lower in {w.lower() for w in self._whitelist}:
            return

        # Rule 1 — Ransomware: high file ops + high CPU
        if len(rec.cpu_history) >= 5:
            avg_cpu = sum(list(rec.cpu_history)[-5:]) / 5
            # file_ops_per_min: injected externally via record_file_op()
            ops = len(rec.file_ops_per_min)
            if avg_cpu > RANSOMWARE_CPU and ops > RANSOMWARE_FILE_RATE:
                self._flag(rec, "ransomware_pattern",
                           f"CPU={avg_cpu:.0f}% + {ops} file ops/min", "critical")

        # Rule 2 — Cryptominer: sustained high CPU
        if len(rec.cpu_history) >= CRYPTOMINER_SUSTAINED // self._poll_interval:
            history_slice = list(rec.cpu_history)[-(CRYPTOMINER_SUSTAINED // self._poll_interval):]
            if min(history_slice) > CRYPTOMINER_CPU:
                self._flag(rec, "cryptominer_pattern",
                           f"Sustained CPU>{CRYPTOMINER_CPU}% for >{CRYPTOMINER_SUSTAINED}s", "high")

        # Rule 3 — Mass deletion
        recent_deletes = [t for t in rec.delete_events if now - t < MASS_DELETE_WINDOW]
        if len(recent_deletes) >= MASS_DELETE_COUNT:
            self._flag(rec, "mass_deletion",
                       f"{len(recent_deletes)} files deleted in <{MASS_DELETE_WINDOW}s", "critical")

        # Rule 6 — Network phone-home: unknown process with outbound connection
        if rec.connections and not self._is_known_process(rec.name):
            if "new_outbound" not in rec.alerts_raised:
                outbound = [c for c in rec.connections if c.get("raddr") and c["raddr"] != "()"]
                if outbound:
                    self._flag(rec, "network_phone_home",
                               f"Unknown process opened {len(outbound)} outbound connection(s)", "medium")

    def _is_known_process(self, name: str) -> bool:
        lower = name.lower()
        return (lower in {w.lower() for w in self._whitelist} or
                (self.db and self.db.is_process_trusted(name)))

    def _flag(self, rec: ProcessRecord, alert_type: str, detail: str, severity: str) -> None:
        if alert_type in rec.alerts_raised:
            return
        rec.alerts_raised.add(alert_type)
        logger.warning(f"[{severity.upper()}] {alert_type} | PID={rec.pid} | {rec.name} | {detail}")
        alert = {
            "type": alert_type,
            "severity": severity,
            "pid": rec.pid,
            "name": rec.name,
            "path": rec.path,
            "detail": detail,
        }
        if self.db:
            self.db.log_threat(alert_type, severity, rec.path, detail, "")
        if self.on_alert:
            self.on_alert(alert)

    # ------------------------------------------------------------------ #
    #  External hooks                                                       #
    # ------------------------------------------------------------------ #
    def record_file_op(self, pid: int) -> None:
        if pid in self._records:
            self._records[pid].file_ops_per_min.append(time.time())

    def record_delete(self, pid: int) -> None:
        if pid in self._records:
            self._records[pid].delete_events.append(time.time())

    def kill_process(self, pid: int) -> bool:
        try:
            psutil.Process(pid).kill()
            logger.info(f"Killed process PID={pid}")
            return True
        except Exception as e:
            logger.error(f"Could not kill PID={pid}: {e}")
            return False

    def get_process_list(self) -> List[dict]:
        result = []
        for pid, rec in list(self._records.items()):
            cpu = rec.cpu_history[-1] if rec.cpu_history else 0
            try:
                proc = psutil.Process(pid)
                mem = proc.memory_info().rss // 1024 // 1024
                status = proc.status()
            except Exception:
                mem, status = 0, "?"
            result.append({
                "pid": pid,
                "name": rec.name,
                "path": rec.path,
                "cpu": round(cpu, 1),
                "mem_mb": mem,
                "status": status,
                "suspicious": len(rec.alerts_raised) > 0,
                "alerts": list(rec.alerts_raised),
            })
        return sorted(result, key=lambda x: x["cpu"], reverse=True)

    def trust_process(self, pid: int) -> None:
        if pid in self._records:
            rec = self._records[pid]
            self._whitelist.add(rec.name)
            if self.db:
                self.db.trust_process(rec.name, rec.path)
            logger.info(f"Trusted: {rec.name}")
