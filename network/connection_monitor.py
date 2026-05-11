"""
network/connection_monitor.py — Live network connection tracker
"""
import logging
import socket
import threading
import time
from typing import Callable, Dict, List, Optional, Set

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

logger = logging.getLogger(__name__)

RISK_PORTS = {22, 23, 25, 110, 143, 3389, 4444, 5900, 6667, 8080, 9001}


class ConnectionMonitor:
    """
    Polls psutil.net_connections() and tracks new outbound connections.
    """

    def __init__(self, config: dict, db=None,
                 on_alert: Optional[Callable[[dict], None]] = None):
        self.config = config
        self.db = db
        self.on_alert = on_alert
        self._seen: Set[str] = set()
        self._connections: List[dict] = []
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._poll_interval = config.get("network_poll_interval", 5)

    def start(self) -> None:
        if not PSUTIL_AVAILABLE:
            logger.error("psutil not available — connection monitor disabled")
            return
        self._running = True
        self._thread = threading.Thread(target=self._run, name="ConnectionMonitor", daemon=True)
        self._thread.start()
        logger.info("Connection monitor started")

    def stop(self) -> None:
        self._running = False

    def _run(self) -> None:
        while self._running:
            try:
                self._poll()
            except Exception as e:
                logger.error(f"Connection monitor error: {e}")
            time.sleep(self._poll_interval)

    def _poll(self) -> None:
        connections = []
        try:
            for conn in psutil.net_connections(kind="inet"):
                if not conn.raddr:
                    continue
                remote_ip = conn.raddr.ip
                remote_port = conn.raddr.port
                pid = conn.pid or 0
                proto = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"

                proc_name = ""
                proc_path = ""
                try:
                    if pid:
                        p = psutil.Process(pid)
                        proc_name = p.name()
                        proc_path = p.exe()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

                conn_id = f"{pid}:{remote_ip}:{remote_port}"
                risk = self._assess_risk(remote_port, proc_name)

                rec = {
                    "pid": pid,
                    "process_name": proc_name,
                    "process_path": proc_path,
                    "local_addr": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "",
                    "remote_ip": remote_ip,
                    "remote_host": "",
                    "remote_port": remote_port,
                    "protocol": proto,
                    "status": conn.status,
                    "risk": risk,
                }

                if conn_id not in self._seen:
                    self._seen.add(conn_id)
                    rec["remote_host"] = self._resolve(remote_ip)
                    if self.db:
                        self.db.log_connection(
                            pid, proc_name,
                            rec["local_addr"], remote_ip,
                            rec["remote_host"], remote_port,
                            proto, conn.status, risk
                        )
                    if risk in ("medium", "high"):
                        self._emit_alert(rec)

                connections.append(rec)
        except Exception as e:
            logger.error(f"net_connections error: {e}")

        self._connections = connections

    @staticmethod
    def _resolve(ip: str) -> str:
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return ip

    @staticmethod
    def _assess_risk(port: int, proc_name: str) -> str:
        if port in RISK_PORTS:
            return "high"
        if port > 49000:
            return "low"
        return "medium" if port not in (80, 443, 53) else "low"

    def _emit_alert(self, rec: dict) -> None:
        alert = {
            "type": "network_phone_home",
            "severity": rec["risk"],
            "detail": f"{rec['process_name']} → {rec['remote_ip']}:{rec['remote_port']}",
            "pid": rec["pid"],
        }
        if self.on_alert:
            self.on_alert(alert)

    def get_connections(self) -> List[dict]:
        return list(self._connections)
