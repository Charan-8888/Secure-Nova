"""
utils/logger.py — Centralized logging for SecureNova

Provides:
- Standard text log (RotatingFileHandler, 5 MB, 3 backups)
- JSON security audit log (JSONL format, 10 MB, 5 backups)
- audit_log() convenience function for security events
"""
import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from logging.handlers import RotatingFileHandler

LOG_DIR = Path("logs")
LOG_FILE = LOG_DIR / "securenova.log"
AUDIT_FILE = LOG_DIR / "security_audit.jsonl"


class JSONSecurityHandler(logging.Handler):
    """Writes structured JSON lines to the security audit log."""

    def __init__(self, filepath: Path, max_bytes: int = 10 * 1024 * 1024,
                 backup_count: int = 5):
        super().__init__()
        self._handler = RotatingFileHandler(
            filepath, maxBytes=max_bytes, backupCount=backup_count, encoding="utf-8"
        )

    def emit(self, record: logging.LogRecord) -> None:
        try:
            entry = {
                "timestamp": datetime.fromtimestamp(record.created).isoformat(),
                "level": record.levelname,
                "source": record.name,
                "message": record.getMessage(),
            }
            # Merge extra security fields if present
            for key in ("event", "severity", "path", "detail", "pid",
                         "threat_name", "engine", "confidence", "action"):
                val = getattr(record, key, None)
                if val is not None:
                    entry[key] = val

            line = json.dumps(entry, default=str) + "\n"
            self._handler.stream = self._handler._open() if not hasattr(self._handler, 'stream') or self._handler.stream is None else self._handler.stream
            self._handler.emit(
                logging.makeLogRecord({"msg": line.rstrip(), "levelno": record.levelno})
            )
        except Exception:
            self.handleError(record)

    def close(self):
        self._handler.close()
        super().close()


_security_logger = None


def setup_logging(level: str = "INFO") -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    numeric_level = getattr(logging, level.upper(), logging.INFO)

    fmt = logging.Formatter(
        "[%(asctime)s] [%(levelname)-8s] [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    root = logging.getLogger()
    root.setLevel(numeric_level)

    # Prevent duplicate handlers on repeated calls
    if root.handlers:
        return

    # File handler — 5 MB max, 3 backups
    fh = RotatingFileHandler(LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8")
    fh.setFormatter(fmt)
    root.addHandler(fh)

    # Console handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(fmt)
    root.addHandler(ch)

    # Security audit handler (JSON)
    global _security_logger
    _security_logger = logging.getLogger("securenova.audit")
    _security_logger.setLevel(logging.INFO)
    _security_logger.propagate = False

    audit_fh = RotatingFileHandler(
        AUDIT_FILE, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
    )
    audit_fmt = logging.Formatter("%(message)s")
    audit_fh.setFormatter(audit_fmt)
    _security_logger.addHandler(audit_fh)

    logging.info("SecureNova logging initialised — level=%s", level)


def audit_log(event: str, severity: str, source: str, **details) -> None:
    """Write a structured JSON entry to the security audit log.

    Usage:
        audit_log("threat_detected", "high", "file_scanner",
                  path="/some/file", threat_name="EICAR")
    """
    global _security_logger
    if _security_logger is None:
        _security_logger = logging.getLogger("securenova.audit")

    entry = {
        "timestamp": datetime.now().isoformat(),
        "event": event,
        "severity": severity,
        "source": source,
        **details,
    }
    _security_logger.info(json.dumps(entry, default=str))
