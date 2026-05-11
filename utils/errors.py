"""
utils/errors.py — Structured error types for SecureNova

Replaces silent failures with typed, loggable, GUI-reportable errors.
"""
import logging
import traceback
from datetime import datetime
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)


class ScanError(Exception):
    """Base error for all scan/monitor operations."""

    def __init__(self, message: str, source: str = "", path: str = "",
                 severity: str = "medium", recoverable: bool = True):
        super().__init__(message)
        self.message = message
        self.source = source
        self.path = path
        self.severity = severity
        self.recoverable = recoverable
        self.timestamp = datetime.now().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "error_type": self.__class__.__name__,
            "message": self.message,
            "source": self.source,
            "path": self.path,
            "severity": self.severity,
            "recoverable": self.recoverable,
            "timestamp": self.timestamp,
        }


class PermissionDeniedError(ScanError):
    """Raised when a scan/clean operation lacks required permissions."""

    def __init__(self, path: str, source: str = "", operation: str = "access"):
        super().__init__(
            f"Permission denied: cannot {operation} '{path}'",
            source=source, path=path, severity="medium", recoverable=True
        )
        self.operation = operation


class ModuleUnavailableError(ScanError):
    """Raised when an optional dependency or module is missing."""

    def __init__(self, module_name: str, source: str = ""):
        super().__init__(
            f"Module '{module_name}' is not available",
            source=source, severity="low", recoverable=True
        )
        self.module_name = module_name


class SafetyBlockedError(ScanError):
    """Raised when a safety check prevents an operation on a protected resource."""

    def __init__(self, path: str, reason: str = "system_protected", source: str = ""):
        super().__init__(
            f"Safety blocked: '{path}' — {reason}",
            source=source, path=path, severity="info", recoverable=False
        )
        self.reason = reason


class ScanTimeoutError(ScanError):
    """Raised when a scan operation exceeds its timeout."""

    def __init__(self, path: str, timeout_seconds: int, source: str = ""):
        super().__init__(
            f"Scan timeout ({timeout_seconds}s) on '{path}'",
            source=source, path=path, severity="low", recoverable=True
        )
        self.timeout_seconds = timeout_seconds


def error_to_alert(error: Exception, source: str = "") -> Dict[str, Any]:
    """Convert any exception to a GUI-compatible alert dict."""
    if isinstance(error, ScanError):
        return {
            "type": "scan_error",
            "severity": error.severity,
            "source": error.source or source,
            "detail": error.message,
            "path": error.path,
            "recoverable": error.recoverable,
            "timestamp": error.timestamp,
        }
    return {
        "type": "scan_error",
        "severity": "medium",
        "source": source,
        "detail": str(error),
        "path": "",
        "recoverable": True,
        "timestamp": datetime.now().isoformat(),
    }


def collect_errors(func):
    """Decorator that catches exceptions and appends to an errors list.
    The decorated function must accept `_errors: list` kwarg or the instance
    must have a `_errors` attribute."""
    def wrapper(*args, **kwargs):
        errors_list = kwargs.pop("_errors", None)
        if errors_list is None and args and hasattr(args[0], "_errors"):
            errors_list = args[0]._errors
        try:
            return func(*args, **kwargs)
        except ScanError as e:
            logger.warning(f"[{e.source}] {e.message}")
            if errors_list is not None:
                errors_list.append(e.to_dict())
        except PermissionError as e:
            err = PermissionDeniedError(str(e), source=func.__qualname__)
            logger.warning(err.message)
            if errors_list is not None:
                errors_list.append(err.to_dict())
        except Exception as e:
            err = ScanError(str(e), source=func.__qualname__,
                            severity="medium", recoverable=True)
            logger.error(f"[{func.__qualname__}] {e}")
            if errors_list is not None:
                errors_list.append(err.to_dict())
        return None
    return wrapper
