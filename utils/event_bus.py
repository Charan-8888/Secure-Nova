"""
utils/event_bus.py — Centralized pub/sub event system for SecureNova

Decouples modules: publishers emit events, subscribers react.
Thread-safe, with optional event history for replay/debugging.
"""
import logging
import threading
import time
from collections import defaultdict, deque
from datetime import datetime
from typing import Callable, Dict, List, Optional, Any

logger = logging.getLogger(__name__)


class SecurityEvent:
    """Structured security event payload."""

    __slots__ = ("timestamp", "event_type", "severity", "source", "payload", "_id")

    SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

    def __init__(self, event_type: str, severity: str, source: str,
                 payload: Optional[Dict[str, Any]] = None):
        self.timestamp = datetime.now().isoformat()
        self.event_type = event_type
        self.severity = severity
        self.source = source
        self.payload = payload or {}
        self._id = f"{int(time.time() * 1000)}_{id(self)}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self._id,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "severity": self.severity,
            "source": self.source,
            **self.payload,
        }

    def to_alert(self) -> Dict[str, Any]:
        """Convert to legacy alert dict for backward compatibility."""
        return {
            "type": self.event_type,
            "severity": self.severity,
            "source": self.source,
            "detail": self.payload.get("detail", ""),
            "path": self.payload.get("path", ""),
            "timestamp": self.timestamp,
        }

    @property
    def severity_level(self) -> int:
        return self.SEVERITY_ORDER.get(self.severity, 2)

    def __repr__(self):
        return f"<SecurityEvent {self.event_type} [{self.severity}] from={self.source}>"


# ─── Well-known event types ──────────────────────────────────────────────
class EventTypes:
    THREAT_DETECTED = "threat_detected"
    THREAT_CLEANED = "threat_cleaned"
    SCAN_STARTED = "scan_started"
    SCAN_PROGRESS = "scan_progress"
    SCAN_COMPLETE = "scan_complete"
    SCAN_ERROR = "scan_error"
    PROCESS_ALERT = "process_alert"
    REGISTRY_CHANGE = "registry_change"
    NETWORK_ALERT = "network_alert"
    USB_DETECTED = "usb_detected"
    BEHAVIOR_ALERT = "behavior_alert"
    SAFETY_BLOCKED = "safety_blocked"
    QUARANTINE_ACTION = "quarantine_action"
    VALIDATION_RESULT = "validation_result"


class EventBus:
    """Thread-safe publish/subscribe event bus."""

    def __init__(self, history_size: int = 500):
        self._subscribers: Dict[str, List[Callable]] = defaultdict(list)
        self._global_subscribers: List[Callable] = []
        self._history: deque = deque(maxlen=history_size)
        self._lock = threading.Lock()
        self._stats: Dict[str, int] = defaultdict(int)

    def subscribe(self, event_type: str, callback: Callable[[SecurityEvent], None]) -> None:
        """Subscribe to a specific event type."""
        with self._lock:
            if callback not in self._subscribers[event_type]:
                self._subscribers[event_type].append(callback)

    def subscribe_all(self, callback: Callable[[SecurityEvent], None]) -> None:
        """Subscribe to all events."""
        with self._lock:
            if callback not in self._global_subscribers:
                self._global_subscribers.append(callback)

    def unsubscribe(self, event_type: str, callback: Callable) -> None:
        """Remove a subscription."""
        with self._lock:
            subs = self._subscribers.get(event_type, [])
            if callback in subs:
                subs.remove(callback)

    def publish(self, event: SecurityEvent) -> None:
        """Publish an event to all matching subscribers."""
        with self._lock:
            self._history.append(event)
            self._stats[event.event_type] += 1
            subscribers = list(self._subscribers.get(event.event_type, []))
            global_subs = list(self._global_subscribers)

        for cb in subscribers + global_subs:
            try:
                cb(event)
            except Exception as e:
                logger.error(f"Event subscriber error for {event.event_type}: {e}")

    def emit(self, event_type: str, severity: str, source: str, **payload) -> SecurityEvent:
        """Convenience: create and publish an event in one call."""
        event = SecurityEvent(event_type, severity, source, payload)
        self.publish(event)
        return event

    def get_history(self, event_type: str = None, severity: str = None,
                    source: str = None, limit: int = 100) -> List[Dict]:
        """Query event history with optional filters."""
        with self._lock:
            events = list(self._history)

        if event_type:
            events = [e for e in events if e.event_type == event_type]
        if severity:
            min_level = SecurityEvent.SEVERITY_ORDER.get(severity, 0)
            events = [e for e in events if e.severity_level >= min_level]
        if source:
            events = [e for e in events if e.source == source]

        return [e.to_dict() for e in events[-limit:]]

    def get_stats(self) -> Dict[str, int]:
        """Get event count by type."""
        with self._lock:
            return dict(self._stats)

    def clear_history(self) -> None:
        with self._lock:
            self._history.clear()


def create_alert_bridge(event_bus: EventBus) -> Callable[[dict], None]:
    """Create an on_alert callback that publishes to the event bus.
    This bridges old-style on_alert(dict) calls to the new event bus."""
    def bridge(alert: dict):
        event_bus.emit(
            event_type=alert.get("type", "unknown"),
            severity=alert.get("severity", "medium"),
            source=alert.get("source", "unknown"),
            detail=alert.get("detail", ""),
            path=alert.get("path", ""),
            pid=alert.get("pid", 0),
        )
    return bridge
