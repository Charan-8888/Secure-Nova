"""
tests/test_events.py — Event bus tests

Covers: publish/subscribe, filtering, history, severity ordering,
legacy alert bridge, deduplication, and thread safety.
"""
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.event_bus import EventBus, SecurityEvent, EventTypes, create_alert_bridge


class TestSecurityEvent:
    def test_create_event(self):
        evt = SecurityEvent("threat_detected", "high", "file_scanner",
                            {"path": "/test/file"})
        assert evt.event_type == "threat_detected"
        assert evt.severity == "high"
        assert evt.source == "file_scanner"
        assert evt.payload["path"] == "/test/file"
        assert evt.timestamp is not None

    def test_to_dict(self):
        evt = SecurityEvent("scan_complete", "info", "full_scan")
        d = evt.to_dict()
        assert "timestamp" in d
        assert d["event_type"] == "scan_complete"
        assert d["severity"] == "info"

    def test_to_alert(self):
        evt = SecurityEvent("threat_detected", "high", "file_scanner",
                            {"detail": "EICAR found", "path": "/test"})
        alert = evt.to_alert()
        assert alert["type"] == "threat_detected"
        assert alert["severity"] == "high"
        assert alert["detail"] == "EICAR found"

    def test_severity_level_ordering(self):
        info = SecurityEvent("test", "info", "test")
        high = SecurityEvent("test", "high", "test")
        critical = SecurityEvent("test", "critical", "test")
        assert info.severity_level < high.severity_level < critical.severity_level


class TestEventBusPublishSubscribe:
    def test_subscribe_and_receive(self):
        bus = EventBus()
        received = []
        bus.subscribe("test_event", lambda e: received.append(e))
        bus.emit("test_event", "info", "test", detail="hello")
        assert len(received) == 1
        assert received[0].payload["detail"] == "hello"

    def test_multiple_subscribers(self):
        bus = EventBus()
        r1, r2 = [], []
        bus.subscribe("multi", lambda e: r1.append(e))
        bus.subscribe("multi", lambda e: r2.append(e))
        bus.emit("multi", "info", "test")
        assert len(r1) == 1
        assert len(r2) == 1

    def test_subscribe_all(self):
        bus = EventBus()
        received = []
        bus.subscribe_all(lambda e: received.append(e))
        bus.emit("type_a", "info", "test")
        bus.emit("type_b", "low", "test")
        assert len(received) == 2

    def test_unsubscribe(self):
        bus = EventBus()
        received = []
        cb = lambda e: received.append(e)
        bus.subscribe("test", cb)
        bus.emit("test", "info", "test")
        assert len(received) == 1

        bus.unsubscribe("test", cb)
        bus.emit("test", "info", "test")
        assert len(received) == 1  # No new event

    def test_no_cross_event_delivery(self):
        bus = EventBus()
        received = []
        bus.subscribe("type_a", lambda e: received.append(e))
        bus.emit("type_b", "info", "test")
        assert len(received) == 0


class TestEventHistory:
    def test_history_stored(self):
        bus = EventBus()
        bus.emit("scan_started", "info", "full_scan")
        bus.emit("threat_detected", "high", "file_scanner")
        history = bus.get_history()
        assert len(history) == 2

    def test_history_filter_by_type(self):
        bus = EventBus()
        bus.emit("scan_started", "info", "full_scan")
        bus.emit("threat_detected", "high", "scanner")
        bus.emit("scan_complete", "info", "full_scan")
        threats = bus.get_history(event_type="threat_detected")
        assert len(threats) == 1

    def test_history_filter_by_severity(self):
        bus = EventBus()
        bus.emit("event1", "info", "test")
        bus.emit("event2", "high", "test")
        bus.emit("event3", "critical", "test")
        high_plus = bus.get_history(severity="high")
        assert len(high_plus) == 2  # high + critical

    def test_history_filter_by_source(self):
        bus = EventBus()
        bus.emit("event1", "info", "scanner")
        bus.emit("event2", "info", "monitor")
        scanner_events = bus.get_history(source="scanner")
        assert len(scanner_events) == 1

    def test_history_limit(self):
        bus = EventBus()
        for i in range(20):
            bus.emit("flood", "info", "test")
        limited = bus.get_history(limit=5)
        assert len(limited) == 5

    def test_clear_history(self):
        bus = EventBus()
        bus.emit("test", "info", "test")
        bus.clear_history()
        assert len(bus.get_history()) == 0


class TestEventStats:
    def test_stats_tracking(self):
        bus = EventBus()
        bus.emit("type_a", "info", "test")
        bus.emit("type_a", "info", "test")
        bus.emit("type_b", "high", "test")
        stats = bus.get_stats()
        assert stats["type_a"] == 2
        assert stats["type_b"] == 1


class TestAlertBridge:
    def test_bridge_converts_alert_to_event(self):
        bus = EventBus()
        received = []
        bus.subscribe("process_alert", lambda e: received.append(e))

        bridge = create_alert_bridge(bus)
        bridge({
            "type": "process_alert",
            "severity": "high",
            "detail": "Suspicious process detected",
            "pid": 1234,
        })

        assert len(received) == 1
        assert received[0].severity == "high"
        assert received[0].payload["detail"] == "Suspicious process detected"

    def test_bridge_missing_fields(self):
        bus = EventBus()
        received = []
        bus.subscribe_all(lambda e: received.append(e))
        bridge = create_alert_bridge(bus)
        bridge({"type": "minimal"})
        assert len(received) == 1
        assert received[0].severity == "medium"  # default


class TestThreadSafety:
    def test_concurrent_publish(self):
        bus = EventBus()
        received = []
        bus.subscribe_all(lambda e: received.append(e))

        def publish_batch(start):
            for i in range(50):
                bus.emit(f"concurrent_{start}", "info", "test", num=i)

        threads = [threading.Thread(target=publish_batch, args=(t,))
                   for t in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(received) == 250

    def test_subscriber_exception_isolation(self):
        bus = EventBus()
        good_received = []

        def bad_subscriber(e):
            raise ValueError("Intentional test error")

        def good_subscriber(e):
            good_received.append(e)

        bus.subscribe("test", bad_subscriber)
        bus.subscribe("test", good_subscriber)
        bus.emit("test", "info", "test")

        # Good subscriber should still receive despite bad one raising
        assert len(good_received) == 1
