"""
monitor/startup_manager.py — Startup item manager (registry + folder + scheduler)
"""
import logging
import subprocess
from pathlib import Path
from typing import List

logger = logging.getLogger(__name__)

STARTUP_FOLDER = Path.home() / r"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"


def _query_scheduled_tasks() -> List[dict]:
    try:
        result = subprocess.run(
            ["schtasks", "/query", "/fo", "CSV", "/v"],
            capture_output=True, text=True, timeout=15
        )
        tasks = []
        lines = result.stdout.splitlines()
        if len(lines) < 2:
            return []
        headers = [h.strip('"') for h in lines[0].split('","')]
        for line in lines[1:]:
            parts = line.split('","')
            if len(parts) == len(headers):
                d = {h: p.strip('"') for h, p in zip(headers, parts)}
                if d.get("Status") in ("Ready", "Running"):
                    tasks.append({
                        "name": d.get("TaskName", ""),
                        "path": d.get("Task To Run", ""),
                        "location": "TaskScheduler",
                        "trusted": True,
                    })
        return tasks
    except Exception as e:
        logger.error(f"schtasks query error: {e}")
        return []


def _get_startup_folder_items() -> List[dict]:
    items = []
    if STARTUP_FOLDER.exists():
        for f in STARTUP_FOLDER.iterdir():
            items.append({
                "name": f.name,
                "path": str(f),
                "location": "StartupFolder",
                "trusted": True,
            })
    return items


class StartupManager:
    def __init__(self, db=None, registry_watcher=None,
                 on_alert=None):
        self.db = db
        self.registry_watcher = registry_watcher
        self.on_alert = on_alert

    def get_all_startup_items(self) -> List[dict]:
        items = []
        if self.registry_watcher:
            items += self.registry_watcher.get_startup_items()
        items += _get_startup_folder_items()
        items += _query_scheduled_tasks()
        return items

    def snapshot_all(self) -> None:
        for item in self.get_all_startup_items():
            if self.db:
                self.db.snapshot_startup_item(
                    item["name"], item.get("path", ""),
                    item["location"]
                )
        logger.info("Startup baseline snapshot taken")
