#!/usr/bin/env python3
"""Existing Mac-side scheduler retained for the v2 transition.

Scheduled prompts continue through ``MacCompanion.process_event`` and therefore
the desktop Bridge's authoritative submit controller.  The scheduler does not
gain an offline queue or bypass the user's existing desktop permission mode.
"""

import argparse
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set

try:
    from gateway.mac_companion.companion import MacCompanion
except ImportError:  # pragma: no cover - script execution fallback
    import sys

    sys.path.append(str(Path(__file__).resolve().parents[2]))
    from gateway.mac_companion.companion import MacCompanion


class ScheduleError(Exception):
    pass


@dataclass
class CronField:
    raw: str
    minimum: int
    maximum: int
    values: Optional[Set[int]]

    @classmethod
    def parse(cls, raw: str, minimum: int, maximum: int) -> "CronField":
        raw = raw.strip()
        if raw == "*":
            return cls(raw, minimum, maximum, None)
        values: Set[int] = set()
        for chunk in raw.split(","):
            if not chunk:
                raise ScheduleError(f"invalid cron field: {raw}")
            if "-" in chunk:
                start_s, end_s = chunk.split("-", 1)
                start, end = int(start_s), int(end_s)
                if start > end:
                    raise ScheduleError(f"invalid cron range: {chunk}")
                values.update(range(start, end + 1))
            else:
                values.add(int(chunk))
        if not values or min(values) < minimum or max(values) > maximum:
            raise ScheduleError(f"cron field out of range: {raw}")
        return cls(raw, minimum, maximum, values)

    def matches(self, value: int) -> bool:
        return self.values is None or value in self.values


@dataclass
class CronExpression:
    minute: CronField
    hour: CronField
    day: CronField
    month: CronField
    weekday: CronField

    @classmethod
    def parse(cls, raw: str) -> "CronExpression":
        parts = raw.split()
        if len(parts) != 5:
            raise ScheduleError("cron expression must have 5 fields")
        return cls(
            minute=CronField.parse(parts[0], 0, 59),
            hour=CronField.parse(parts[1], 0, 23),
            day=CronField.parse(parts[2], 1, 31),
            month=CronField.parse(parts[3], 1, 12),
            weekday=CronField.parse(parts[4], 0, 6),
        )

    def matches(self, moment: datetime) -> bool:
        cron_weekday = (moment.weekday() + 1) % 7
        return (
            self.minute.matches(moment.minute)
            and self.hour.matches(moment.hour)
            and self.day.matches(moment.day)
            and self.month.matches(moment.month)
            and self.weekday.matches(cron_weekday)
        )


@dataclass
class ScheduledTask:
    name: str
    cron: CronExpression
    prompt: str
    catch_up: bool = False

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScheduledTask":
        name = str(data.get("name", "")).strip()
        prompt = str(data.get("prompt", "")).strip()
        cron = str(data.get("cron", "")).strip()
        if not name:
            raise ScheduleError("scheduled task name is required")
        if not prompt:
            raise ScheduleError(f"scheduled task {name} has empty prompt")
        if not cron:
            raise ScheduleError(f"scheduled task {name} has empty cron")
        return cls(name=name, cron=CronExpression.parse(cron), prompt=prompt, catch_up=bool(data.get("catch_up", False)))

    def delivery_id_for(self, moment: datetime) -> str:
        stamp = moment.strftime("%Y%m%d%H%M")
        safe_name = "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in self.name).strip("-")
        return f"schedule-{safe_name}-{stamp}"


@dataclass
class SchedulerState:
    delivered_ids: Set[str]

    @classmethod
    def load(cls, path: Path) -> "SchedulerState":
        if not path.exists():
            return cls(delivered_ids=set())
        data = json.loads(path.read_text(encoding="utf-8"))
        return cls(delivered_ids=set(data.get("delivered_ids", [])))

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"delivered_ids": sorted(self.delivered_ids)}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


class ScheduledPromptRunner:
    def __init__(self, tasks: Iterable[ScheduledTask], state: SchedulerState):
        self.tasks = list(tasks)
        self.state = state

    @classmethod
    def from_file(cls, tasks_path: Path, state_path: Path) -> "ScheduledPromptRunner":
        data = json.loads(tasks_path.read_text(encoding="utf-8"))
        tasks = [ScheduledTask.from_dict(item) for item in data.get("tasks", [])]
        return cls(tasks, SchedulerState.load(state_path))

    def due_tasks(self, moment: datetime) -> List[ScheduledTask]:
        return [task for task in self.tasks if task.cron.matches(moment)]

    def run_due(self, companion: MacCompanion, moment: datetime) -> List[Dict[str, Any]]:
        receipts = []
        for task in self.due_tasks(moment):
            delivery_id = task.delivery_id_for(moment)
            if delivery_id in self.state.delivered_ids:
                continue
            event = {
                "id": 0,
                "type": "schedule.submit",
                "source_role": "scheduler",
                "delivery_id": delivery_id,
                "body": {"payload": {"prompt": task.prompt, "schedule_name": task.name}},
            }
            receipts.append(companion.process_event(event))
            self.state.delivered_ids.add(delivery_id)
        return [receipt for receipt in receipts if receipt]


def load_tasks(path: Path) -> List[ScheduledTask]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return [ScheduledTask.from_dict(item) for item in data.get("tasks", [])]


def main() -> None:
    parser = argparse.ArgumentParser(description="Run due Claudian Remote scheduled prompts once")
    parser.add_argument("--tasks", required=True, help="Path to scheduled_tasks.json")
    parser.add_argument("--state", required=True, help="Path to scheduler state JSON")
    parser.add_argument("--companion-config", required=True, help="Path to Mac companion config JSON")
    args = parser.parse_args()

    from gateway.mac_companion.companion import CompanionConfig

    runner = ScheduledPromptRunner.from_file(Path(args.tasks), Path(args.state))
    companion = MacCompanion.from_config(CompanionConfig.from_file(Path(args.companion_config)))
    receipts = runner.run_due(companion, datetime.now())
    runner.state.save(Path(args.state))
    print(json.dumps({"ok": True, "receipts": receipts}, ensure_ascii=False))


if __name__ == "__main__":
    main()
