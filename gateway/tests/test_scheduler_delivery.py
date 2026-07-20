from datetime import datetime

import pytest

from gateway.mac_companion.companion import CompanionConfig, MacCompanion
from gateway.mac_companion.scheduler import CronExpression, ScheduleError, ScheduledPromptRunner, ScheduledTask, SchedulerState
from gateway.tests.test_mac_companion import FakeAdapter, FakeRelay


def companion():
    return MacCompanion(
        CompanionConfig(
            relay_base_url="https://relay.example.invalid",
            relay_token="mac-relay-token",
            pairing_id="room-a",
            adapter_base_url="http://127.0.0.1:27123",
            adapter_token="local-rest-token",
        ),
        FakeRelay(),
        FakeAdapter(),
    )


def task(name="morning-sync", cron="30 7 * * *", prompt="sync please"):
    return ScheduledTask.from_dict({"name": name, "cron": cron, "prompt": prompt})


def test_morning_sync_schedule_produces_prompt_at_expected_local_time():
    runner = ScheduledPromptRunner([task()], SchedulerState(delivered_ids=set()))
    mac = companion()

    receipts = runner.run_due(mac, datetime(2026, 6, 28, 7, 30))

    assert len(receipts) == 1
    assert mac.adapter.submitted[0]["text"] == "sync please"
    assert mac.adapter.submitted[0]["delivery_id"] == "schedule-morning-sync-202606280730"


def test_missed_schedule_does_not_duplicate_after_restart_without_catchup():
    state = SchedulerState(delivered_ids={"schedule-morning-sync-202606280730"})
    runner = ScheduledPromptRunner([task()], state)
    mac = companion()

    receipts = runner.run_due(mac, datetime(2026, 6, 28, 7, 30))

    assert receipts == []
    assert mac.adapter.submitted == []


def test_scheduled_prompt_uses_same_receipt_format_as_mobile_message():
    runner = ScheduledPromptRunner([task(prompt="shared path")], SchedulerState(delivered_ids=set()))
    mac = companion()

    receipt = runner.run_due(mac, datetime(2026, 6, 28, 7, 30))[0]

    assert receipt["type"] == "message.receipt"
    assert receipt["target_role"] == "mobile"
    assert receipt["body"]["payload"]["status"] == "accepted"


def test_scheduler_rejects_empty_prompt_and_invalid_cron():
    with pytest.raises(ScheduleError):
        ScheduledTask.from_dict({"name": "empty", "cron": "30 7 * * *", "prompt": ""})
    with pytest.raises(ScheduleError):
        CronExpression.parse("not a cron")
    with pytest.raises(ScheduleError):
        ScheduledTask.from_dict({"name": "bad", "cron": "99 7 * * *", "prompt": "x"})
