import json
from pathlib import Path

import pytest

from installer.claudian_remote_lifecycle.transaction import LocalTailscaleTransaction
from installer.claudian_remote_lifecycle.model import CHECKPOINT_SCHEMA_V1
from installer.tests.test_runtime_transaction import (
    FakeTailscale,
    FixtureReleaseSource,
    dependencies,
    plan,
)


FIXTURE_PATH = Path(__file__).parent / "fixtures" / "beta4" / "entry-states.json"
EXPECTED_FIXTURE_IDS = {
    "clean",
    "current",
    "legacy",
    "conflict",
    "recovery-required",
}
SYNTHETIC_RUNTIME_CREDENTIAL = "synthetic-runtime-canary"


class CountingTailscale(FakeTailscale):
    def __init__(self):
        super().__init__()
        self.preflight_calls = 0

    def preflight(self):
        self.preflight_calls += 1
        return super().preflight()


@pytest.fixture(scope="module")
def fixture_bundle():
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def fixture_by_id(bundle, fixture_id):
    return next(entry for entry in bundle["entries"] if entry["fixture_id"] == fixture_id)


def beta4_plan(bundle):
    value = plan()
    value["compatibility_set_id"] = bundle["baseline"]["compatibility_set_id"]
    return value


def materialize_vault(entry, vault):
    vault_state = entry["entry_state"]["vault"]
    plugin_root = vault / ".obsidian" / "plugins"
    for descriptor in vault_state["plugin_directories"]:
        destination = plugin_root / descriptor["id"]
        destination.mkdir(parents=True, exist_ok=True)
        (destination / "manifest.json").write_text(
            json.dumps({"id": descriptor["id"], "version": descriptor["version"]}),
            encoding="utf-8",
        )
        preferences = dict(descriptor.get("preferences") or {})
        if descriptor.get("legacy_credential_present") is True:
            assert descriptor["credential_value_in_fixture"] is False
            preferences["mobile_token"] = SYNTHETIC_RUNTIME_CREDENTIAL
        (destination / "data.json").write_text(json.dumps(preferences), encoding="utf-8")
    enabled = vault / ".obsidian" / "community-plugins.json"
    enabled.parent.mkdir(parents=True, exist_ok=True)
    enabled.write_text(json.dumps(vault_state["enabled_plugin_ids"]), encoding="utf-8")


def test_fixture_bundle_matches_the_frozen_beta4_release_metadata(fixture_bundle):
    package = json.loads((FIXTURE_PATH.parents[4] / "package.json").read_text(encoding="utf-8"))
    support = json.loads(
        (FIXTURE_PATH.parents[4] / "release" / "support-matrix.json").read_text(encoding="utf-8")
    )
    baseline = fixture_bundle["baseline"]

    assert fixture_bundle["fixture_schema"] == "claudian-remote.beta4-entry-states/v1"
    assert package["version"] == baseline["release_version"]
    assert support["release_version"] == baseline["release_version"]
    assert support["components"]["compatibility_set_id"] == baseline["compatibility_set_id"]
    assert {
        component: support["components"][component]
        for component in baseline["components"]
    } == baseline["components"]
    assert support["claudian"]["exact_version"] == baseline["claudian_exact_version"]
    assert baseline["topology"] == "local_tailscale"
    assert baseline["checkpoint_schema"] == CHECKPOINT_SCHEMA_V1


def test_fixture_bundle_is_secret_free_and_covers_every_beta4_entry_state(fixture_bundle):
    entries = fixture_bundle["entries"]
    assert len(entries) == len(EXPECTED_FIXTURE_IDS)
    assert {entry["fixture_id"] for entry in entries} == EXPECTED_FIXTURE_IDS

    encoded = FIXTURE_PATH.read_text(encoding="utf-8")
    for forbidden in (
        '"mobile_token"',
        '"relayToken"',
        '"password"',
        '"authorization"',
        "-----BEGIN",
        "https://",
        "http://",
        SYNTHETIC_RUNTIME_CREDENTIAL,
    ):
        assert forbidden not in encoded

    for entry in entries:
        assert set(entry) == {"fixture_id", "entry_state", "expected_beta4_behavior"}
        for plugin in entry["entry_state"]["vault"]["plugin_directories"]:
            if plugin.get("legacy_credential_present") is True:
                assert plugin["credential_value_in_fixture"] is False


@pytest.mark.parametrize(
    ("fixture_id", "route", "future_journey", "terminal_state", "code"),
    [
        ("clean", "local_tailscale_install", "fresh_install", "ready", "installation_ready"),
        ("current", "ordinary_signed_update", "current_update", "ready", "installation_ready"),
        (
            "legacy",
            "legacy_migration_gate",
            "legacy_upgrade",
            "blocked",
            "legacy_credential_revocation_unavailable",
        ),
        (
            "conflict",
            "coexistence_conflict",
            "coexistence_conflict",
            "blocked",
            "legacy_and_current_plugin_enabled",
        ),
        (
            "recovery-required",
            "existing_operation_recovery",
            "legacy_upgrade",
            "recovery_required",
            "installation_compensation_failed",
        ),
    ],
)
def test_fixture_behavior_contracts_are_explicit(
    fixture_bundle, fixture_id, route, future_journey, terminal_state, code
):
    expected = fixture_by_id(fixture_bundle, fixture_id)["expected_beta4_behavior"]
    assert expected["route"] == route
    assert expected["future_journey"] == future_journey
    assert expected["terminal_state"] == terminal_state
    assert expected["code"] == code


@pytest.mark.parametrize("fixture_id", ["clean", "current"])
def test_clean_and_current_fixtures_take_the_existing_install_path_without_legacy_calls(
    tmp_path, fixture_bundle, fixture_id
):
    entry = fixture_by_id(fixture_bundle, fixture_id)
    source = FixtureReleaseSource()
    tailscale = CountingTailscale()
    revocations = []
    deps, _ = dependencies(
        tmp_path,
        source=source,
        tailscale=tailscale,
        revoked=revocations,
    )
    materialize_vault(entry, deps.vault_path("vault-a"))

    result = LocalTailscaleTransaction(deps).install(
        beta4_plan(fixture_bundle),
        operation_id="op-" + ("1" if fixture_id == "clean" else "2") * 32,
    )

    expected = entry["expected_beta4_behavior"]
    assert result["state"] == expected["terminal_state"]
    assert result["code"] == expected["code"]
    assert revocations == []
    assert source.calls == expected["release_stage_calls"]
    assert tailscale.preflight_calls == 1


def test_legacy_fixture_reproduces_the_beta4_revoker_block_before_mutation(
    tmp_path, fixture_bundle
):
    entry = fixture_by_id(fixture_bundle, "legacy")
    source = FixtureReleaseSource()
    deps, _ = dependencies(tmp_path, source=source)
    deps.legacy_credential_revoker = None
    vault = deps.vault_path("vault-a")
    materialize_vault(entry, vault)

    result = LocalTailscaleTransaction(deps).install(
        beta4_plan(fixture_bundle), operation_id="op-" + "3" * 32
    )

    expected = entry["expected_beta4_behavior"]
    assert result["state"] == expected["terminal_state"]
    assert result["code"] == expected["code"]
    assert result["mutation_performed"] is False
    assert source.calls == expected["release_stage_calls"]
    assert (vault / ".obsidian" / "plugins" / "whale-agent-bridge").is_dir()
    assert not deps.layout.base.exists()


def test_conflict_fixture_blocks_before_release_or_plugin_mutation(tmp_path, fixture_bundle):
    entry = fixture_by_id(fixture_bundle, "conflict")
    source = FixtureReleaseSource()
    deps, _ = dependencies(tmp_path, source=source)
    vault = deps.vault_path("vault-a")
    materialize_vault(entry, vault)

    with pytest.raises(ValueError, match=entry["expected_beta4_behavior"]["code"]):
        LocalTailscaleTransaction(deps).install(
            beta4_plan(fixture_bundle), operation_id="op-" + "4" * 32
        )

    assert source.calls == entry["expected_beta4_behavior"]["release_stage_calls"]
    for plugin_id in ("whale-agent-bridge", "claudian-remote"):
        assert (vault / ".obsidian" / "plugins" / plugin_id).is_dir()


def test_recovery_fixture_has_complete_secret_free_effect_inventory_and_valid_beta4_action(
    tmp_path, fixture_bundle
):
    entry = fixture_by_id(fixture_bundle, "recovery-required")
    state = entry["entry_state"]
    checkpoint = state["lifecycle"]["checkpoint"]
    transaction = state["lifecycle"]["transaction"]
    runtime = state["runtime"]
    effect = state["credential_effect"]

    assert checkpoint["checkpoint_schema"] == fixture_bundle["baseline"]["checkpoint_schema"]
    assert transaction["transaction_schema"] == fixture_bundle["baseline"]["transaction_schema"]
    assert set(checkpoint) == {
        "checkpoint_schema",
        "operation_id",
        "command",
        "plan_id",
        "phase",
        "state",
        "completed_phases",
        "recorded_answers",
        "active_gate",
    }
    assert checkpoint["operation_id"] == transaction["operation_id"]
    assert checkpoint["plan_id"] == transaction["plan_id"]
    assert checkpoint["state"] == "recovery_required"
    assert checkpoint["phase"] == "installation_compensation_failed"
    assert checkpoint["completed_phases"] == transaction["completed_phases"] == ["staging"]
    assert set(runtime) == {
        "staging_artifacts",
        "active_release",
        "launch_agents",
        "tailscale_serve",
        "ownership",
    }
    assert set(runtime["launch_agents"]) == {"relay", "companion", "availability"}
    assert runtime["tailscale_serve"]["owned_by_operation"] is False
    assert runtime["ownership"] == {"receipt_present": False, "resources": []}
    assert effect == {
        "state": "not_applied",
        "authority_request_dispatched": False,
        "authority_receipt_present": False,
        "local_credential_present": True,
        "credential_value_in_fixture": False,
        "external_effect_observed": False,
    }

    deps, _ = dependencies(tmp_path)
    deps.layout.ensure()
    operation_file = deps.layout.state / f"{transaction['operation_id']}.transaction.json"
    operation_file.write_text(json.dumps(transaction), encoding="utf-8")
    partial = deps.layout.staging / runtime["staging_artifacts"][0]["name"]
    partial.mkdir(parents=True)

    lifecycle = LocalTailscaleTransaction(deps)
    assert lifecycle.recovery_action(checkpoint["operation_id"], checkpoint["plan_id"]) == "rollback"
    assert entry["expected_beta4_behavior"]["new_operation_allowed"] is False
