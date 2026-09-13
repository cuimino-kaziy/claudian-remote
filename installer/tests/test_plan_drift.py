import copy

import pytest

from installer.claudian_remote_lifecycle.inspect import Inspector, content_id
from installer.claudian_remote_lifecycle.plan import (
    EnvironmentDrift,
    PlanBuilder,
    PlanError,
    PlanStore,
    validate_mutation_environment,
    validate_plan_environment,
)
from installer.tests.test_inspect import FakeProbe


def _resign_snapshot(snapshot):
    snapshot["snapshot_id"] = content_id(
        "inspection", {key: value for key, value in snapshot.items() if key != "snapshot_id"}
    )
    return snapshot


def _snapshot_for_journey(
    journey,
    *,
    authority_capability="not_applicable",
    authority_adapter=None,
    existing_operation=None,
):
    probe = FakeProbe()
    original_installation = probe.installation
    lineage = {
        "current": {"present": False, "enabled": False, "recognized": True},
        "legacy": {"present": False, "enabled": False, "recognized": True},
    }
    if journey == "current_update":
        lineage["current"].update({"present": True, "enabled": True})
    elif journey == "legacy_upgrade":
        lineage["legacy"].update({"present": True, "enabled": True})
    elif journey == "coexistence_conflict":
        lineage["current"].update({"present": True, "enabled": True})
        lineage["legacy"].update({"present": True, "enabled": True})
    installation = {
        **original_installation(),
        "installed": journey == "current_update",
        "plugin_lineage": lineage,
        "legacy_authority_capability": authority_capability,
    }
    if authority_adapter is not None:
        installation["legacy_authority_adapter"] = authority_adapter
    if existing_operation is not None:
        installation["existing_operation"] = existing_operation
    probe.installation = lambda: installation
    return Inspector(probe).snapshot()


def test_identical_snapshot_yields_identical_canonical_plan():
    snapshot = Inspector(FakeProbe()).snapshot()
    builder = PlanBuilder()
    first = builder.build(snapshot, mode="local_tailscale")
    second = builder.build(copy.deepcopy(snapshot), mode="local_tailscale")

    assert first == second
    assert first["plan_id"].startswith("plan-")
    assert first["mutation_performed"] is False
    assert first["topology"]["silent_fallback"] is False
    assert first["journey"] == "fresh_install"
    assert first["target_compatibility_set"] == {
        "compatibility_set_id": first["compatibility_set_id"],
        "final_topology": "local_tailscale",
        "required_claudian_version": "2.2.6",
    }
    assert first["pairing_identity_policy"] == "not_applicable"
    assert first["recovery_policy"] == "rollback_pre_boundary"
    assert first["irreversible_boundary"] == {
        "boundary_id": "local_activation_commit",
        "crossed": False,
        "phase": "activation",
    }
    assert first["cancellation"]["available"] is True
    assert first["cancellation_available"] is True
    assert first["human_gates"] == first["gates"]
    recommended = [
        action
        for action in first["next_actions"]
        if action["recommended"] and action["executable"]
    ]
    assert recommended == [first["recommended_next_action"]]
    assert recommended[0]["command"] == "install"
    validate_plan_environment(first, snapshot)


@pytest.mark.parametrize("policy", ["preserve", "rotate"])
def test_current_update_pairing_policy_comes_from_explicit_builder_policy(policy):
    snapshot = _snapshot_for_journey("current_update")
    plan = PlanBuilder(current_update_pairing_identity_policy=policy).build(
        snapshot, mode="local_tailscale"
    )

    assert plan["journey"] == "current_update"
    assert plan["pairing_identity_policy"] == policy
    assert plan["legacy_authority"] == {
        "adapter": "not_applicable",
        "capability": "not_applicable",
    }
    pairing_gates = [
        gate for gate in plan["human_gates"] if gate["gate_type"] == "pairing_approval_required"
    ]
    assert bool(pairing_gates) is (policy == "rotate")


def test_current_update_plan_recommends_the_signed_update_command():
    snapshot = _snapshot_for_journey("current_update")

    plan = PlanBuilder().build(snapshot, mode="local_tailscale")

    assert plan["recommended_next_action"] == {
        "action_id": "execute_update_plan",
        "action_type": "lifecycle_command",
        "owner": "agent",
        "recommended": True,
        "executable": True,
        "command": "update",
        "parameters": {},
    }
    validate_plan_environment(plan, snapshot)


def test_pairing_policy_is_not_inferred_from_installed_version_or_mode():
    snapshot = _snapshot_for_journey("current_update")
    snapshot["installation"]["plugin_versions"] = ["0.1.0-unrelated"]
    _resign_snapshot(snapshot)

    assert (
        PlanBuilder(current_update_pairing_identity_policy="preserve")
        .build(snapshot, mode="local_tailscale")["pairing_identity_policy"]
        == "preserve"
    )
    with pytest.raises(PlanError, match="invalid_current_update_pairing_identity_policy"):
        PlanBuilder(current_update_pairing_identity_policy="guess").build(
            snapshot, mode="local_tailscale"
        )


@pytest.mark.parametrize(
    ("journey", "expected"),
    [
        ("fresh_install", "not_applicable"),
        ("legacy_upgrade", "not_applicable"),
    ],
)
def test_non_current_journeys_bind_pairing_policy_as_not_applicable(journey, expected):
    capability = "available" if journey == "legacy_upgrade" else "not_applicable"
    adapter = "recognized_vps" if journey == "legacy_upgrade" else None
    snapshot = _snapshot_for_journey(
        journey,
        authority_capability=capability,
        authority_adapter=adapter,
    )

    plan = PlanBuilder(current_update_pairing_identity_policy="rotate").build(
        snapshot, mode="local_tailscale"
    )
    assert plan["pairing_identity_policy"] == expected


def test_plan_consumes_inspector_journey_and_rejects_conflict_or_unfinished_operation():
    conflict = _snapshot_for_journey("coexistence_conflict")
    with pytest.raises(PlanError, match="coexistence_conflict"):
        PlanBuilder().build(conflict, mode="local_tailscale")

    unfinished = _snapshot_for_journey(
        "fresh_install",
        existing_operation={
            "operation_id": "op-" + "a" * 32,
            "terminal": False,
            "recommended_action": "rollback",
        },
    )
    assert unfinished["journey"]["journey"] == "unclassified"
    with pytest.raises(PlanError, match="operation_reconciliation_required"):
        PlanBuilder().build(unfinished, mode="local_tailscale")


def test_legacy_plan_binds_non_secret_authority_adapter_and_capability():
    snapshot = _snapshot_for_journey(
        "legacy_upgrade",
        authority_capability="available",
        authority_adapter="recognized_vps",
    )
    plan = PlanBuilder().build(snapshot, mode="local_tailscale")

    assert plan["journey"] == "legacy_upgrade"
    assert plan["legacy_authority"] == {
        "adapter": "recognized_vps",
        "capability": "available",
    }
    assert plan["irreversible_boundary"] == {
        "boundary_id": "legacy_credential_retirement_proof",
        "crossed": False,
        "phase": "retirement_reconciliation",
    }
    assert "legacy_credential_authority" in plan["affected_resources"]


@pytest.mark.parametrize("change", ["vault", "claudian", "network"])
def test_environment_drift_invalidates_plan_before_mutation(change):
    original = Inspector(FakeProbe()).snapshot()
    plan = PlanBuilder().build(original, mode="local_tailscale")
    if change == "vault":
        current = Inspector(FakeProbe(vaults=[{"vault_id": "vault-b", "display_name": "Other"}])).snapshot()
    elif change == "claudian":
        current = Inspector(FakeProbe(claudian_version="2.0.5")).snapshot()
    else:
        probe = FakeProbe()
        probe.network = lambda: {"tailscale_installed": True, "tailscale_logged_in": False}
        current = Inspector(probe).snapshot()
    with pytest.raises(EnvironmentDrift, match="environment_drift"):
        validate_plan_environment(plan, current)


def test_plan_rejects_missing_or_ambiguous_vault_and_tampering():
    builder = PlanBuilder()
    ambiguous = Inspector(FakeProbe(vaults=[{"vault_id": "a"}, {"vault_id": "b"}])).snapshot()
    with pytest.raises(PlanError, match="vault_selection_required"):
        builder.build(ambiguous, mode="local_tailscale")

    selected = builder.build(ambiguous, mode="local_tailscale", vault_id="a")
    selected["topology"]["silent_fallback"] = True
    with pytest.raises(PlanError, match="plan_integrity_failed"):
        validate_plan_environment(selected, ambiguous)

    altered_snapshot = copy.deepcopy(ambiguous)
    altered_snapshot["claudian"]["version"] = "9.9.9"
    with pytest.raises(PlanError, match="inspection_integrity_failed"):
        builder.build(altered_snapshot, mode="local_tailscale", vault_id="a")

    altered_support = copy.deepcopy(ambiguous)
    altered_support["support"]["reason_codes"] = []
    with pytest.raises(PlanError, match="inspection_integrity_failed"):
        builder.build(altered_support, mode="local_tailscale", vault_id="a")


def test_missing_secure_provisioning_is_an_explicit_fail_closed_bootstrap_gate():
    probe = FakeProbe()
    original_installation = probe.installation
    probe.installation = lambda: {
        **original_installation(),
        "secure_provisioning_available": False,
        "secure_provisioning_probe": "companion_route_unavailable",
    }
    snapshot = Inspector(probe).snapshot()
    plan = PlanBuilder().build(snapshot, mode="local_tailscale")
    assert "secure_provisioning_missing" in snapshot["support"]["reason_codes"]
    assert {
        "gate_type": "pairing_admin_bootstrap_required",
        "probe": "companion_secure_provisioning_available",
    } in plan["gates"]
    assert plan["mutation_performed"] is False


def test_beta5_write_plan_rejects_non_local_tailscale_topology():
    snapshot = Inspector(FakeProbe()).snapshot()
    for mode in ("local_lan", "remote_vps"):
        with pytest.raises(PlanError, match="unsupported_connection_mode"):
            PlanBuilder().build(snapshot, mode=mode)


@pytest.mark.parametrize("field", ["compatibility_set_id", "profile_mode", "profile_generation_id"])
def test_installed_release_or_profile_generation_drift_invalidates_plan(field):
    probe = FakeProbe()
    original_installation = probe.installation
    probe.installation = lambda: {
        **original_installation(),
        "compatibility_set_id": "claudian-remote-0.2.0-beta.1",
        "profile_mode": "local_tailscale",
        "profile_generation_id": "profile-generation-" + "a" * 64,
    }
    planned = Inspector(probe).snapshot()
    plan = PlanBuilder().build(planned, mode="local_tailscale")
    changed = copy.deepcopy(planned)
    changed["installation"][field] = "changed"
    changed["snapshot_id"] = content_id(
        "inspection", {key: value for key, value in changed.items() if key != "snapshot_id"}
    )
    with pytest.raises(EnvironmentDrift, match="environment_drift"):
        validate_mutation_environment(plan, planned, changed)


def test_plan_store_is_private_immutable_and_allows_only_declared_gate_drift(tmp_path):
    probe = FakeProbe()
    planned = Inspector(probe).snapshot()
    plan = PlanBuilder().build(planned, mode="local_tailscale")
    store = PlanStore(tmp_path / "state")
    store.write(plan, planned)
    restored_plan, restored_snapshot = store.read(plan["plan_id"])
    assert restored_plan == plan
    assert restored_snapshot == planned
    assert (tmp_path / "state" / "plans").stat().st_mode & 0o777 == 0o700
    assert store._path(plan["plan_id"]).stat().st_mode & 0o777 == 0o600

    after_login = copy.deepcopy(planned)
    after_login["network"]["tailscale_logged_in"] = not bool(
        after_login["network"].get("tailscale_logged_in")
    )
    after_login["snapshot_id"] = Inspector(FakeProbe()).snapshot()["snapshot_id"]
    # Re-sign the synthetic snapshot after the allowed external transition.
    after_login["snapshot_id"] = content_id(
        "inspection", {key: value for key, value in after_login.items() if key != "snapshot_id"}
    )
    validate_mutation_environment(plan, planned, after_login)

    changed = copy.deepcopy(after_login)
    changed["vaults"][0]["claudian_version"] = "2.0.5"
    changed["snapshot_id"] = content_id(
        "inspection", {key: value for key, value in changed.items() if key != "snapshot_id"}
    )
    with pytest.raises(EnvironmentDrift):
        validate_mutation_environment(plan, planned, changed)


def test_journey_or_legacy_authority_drift_invalidates_plan_before_mutation():
    planned = _snapshot_for_journey(
        "legacy_upgrade",
        authority_capability="available",
        authority_adapter="recognized_vps",
    )
    plan = PlanBuilder().build(planned, mode="local_tailscale")

    authority_changed = copy.deepcopy(planned)
    authority_changed["installation"]["legacy_authority_adapter"] = "local_managed_relay"
    _resign_snapshot(authority_changed)
    with pytest.raises(EnvironmentDrift, match="environment_drift"):
        validate_mutation_environment(plan, planned, authority_changed)

    reclassified = _snapshot_for_journey("current_update")
    with pytest.raises(EnvironmentDrift, match="environment_drift"):
        validate_mutation_environment(plan, planned, reclassified)


def test_resume_accepts_only_the_plan_owned_activation_transition():
    probe = FakeProbe()
    original_installation = probe.installation
    probe.installation = lambda: {
        **original_installation(),
        "compatibility_set_id": "claudian-remote-0.1.0",
        "profile_mode": "local_tailscale",
        "profile_generation_id": "profile-generation-" + "a" * 64,
    }
    planned = Inspector(probe).snapshot()
    plan = PlanBuilder().build(planned, mode="local_tailscale")
    current = copy.deepcopy(planned)
    current["installation"].update({
        "compatibility_set_id": plan["compatibility_set_id"],
        "profile_mode": "local_tailscale",
        "profile_generation_id": "profile-generation-" + "b" * 64,
    })
    current["snapshot_id"] = content_id(
        "inspection", {key: value for key, value in current.items() if key != "snapshot_id"}
    )

    with pytest.raises(EnvironmentDrift):
        validate_mutation_environment(plan, planned, current)
    validate_mutation_environment(plan, planned, current, allow_plan_target=True)

    current["installation"]["profile_mode"] = "remote_vps"
    current["snapshot_id"] = content_id(
        "inspection", {key: value for key, value in current.items() if key != "snapshot_id"}
    )
    with pytest.raises(EnvironmentDrift):
        validate_mutation_environment(plan, planned, current, allow_plan_target=True)
