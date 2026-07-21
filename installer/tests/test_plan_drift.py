import copy

import pytest

from installer.claudian_remote_lifecycle.inspect import Inspector
from installer.claudian_remote_lifecycle.plan import (
    EnvironmentDrift,
    PlanBuilder,
    PlanError,
    PlanStore,
    validate_mutation_environment,
    validate_plan_environment,
)
from installer.tests.test_inspect import FakeProbe


def test_identical_snapshot_yields_identical_canonical_plan():
    snapshot = Inspector(FakeProbe()).snapshot()
    builder = PlanBuilder()
    first = builder.build(snapshot, mode="local_tailscale")
    second = builder.build(copy.deepcopy(snapshot), mode="local_tailscale")

    assert first == second
    assert first["plan_id"].startswith("plan-")
    assert first["mutation_performed"] is False
    assert first["topology"]["silent_fallback"] is False
    validate_plan_environment(first, snapshot)


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


def test_trusted_lan_remains_release_blocked_until_real_network_evidence_exists():
    snapshot = Inspector(FakeProbe()).snapshot()
    plan = PlanBuilder().build(snapshot, mode="local_lan")
    assert "trusted_lan_not_release_eligible" in plan["blockers"]
    assert plan["topology"]["silent_fallback"] is False


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
    from installer.claudian_remote_lifecycle.inspect import content_id
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
    from installer.claudian_remote_lifecycle.inspect import content_id
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
    from installer.claudian_remote_lifecycle.inspect import content_id
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
