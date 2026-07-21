import copy

import pytest

from installer.claudian_remote_lifecycle.inspect import Inspector
from installer.claudian_remote_lifecycle.plan import EnvironmentDrift, PlanBuilder, PlanError, validate_plan_environment
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
