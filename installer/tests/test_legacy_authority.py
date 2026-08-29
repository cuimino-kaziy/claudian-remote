import base64
import hashlib
import hmac
import io
import json
import urllib.error
from dataclasses import replace

import pytest

from installer.claudian_remote_lifecycle.checkpoint import CheckpointStore, OperationLock
from installer.claudian_remote_lifecycle.legacy_authority import (
    AuthorityDescriptor,
    CapabilityAwareLegacyRetirementService,
    CredentialHandle,
    LegacyAuthorityTransport,
    LegacyCredentialRetirementService,
    LegacyRetirementOutcomeUnknown,
    OpaqueCredentialSlot,
    RetirementExpectation,
    RetirementIntent,
    RetirementReconciliationResult,
    RetirementProofCandidate,
    RetirementProofConsumer,
    RuntimeEvidenceVerifier,
    UrllibLegacyAuthorityTransport,
    canonical_retirement_payload,
    load_legacy_authority_profile,
)
from installer.claudian_remote_lifecycle.model import (
    ActionOwner,
    AmbiguityState,
    CredentialEffect,
    EffectDisposition,
    EffectSummary,
    Journey,
    NextAction,
    NextActionType,
    PairingIdentityPolicy,
    RecoveryPolicy,
)


NOW = 2_000_000_000
PLAN_ID = "plan-" + "a" * 64
OPERATION_ID = "op-" + "b" * 32
RELEASE_DIGEST = "1" * 64
HELPER_DIGEST = "2" * 64


def test_unconfigured_retirement_service_never_implies_human_authorization():
    class UnconfiguredRetirementService(LegacyCredentialRetirementService):
        def retire(self, **_kwargs):
            raise AssertionError("retire must not be called")

    assert (
        UnconfiguredRetirementService().authorized(
            operation_id=OPERATION_ID,
            plan_id=PLAN_ID,
        )
        is False
    )


class DeterministicEvidenceVerifier(RuntimeEvidenceVerifier):
    def __init__(self, key_id="runtime-key-a", key=b"test-runtime-key"):
        self.key_id = key_id
        self._key = key

    def sign(self, payload):
        return base64.b64encode(hmac.new(self._key, payload, hashlib.sha256).digest()).decode()

    def verify(self, *, payload, evidence, runtime_key_id):
        if runtime_key_id != self.key_id:
            raise ValueError("retirement_runtime_key_mismatch")
        expected = self.sign(payload)
        if not hmac.compare_digest(evidence, expected):
            raise ValueError("retirement_evidence_invalid")


def authority(**changes):
    value = {
        "authority_schema": "claudian-remote.legacy-authority/v1",
        "profile_id": "dogfood-local-v1",
        "protocol_version": "legacy-retirement/v1",
        "authority_instance_id": "authority-instance-a",
        "authority_origin": "https://relay.example:8443",
        "runtime_key_id": "runtime-key-a",
        "owner_id": "owner-a",
        "installation_id": "installation-a",
        "mac_id": "mac-a",
        "vault_id": "vault-a",
        "role": "mobile_remote",
    }
    value.update(changes)
    return AuthorityDescriptor.from_mapping(value)


def slot(**changes):
    value = {
        "slot_schema": "claudian-remote.legacy-credential-slot/v1",
        "slot_id": "slot-a",
        "owner_id": "owner-a",
        "installation_id": "installation-a",
        "vault_id": "vault-a",
        "role": "mobile_remote",
        "consumer_installation_ids": ["installation-a"],
        "old_generation": 7,
        "target_generation": 8,
    }
    value.update(changes)
    return OpaqueCredentialSlot.from_mapping(value)


def expectation(**changes):
    values = {
        "authority": authority(),
        "slot": slot(),
        "operation_id": OPERATION_ID,
        "plan_id": PLAN_ID,
        "release_digest": RELEASE_DIGEST,
        "helper_digest": HELPER_DIGEST,
        "nonce": "nonce-a",
        "idempotency_key": "idempotency-a",
        "not_before_epoch": NOW - 10,
    }
    values.update(changes)
    return RetirementExpectation(**values)


def proof_mapping(expected=None, *, outcome="retired", **changes):
    expected = expected or expectation()
    value = {
        "proof_schema": "claudian-remote.legacy-retirement-proof/v1",
        "outcome": outcome,
        "authority_instance_id": expected.authority.authority_instance_id,
        "authority_origin": expected.authority.authority_origin,
        "runtime_key_id": expected.authority.runtime_key_id,
        "owner_id": expected.authority.owner_id,
        "installation_id": expected.authority.installation_id,
        "mac_id": expected.authority.mac_id,
        "vault_id": expected.authority.vault_id,
        "role": expected.authority.role,
        "slot_id": expected.slot.slot_id,
        "old_generation": expected.slot.old_generation,
        "target_generation": expected.slot.target_generation,
        "operation_id": expected.operation_id,
        "plan_id": expected.plan_id,
        "release_digest": expected.release_digest,
        "helper_digest": expected.helper_digest,
        "nonce": expected.nonce,
        "idempotency_key": expected.idempotency_key,
        "issued_at_epoch": NOW - 2,
        "expires_at_epoch": NOW + 120,
    }
    value.update(changes)
    verifier = DeterministicEvidenceVerifier()
    value["evidence"] = verifier.sign(canonical_retirement_payload(value))
    return value


def checkpoint_store(tmp_path):
    store = CheckpointStore(tmp_path / "state")
    action = NextAction(
        action_id="reconcile-retirement-outcome",
        action_type=NextActionType.LIFECYCLE_COMMAND,
        owner=ActionOwner.AGENT,
        recommended=True,
        executable=True,
        command="resume",
        parameters={"operation_id_ref": "result.operation_id"},
    )
    checkpoint = store.create(
        command="install",
        plan_id=PLAN_ID,
        phase="prepared",
        journey=Journey.LEGACY_UPGRADE,
        irreversible_boundary_crossed=False,
        ambiguity_state=AmbiguityState.NOT_DISPATCHED,
        recovery_policy=RecoveryPolicy.NOT_APPLICABLE,
        effect_summary=EffectSummary(
            local_effect=EffectDisposition.UNCHANGED,
            remote_effect=EffectDisposition.UNCHANGED,
            credential_effect=CredentialEffect.ACTIVE,
            mutation_performed=False,
            owned_resource_count=0,
            effect_codes=(),
        ),
        next_actions=(),
        cancellation_available=False,
        pairing_identity_policy=PairingIdentityPolicy.NOT_APPLICABLE,
        prior_operation_terminal=True,
    )
    expected = expectation(operation_id=checkpoint["operation_id"])
    checkpoint = store.update(
        checkpoint["operation_id"],
        phase="retirement_reconciliation",
        ambiguity_state=AmbiguityState.RETIREMENT_OUTCOME_UNKNOWN,
        recovery_policy=RecoveryPolicy.RECONCILE_SAME_OPERATION,
        effect_summary=EffectSummary(
            local_effect=EffectDisposition.STAGED,
            remote_effect=EffectDisposition.CHANGED,
            credential_effect=CredentialEffect.OUTCOME_UNKNOWN,
            mutation_performed=True,
            owned_resource_count=2,
            effect_codes=("retirement_dispatched",),
        ),
        next_actions=(action,),
        recorded_answers={
            "retirement_intent": RetirementIntent.from_expectation(expected).to_mapping()
        },
    )
    assert checkpoint["operation_id"] != OPERATION_ID
    return store, checkpoint


def pre_dispatch_checkpoint_store(tmp_path):
    store = CheckpointStore(tmp_path / "state")
    resume = NextAction(
        action_id="resume-original-operation",
        action_type=NextActionType.LIFECYCLE_COMMAND,
        owner=ActionOwner.AGENT,
        recommended=True,
        executable=True,
        command="resume",
        parameters={"operation_id_ref": "checkpoint.operation_id"},
    )
    cancel = NextAction(
        action_id="cancel-original-operation",
        action_type=NextActionType.LIFECYCLE_COMMAND,
        owner=ActionOwner.AGENT,
        recommended=False,
        executable=True,
        command="cancel",
        parameters={"operation_id_ref": "result.operation_id"},
    )
    checkpoint = store.create(
        command="install",
        plan_id=PLAN_ID,
        phase="preparation",
        journey=Journey.LEGACY_UPGRADE,
        irreversible_boundary_crossed=False,
        ambiguity_state=AmbiguityState.NOT_DISPATCHED,
        recovery_policy=RecoveryPolicy.RETRY_SAME_OPERATION,
        effect_summary=EffectSummary(
            local_effect=EffectDisposition.STAGED,
            remote_effect=EffectDisposition.UNCHANGED,
            credential_effect=CredentialEffect.NOT_DISPATCHED,
            mutation_performed=True,
            owned_resource_count=1,
            effect_codes=("operation_staged",),
        ),
        next_actions=(resume, cancel),
        cancellation_available=True,
        pairing_identity_policy=PairingIdentityPolicy.NOT_APPLICABLE,
        prior_operation_terminal=True,
    )
    return store, checkpoint


def bound_expectation(checkpoint, **changes):
    values = {
        "operation_id": checkpoint["operation_id"],
        "plan_id": checkpoint["plan_id"],
    }
    values.update(changes)
    return expectation(**values)


def test_descriptor_normalizes_exact_https_origin_and_rejects_unsafe_shapes():
    assert authority(authority_origin="https://Relay.Example:443").authority_origin == "https://relay.example"
    for origin in (
        "http://relay.example",
        "https://user@relay.example",
        "https://relay.example/path",
        "https://relay.example?x=1",
        "https://relay.example#fragment",
        "https://[fe80::1%25en0]",
    ):
        with pytest.raises(ValueError, match="legacy_authority_origin_invalid"):
            authority(authority_origin=origin)


def test_slot_scope_must_be_exactly_one_owner_installation_and_never_a_token_hash():
    with pytest.raises(ValueError, match="shared_credential_scope_unsupported"):
        slot(consumer_installation_ids=["installation-a", "installation-b"])
    with pytest.raises(ValueError, match="shared_credential_scope_unsupported"):
        slot(consumer_installation_ids=[])
    with pytest.raises(ValueError, match="opaque_slot_id_invalid"):
        slot(slot_id="sha256:" + "a" * 64)


def test_credential_handle_is_nonserializable_redacted_and_destroyable():
    marker = "synthetic-retirement-secret"
    handle = CredentialHandle.from_memory(marker)
    assert marker not in repr(handle)
    assert marker not in str(handle)
    assert handle.read_once() == marker.encode()
    with pytest.raises(ValueError, match="credential_handle_consumed"):
        handle.read_once()
    handle.destroy()
    with pytest.raises(ValueError, match="credential_handle_destroyed"):
        handle.read_once()


@pytest.mark.parametrize(
    ("field", "replacement", "code"),
    [
        ("authority_instance_id", "authority-instance-b", "retirement_authority_mismatch"),
        ("authority_origin", "https://relay.example:9443", "retirement_authority_mismatch"),
        ("runtime_key_id", "runtime-key-b", "retirement_runtime_key_mismatch"),
        ("owner_id", "owner-b", "retirement_scope_mismatch"),
        ("installation_id", "installation-b", "retirement_scope_mismatch"),
        ("mac_id", "mac-b", "retirement_scope_mismatch"),
        ("vault_id", "vault-b", "retirement_scope_mismatch"),
        ("role", "other-role", "retirement_scope_mismatch"),
        ("slot_id", "slot-b", "retirement_slot_mismatch"),
        ("operation_id", "op-" + "c" * 32, "retirement_operation_mismatch"),
        ("plan_id", "plan-" + "d" * 64, "retirement_plan_mismatch"),
        ("release_digest", "3" * 64, "retirement_release_mismatch"),
        ("helper_digest", "4" * 64, "retirement_helper_mismatch"),
        ("nonce", "nonce-b", "retirement_nonce_mismatch"),
        ("idempotency_key", "idempotency-b", "retirement_idempotency_mismatch"),
        ("old_generation", 6, "retirement_generation_mismatch"),
        ("target_generation", 9, "retirement_generation_mismatch"),
    ],
)
def test_proof_is_bound_to_every_expected_identity(field, replacement, code):
    expected = expectation()
    candidate = RetirementProofCandidate.from_mapping(
        proof_mapping(expected, **{field: replacement})
    )
    with pytest.raises(ValueError, match=code):
        RetirementProofConsumer.validate_only(
            candidate,
            expected,
            DeterministicEvidenceVerifier(),
            now_epoch=NOW,
        )


def test_proof_rejects_bare_truthiness_unknown_fields_bad_evidence_and_time_failures():
    expected = expectation()
    for value in (True, {"verified": True}):
        with pytest.raises((TypeError, ValueError)):
            RetirementProofCandidate.from_mapping(value)

    extra = proof_mapping(expected)
    extra["verified"] = True
    with pytest.raises(ValueError, match="retirement_proof_fields_invalid"):
        RetirementProofCandidate.from_mapping(extra)

    bad = proof_mapping(expected)
    bad["evidence"] = base64.b64encode(b"altered").decode()
    with pytest.raises(ValueError, match="retirement_evidence_invalid"):
        RetirementProofConsumer.validate_only(
            RetirementProofCandidate.from_mapping(bad),
            expected,
            DeterministicEvidenceVerifier(),
            now_epoch=NOW,
        )

    for changes, code in (
        ({"expires_at_epoch": NOW - 1}, "retirement_proof_expired"),
        ({"issued_at_epoch": NOW + 500}, "retirement_clock_skew_invalid"),
        (
            {"issued_at_epoch": NOW - 2, "expires_at_epoch": NOW + 1000},
            "retirement_proof_ttl_invalid",
        ),
    ):
        candidate = RetirementProofCandidate.from_mapping(proof_mapping(expected, **changes))
        with pytest.raises(ValueError, match=code):
            RetirementProofConsumer.validate_only(
                candidate,
                expected,
                DeterministicEvidenceVerifier(),
                now_epoch=NOW,
            )

    expires_now = RetirementProofCandidate.from_mapping(
        proof_mapping(expected, expires_at_epoch=NOW)
    )
    with pytest.raises(ValueError, match="retirement_proof_expired"):
        RetirementProofConsumer.validate_only(
            expires_now,
            expected,
            DeterministicEvidenceVerifier(),
            now_epoch=NOW,
        )


@pytest.mark.parametrize(
    ("field", "replacement", "code"),
    [
        ("proof_schema", "attacker/v99", "retirement_proof_schema_invalid"),
        ("outcome", "not_applied", "retirement_proof_outcome_invalid"),
    ],
)
def test_direct_dataclass_construction_cannot_bypass_proof_parser(
    field, replacement, code
):
    expected = expectation()
    candidate = RetirementProofCandidate.from_mapping(proof_mapping(expected))
    tampered = replace(candidate, **{field: replacement})
    with pytest.raises(ValueError, match=code):
        RetirementProofConsumer.validate_only(
            tampered,
            expected,
            DeterministicEvidenceVerifier(),
            now_epoch=NOW,
        )


@pytest.mark.parametrize("contract", ["authority", "slot"])
def test_direct_expectation_contract_construction_is_reparsed(contract):
    expected = expectation()
    if contract == "authority":
        tampered = replace(
            expected,
            authority=replace(expected.authority, authority_schema="attacker/v99"),
        )
        code = "legacy_authority_schema_invalid"
    else:
        tampered = replace(
            expected,
            slot=replace(expected.slot, slot_schema="attacker/v99"),
        )
        code = "legacy_credential_slot_schema_invalid"
    candidate = RetirementProofCandidate.from_mapping(proof_mapping(expected))
    with pytest.raises(ValueError, match=code):
        RetirementProofConsumer.validate_only(
            candidate,
            tampered,
            DeterministicEvidenceVerifier(),
            now_epoch=NOW,
        )


def test_valid_proof_is_consumed_atomically_once_and_checkpoint_is_secret_free(tmp_path):
    store, checkpoint = checkpoint_store(tmp_path)
    expected = bound_expectation(checkpoint)
    candidate = RetirementProofCandidate.from_mapping(proof_mapping(expected))
    consumer = RetirementProofConsumer(store, DeterministicEvidenceVerifier(), clock=lambda: NOW)

    commit = consumer.consume(candidate, expected)
    persisted = store.read(checkpoint["operation_id"])

    assert commit.operation_id == checkpoint["operation_id"]
    assert persisted["irreversible_boundary_crossed"] is True
    assert persisted["ambiguity_state"] == "retired"
    assert persisted["recovery_policy"] == "finish_forward"
    assert persisted["effect_summary"]["credential_effect"] == "retired"
    assert persisted["recorded_answers"]["retirement_commit"] == commit.to_mapping()
    encoded = store.path_for(checkpoint["operation_id"]).read_text()
    for forbidden in (
        expected.nonce,
        expected.idempotency_key,
        expected.authority.authority_origin,
        candidate.evidence,
        "synthetic-retirement-secret",
    ):
        assert forbidden not in encoded

    with pytest.raises(ValueError, match="retirement_proof_replay"):
        consumer.consume(candidate, expected)


def test_generation_high_water_rejects_same_slot_across_operations(tmp_path):
    store, first_checkpoint = checkpoint_store(tmp_path)
    first_expected = bound_expectation(first_checkpoint)
    consumer = RetirementProofConsumer(
        store,
        DeterministicEvidenceVerifier(),
        clock=lambda: NOW,
    )
    consumer.consume(
        RetirementProofCandidate.from_mapping(proof_mapping(first_expected)),
        first_expected,
    )

    _same_store, second_checkpoint = checkpoint_store(tmp_path)
    second_expected = bound_expectation(second_checkpoint)
    second_candidate = RetirementProofCandidate.from_mapping(
        proof_mapping(second_expected)
    )
    with pytest.raises(ValueError, match="retirement_generation_replay"):
        consumer.consume(second_candidate, second_expected)


def test_generation_history_corruption_fails_closed(tmp_path):
    store, checkpoint = checkpoint_store(tmp_path)
    (store.directory.path / ("op-" + "f" * 32 + ".json")).write_text("{", encoding="utf-8")
    expected = bound_expectation(checkpoint)
    candidate = RetirementProofCandidate.from_mapping(proof_mapping(expected))
    with pytest.raises(ValueError, match="retirement_generation_history_invalid"):
        RetirementProofConsumer(
            store,
            DeterministicEvidenceVerifier(),
            clock=lambda: NOW,
        ).consume(candidate, expected)


def test_checkpoint_cannot_cross_retired_boundary_without_a_valid_commit(tmp_path):
    store, checkpoint = checkpoint_store(tmp_path)
    with pytest.raises(ValueError, match="retired_boundary_requires_retirement_commit"):
        store.update(
            checkpoint["operation_id"],
            irreversible_boundary_crossed=True,
            ambiguity_state=AmbiguityState.RETIRED,
            recovery_policy=RecoveryPolicy.FINISH_FORWARD,
            effect_summary=EffectSummary(
                local_effect=EffectDisposition.STAGED,
                remote_effect=EffectDisposition.CHANGED,
                credential_effect=CredentialEffect.RETIRED,
                mutation_performed=True,
                owned_resource_count=2,
                effect_codes=("retirement_proof_consumed",),
            ),
            cancellation_available=False,
        )


def test_already_retired_reconciliation_requires_original_binding_and_resists_clock_rollback(tmp_path):
    store, checkpoint = checkpoint_store(tmp_path)
    expected = bound_expectation(checkpoint)
    consumer = RetirementProofConsumer(store, DeterministicEvidenceVerifier(), clock=lambda: NOW)
    first = RetirementProofCandidate.from_mapping(proof_mapping(expected))
    commit = consumer.consume(first, expected)

    reconciled = RetirementProofCandidate.from_mapping(
        proof_mapping(expected, outcome="already_retired", issued_at_epoch=NOW)
    )
    assert consumer.consume(reconciled, expected) == commit

    wrong = expectation(
        authority=expected.authority,
        slot=expected.slot,
        operation_id=expected.operation_id,
        plan_id=expected.plan_id,
        idempotency_key="different-idempotency",
    )
    with pytest.raises(ValueError, match="retirement_idempotency_mismatch"):
        consumer.consume(reconciled, wrong)

    rollback_clock = RetirementProofConsumer(
        store,
        DeterministicEvidenceVerifier(),
        clock=lambda: NOW - 500,
    )
    with pytest.raises(ValueError, match="retirement_clock_rollback"):
        rollback_clock.consume(reconciled, expected)


def test_service_revalidates_authority_when_checkpoint_commit_already_exists(tmp_path):
    store, checkpoint = pre_dispatch_checkpoint_store(tmp_path)
    initial_transport = FakeAuthorityTransport()
    initial = capability_service(tmp_path, store, initial_transport)
    commit = initial.retire(
        credential=CredentialHandle.from_memory("synthetic-old-secret"),
        operation_id=checkpoint["operation_id"],
        plan_id=checkpoint["plan_id"],
        installation_id="installation-a",
        vault_id="vault-a",
        role="mobile",
    )

    class AlreadyRetiredTransport(ReconcileAuthorityTransport):
        def __init__(self):
            super().__init__("retired")
            self.reconciliations = 0

        def reconcile(self, credential, request):
            self.reconciliations += 1
            self.last_request = dict(request)
            expected = RetirementExpectation(
                authority=authority(role="mobile"),
                slot=slot(role="mobile"),
                operation_id=request["operation_id"],
                plan_id=request["plan_id"],
                release_digest=request["release_digest"],
                helper_digest=request["helper_digest"],
                nonce=request["nonce"],
                idempotency_key=request["idempotency_key"],
                not_before_epoch=NOW,
            )
            return {
                "outcome": "retired",
                "proof": proof_mapping(
                    expected,
                    outcome="already_retired",
                    issued_at_epoch=NOW,
                ),
                "verification": self.verify(credential, request),
                "restart_epoch": 8,
            }

    reconciliation_transport = AlreadyRetiredTransport()
    reconciled = capability_service(
        tmp_path,
        store,
        reconciliation_transport,
    ).reconcile(
        credential=CredentialHandle.from_memory("synthetic-old-secret"),
        operation_id=checkpoint["operation_id"],
        plan_id=checkpoint["plan_id"],
        installation_id="installation-a",
        vault_id="vault-a",
        role="mobile",
    )

    assert reconciliation_transport.reconciliations == 1
    assert reconciled == RetirementReconciliationResult("retired", commit)


def test_cloned_checkpoint_cannot_consume_proof_for_another_mac(tmp_path):
    store, checkpoint = checkpoint_store(tmp_path)
    original = bound_expectation(checkpoint)
    candidate = RetirementProofCandidate.from_mapping(proof_mapping(original))
    clone = bound_expectation(checkpoint, authority=authority(mac_id="mac-clone"))
    with pytest.raises(ValueError, match="retirement_scope_mismatch"):
        RetirementProofConsumer(store, DeterministicEvidenceVerifier(), clock=lambda: NOW).consume(
            candidate, clone
        )


class FakeAuthorityTransport(LegacyAuthorityTransport):
    def __init__(self, runtime_key=b"test-runtime-key"):
        self.commits = 0
        self.runtime_key = runtime_key
        self.last_request = None

    def descriptor(self, _credential):
        return {
            "authority": authority(role="mobile").to_mapping(),
            "slot": slot(role="mobile").to_mapping(),
            "restart_epoch": 8,
        }

    def commit(self, _credential, request):
        self.commits += 1
        self.last_request = dict(request)
        expected = RetirementExpectation(
            authority=authority(role="mobile"),
            slot=slot(role="mobile"),
            operation_id=request["operation_id"],
            plan_id=request["plan_id"],
            release_digest=request["release_digest"],
            helper_digest=request["helper_digest"],
            nonce=request["nonce"],
            idempotency_key=request["idempotency_key"],
            not_before_epoch=NOW,
        )
        return proof_mapping(expected)

    def verify(self, _credential, request):
        assert dict(request) == self.last_request
        value = {
            "verification_schema": "claudian-remote.legacy-retirement-health/v1",
            "authority_instance_id": "authority-instance-a",
            "protocol_version": "legacy-retirement/v1",
            "restart_epoch": 9,
            "runtime_key_id": "runtime-key-a",
            "slot_id": "slot-a",
            "target_generation": 8,
            "idempotency_key": request["idempotency_key"],
            "old_credential_rejected": True,
            "issued_at_epoch": NOW,
        }
        payload = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode()
        value["evidence"] = base64.b64encode(
            hmac.new(self.runtime_key, payload, hashlib.sha256).digest()
        ).decode()
        return value


class ReconcileAuthorityTransport(FakeAuthorityTransport):
    def __init__(self, outcome, runtime_key=b"test-runtime-key"):
        super().__init__(runtime_key)
        self.outcome = outcome

    def reconcile(self, _credential, request):
        self.last_request = dict(request)
        if self.outcome == "unavailable":
            raise TimeoutError("authority_temporarily_unavailable")
        if self.outcome == "retired":
            proof = super().commit(_credential, request)
            return {
                "outcome": "retired",
                "proof": proof,
                "verification": self.verify(_credential, request),
                "restart_epoch": 8,
            }
        value = {
            "reconciliation_schema": "claudian-remote.legacy-retirement-reconciliation/v1",
            "outcome": "not_applied",
            "authority_instance_id": "authority-instance-a",
            "authority_origin": "https://relay.example:8443",
            "runtime_key_id": "runtime-key-a",
            "owner_id": request["owner_id"],
            "installation_id": request["installation_id"],
            "mac_id": request["mac_id"],
            "vault_id": request["vault_id"],
            "role": request["role"],
            "slot_id": request["slot_id"],
            "old_generation": request["old_generation"],
            "target_generation": request["target_generation"],
            "current_generation": request["old_generation"],
            "operation_id": request["operation_id"],
            "plan_id": request["plan_id"],
            "release_digest": request["release_digest"],
            "helper_digest": request["helper_digest"],
            "nonce": request["nonce"],
            "idempotency_key": request["idempotency_key"],
            "issued_at_epoch": NOW,
            "expires_at_epoch": NOW + 300,
        }
        payload = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode()
        value["evidence"] = base64.b64encode(
            hmac.new(self.runtime_key, payload, hashlib.sha256).digest()
        ).decode()
        return {"outcome": "not_applied", "receipt": value}


def capability_service(tmp_path, store, transport, *, lock_held_by_caller=False):
    runtime_key = tmp_path / "runtime.key"
    runtime_key.write_bytes(b"test-runtime-key")
    runtime_key.chmod(0o600)
    profile = tmp_path / "authority-profile.json"
    profile.write_text(
        json.dumps(
            {
                "profile_schema": "claudian-remote.legacy-authority-profile/v1",
                "profile_id": "dogfood-local-v1",
                "protocol_version": "legacy-retirement/v1",
                "authority_origin": "https://relay.example:8443",
                "authority_instance_id": "authority-instance-a",
                "runtime_key_id": "runtime-key-a",
                "runtime_key_path": str(runtime_key),
                "release_digest": RELEASE_DIGEST,
                "helper_digest": HELPER_DIGEST,
                "owner_id": "owner-a",
                "mac_id": "mac-a",
            }
        )
    )
    profile.chmod(0o600)
    return CapabilityAwareLegacyRetirementService(
        profile,
        store,
        clock=lambda: NOW,
        transport_factory=lambda _origin: transport,
        lock_held_by_caller=lock_held_by_caller,
    )


def test_capability_aware_service_consumes_authority_proof_without_persisting_secret(
    tmp_path,
):
    store, checkpoint = pre_dispatch_checkpoint_store(tmp_path)
    runtime_key = tmp_path / "runtime.key"
    runtime_key.write_bytes(b"test-runtime-key")
    runtime_key.chmod(0o600)
    profile = tmp_path / "authority-profile.json"
    profile.write_text(
        json.dumps(
            {
                "profile_schema": "claudian-remote.legacy-authority-profile/v1",
                "profile_id": "dogfood-local-v1",
                "protocol_version": "legacy-retirement/v1",
                "authority_origin": "https://relay.example:8443",
                "authority_instance_id": "authority-instance-a",
                "runtime_key_id": "runtime-key-a",
                "runtime_key_path": str(runtime_key),
                "release_digest": RELEASE_DIGEST,
                "helper_digest": HELPER_DIGEST,
                "owner_id": "owner-a",
                "mac_id": "mac-a",
            }
        )
    )
    profile.chmod(0o600)
    transport = FakeAuthorityTransport()
    service = CapabilityAwareLegacyRetirementService(
        profile,
        store,
        clock=lambda: NOW,
        transport_factory=lambda _origin: transport,
    )
    handle = CredentialHandle.from_memory("synthetic-old-secret")

    commit = service.retire(
        credential=handle,
        operation_id=checkpoint["operation_id"],
        plan_id=checkpoint["plan_id"],
        installation_id="installation-a",
        vault_id="vault-a",
        role="mobile",
    )

    assert commit.target_generation == 8
    assert transport.commits == 1
    encoded = store.path_for(checkpoint["operation_id"]).read_text()
    assert "synthetic-old-secret" not in encoded


def test_commit_transport_failure_locks_checkpoint_for_same_operation_reconciliation(
    tmp_path,
):
    store, checkpoint = pre_dispatch_checkpoint_store(tmp_path)
    runtime_key = tmp_path / "runtime.key"
    runtime_key.write_bytes(b"test-runtime-key")
    runtime_key.chmod(0o600)
    profile = tmp_path / "authority-profile.json"
    profile.write_text(
        json.dumps(
            {
                "profile_schema": "claudian-remote.legacy-authority-profile/v1",
                "profile_id": "dogfood-local-v1",
                "protocol_version": "legacy-retirement/v1",
                "authority_origin": "https://relay.example:8443",
                "authority_instance_id": "authority-instance-a",
                "runtime_key_id": "runtime-key-a",
                "runtime_key_path": str(runtime_key),
                "release_digest": RELEASE_DIGEST,
                "helper_digest": HELPER_DIGEST,
                "owner_id": "owner-a",
                "mac_id": "mac-a",
            }
        )
    )
    profile.chmod(0o600)

    class TimeoutAfterDispatch(FakeAuthorityTransport):
        def commit(self, _credential, request):
            self.commits += 1
            self.last_request = dict(request)
            raise TimeoutError("response_lost_after_dispatch")

    transport = TimeoutAfterDispatch()
    service = CapabilityAwareLegacyRetirementService(
        profile,
        store,
        clock=lambda: NOW,
        transport_factory=lambda _origin: transport,
    )

    with pytest.raises(LegacyRetirementOutcomeUnknown):
        service.retire(
            credential=CredentialHandle.from_memory("synthetic-old-secret"),
            operation_id=checkpoint["operation_id"],
            plan_id=checkpoint["plan_id"],
            installation_id="installation-a",
            vault_id="vault-a",
            role="mobile",
        )

    locked = store.read(checkpoint["operation_id"])
    assert transport.commits == 1
    assert locked["state"] == "recovery_required"
    assert locked["irreversible_boundary_crossed"] is False
    assert locked["ambiguity_state"] == "retirement_outcome_unknown"
    assert locked["recovery_policy"] == "reconcile_same_operation"
    assert locked["cancellation_available"] is False
    assert [item["command"] for item in locked["next_actions"]] == ["resume"]
    assert "synthetic-old-secret" not in store.path_for(checkpoint["operation_id"]).read_text()


@pytest.mark.parametrize(
    ("authority_outcome", "expected_outcome", "ambiguity", "recovery"),
    [
        ("not_applied", "not_applied", "not_applied", "rollback_pre_boundary"),
        ("retired", "retired", "retired", "finish_forward"),
        (
            "unavailable",
            "inconclusive",
            "inconclusive",
            "manual_recovery_required",
        ),
    ],
)
def test_same_operation_reconciliation_has_three_fail_closed_outcomes(
    tmp_path,
    authority_outcome,
    expected_outcome,
    ambiguity,
    recovery,
):
    store, checkpoint = pre_dispatch_checkpoint_store(tmp_path)

    class TimeoutAfterDispatch(FakeAuthorityTransport):
        def commit(self, _credential, request):
            self.last_request = dict(request)
            raise TimeoutError("response_lost_after_dispatch")

    with pytest.raises(LegacyRetirementOutcomeUnknown):
        capability_service(tmp_path, store, TimeoutAfterDispatch()).retire(
            credential=CredentialHandle.from_memory("synthetic-old-secret"),
            operation_id=checkpoint["operation_id"],
            plan_id=checkpoint["plan_id"],
            installation_id="installation-a",
            vault_id="vault-a",
            role="mobile",
        )

    result = capability_service(
        tmp_path,
        store,
        ReconcileAuthorityTransport(authority_outcome),
    ).reconcile(
        credential=CredentialHandle.from_memory("synthetic-old-secret"),
        operation_id=checkpoint["operation_id"],
        plan_id=checkpoint["plan_id"],
        installation_id="installation-a",
        vault_id="vault-a",
        role="mobile",
    )

    assert isinstance(result, RetirementReconciliationResult)
    assert result.outcome == expected_outcome
    persisted = store.read(checkpoint["operation_id"])
    assert persisted["ambiguity_state"] == ambiguity
    assert persisted["recovery_policy"] == recovery
    encoded = store.path_for(checkpoint["operation_id"]).read_text()
    assert "synthetic-old-secret" not in encoded
    assert '"nonce":' not in encoded
    assert '"idempotency_key":' not in encoded


def test_proof_commit_reuses_outer_lifecycle_lock_without_self_deadlock(tmp_path):
    store, checkpoint = pre_dispatch_checkpoint_store(tmp_path)
    service = capability_service(
        tmp_path,
        store,
        FakeAuthorityTransport(),
        lock_held_by_caller=True,
    )

    with OperationLock(store.directory.path):
        commit = service.retire(
            credential=CredentialHandle.from_memory("synthetic-old-secret"),
            operation_id=checkpoint["operation_id"],
            plan_id=checkpoint["plan_id"],
            installation_id="installation-a",
            vault_id="vault-a",
            role="mobile",
        )

    assert commit.target_generation == 8
    assert store.read(checkpoint["operation_id"])["ambiguity_state"] == "retired"


def test_missing_authority_profile_fails_before_consuming_credential(tmp_path):
    store, checkpoint = checkpoint_store(tmp_path)
    service = CapabilityAwareLegacyRetirementService(
        tmp_path / "missing-profile.json",
        store,
    )
    handle = CredentialHandle.from_memory("keep-readable")

    with pytest.raises(ValueError, match="legacy_authority_unsupported"):
        service.retire(
            credential=handle,
            operation_id=checkpoint["operation_id"],
            plan_id=checkpoint["plan_id"],
            installation_id="installation-a",
            vault_id="vault-a",
            role="mobile",
        )
    assert handle.read_once() == b"keep-readable"


def test_authority_profile_and_runtime_key_reject_symlink_and_oversize(tmp_path):
    runtime_key = tmp_path / "runtime.key"
    runtime_key.write_bytes(b"test-runtime-key")
    runtime_key.chmod(0o600)
    profile_value = {
        "profile_schema": "claudian-remote.legacy-authority-profile/v1",
        "profile_id": "dogfood-local-v1",
        "protocol_version": "legacy-retirement/v1",
        "authority_origin": "https://relay.example:8443",
        "authority_instance_id": "authority-instance-a",
        "runtime_key_id": "runtime-key-a",
        "runtime_key_path": str(runtime_key),
        "release_digest": RELEASE_DIGEST,
        "helper_digest": HELPER_DIGEST,
        "owner_id": "owner-a",
        "mac_id": "mac-a",
    }
    profile = tmp_path / "authority-profile.json"
    profile.write_text(json.dumps(profile_value))
    profile.chmod(0o600)
    store, _ = checkpoint_store(tmp_path / "checkpoint")

    profile_link = tmp_path / "authority-profile-link.json"
    profile_link.symlink_to(profile)
    with pytest.raises(ValueError, match="legacy_authority_profile_unsafe"):
        load_legacy_authority_profile(profile_link)

    key_link = tmp_path / "runtime-link.key"
    key_link.symlink_to(runtime_key)
    profile_value["runtime_key_path"] = str(key_link)
    profile.write_text(json.dumps(profile_value))
    service = CapabilityAwareLegacyRetirementService(profile, store)
    assert service.available() is False

    oversized = tmp_path / "oversized.key"
    oversized.write_bytes(b"x" * 4097)
    oversized.chmod(0o600)
    profile_value["runtime_key_path"] = str(oversized)
    profile.write_text(json.dumps(profile_value))
    assert service.available() is False


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        (
            {"ok": False, "error": "retirement_idempotency_conflict"},
            "legacy_authority_rejected:retirement_idempotency_conflict",
        ),
        ({"ok": False, "error": "unknown_remote_error"}, "response_invalid"),
        ({"unexpected": True}, "response_invalid"),
    ],
)
def test_http_rejection_is_not_misclassified_as_network_unavailable(body, expected):
    class RejectingOpener:
        def open(self, *_args, **_kwargs):
            encoded = json.dumps(body).encode()
            raise urllib.error.HTTPError(
                "https://relay.example/api/v2/legacy-retirement/descriptor",
                409,
                "Conflict",
                {"Content-Length": str(len(encoded))},
                io.BytesIO(encoded),
            )

    transport = UrllibLegacyAuthorityTransport("https://relay.example")
    transport._opener = RejectingOpener()

    with pytest.raises(ValueError, match=expected):
        transport.descriptor(bytearray(b"old-mobile-secret"))


def test_redirect_http_error_without_body_fails_closed():
    class RedirectingOpener:
        def open(self, *_args, **_kwargs):
            raise urllib.error.HTTPError(
                "https://other.example/api/v2/legacy-retirement/descriptor",
                302,
                "legacy_authority_redirect_forbidden",
                {},
                None,
            )

    transport = UrllibLegacyAuthorityTransport("https://relay.example")
    transport._opener = RedirectingOpener()

    with pytest.raises(ValueError, match="legacy_authority_response_invalid"):
        transport.descriptor(bytearray(b"old-mobile-secret"))
