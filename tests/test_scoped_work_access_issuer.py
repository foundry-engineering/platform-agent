from __future__ import annotations

import base64
import copy
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from agent_protocol.schema import canonical_sha256
from agent_protocol.work_authority import (
    derive_work_authority_id, validate_work_authority,
    work_authority_signed_payload_sha256, work_authority_signing_message,
)
from agent_protocol.work_access_witness import verify_work_access_witness_signatures
from platform_agent.skill_activation_issuer import SkillActivationIssuer
from platform_agent.work_access_witness_issuer import (
    WorkAccessWitnessIssuer, WorkAccessWitnessIssuerError, WorkAccessWitnessSigner,
)
from test_skill_activation_issuer import FakeAdmissions, _admission, _package, _scope, _signer

NOW = datetime(2026, 9, 16, 10, 12, tzinfo=UTC)
REQUEST = {"tool_id": "finance.ledger-read", "connector_id": None,
           "resource": {"resource_type": "business-record", "resource_id": "ledger:2026-09", "action": "read"},
           "arguments": {"period": "2026-09"}}


class Harness:
    def __init__(self, *, activation_now=NOW, activation_lifetime=60):
        self.admissions = FakeAdmissions()
        package = _package()
        self.admissions.record = _admission(package)
        signer, public = _signer()
        context = {**self.admissions.context.as_dict(), "execution_scope": _scope().as_dict()}
        self.authority = {
            "schema_version": "work-authority.v1", "authority_id": "",
            "tenant_context": context, "task_id": "tsk_" + "a" * 32,
            "agent_id": "bookkeeper-agent", "role_id": "bookkeeper",
            "request_sha256": canonical_sha256(REQUEST),
            "policy_ref": {"policy_id": "fixture.v1", "policy_sha256": "a" * 64,
                           "jurisdiction": "AT", "constraints": []},
            "issued_at": "2026-09-16T10:11:00Z", "expires_at": "2026-09-16T10:13:00Z",
            "resources": [{"resource_type": "business-record", "resource_id": "ledger:2026-09",
                           "actions": ["read"], "data_classification": "internal"}],
            "tool_ids": [REQUEST["tool_id"]], "connector_ids": [],
            "budget": {"max_model_calls": 1, "max_tool_calls": 1,
                       "max_cost_microusd": 500000, "max_wall_seconds": 60},
            "approvals": [], "constraint_evidence": [], "regulated_reviews": [],
        }
        self.authority["authority_id"] = derive_work_authority_id(self.authority)
        self.authority["signatures"] = [{"kid": signer.kid, "alg": "ed25519",
            "signed_sha256": work_authority_signed_payload_sha256(self.authority),
            "sig_b64": base64.b64encode(signer.sign(work_authority_signing_message(self.authority))).decode()}]
        validate_work_authority(self.authority)
        issuer = SkillActivationIssuer(admissions=self.admissions,
                                       verify_authority_binding=lambda *_: _scope())
        self.activation = issuer.issue(
            tenant_id=self.admissions.context.tenant_id, project_id=self.admissions.context.project_id,
            role_id="bookkeeper", skill_id="finance.reconcile", package_id=package["package_id"],
            package=package, run_id="run_" + "b" * 32, task_id=self.authority["task_id"],
            agent_id=self.authority["agent_id"], authority_class="work-authority",
            authority_id=self.authority["authority_id"], signers=[signer], now=activation_now,
            lifetime_seconds=activation_lifetime,
        )
        self.signatures = []
        self.on_sign = lambda: None

        def sign(message):
            self.signatures.append(message)
            self.on_sign()
            return signer.sign(message)

        self.signer = WorkAccessWitnessSigner(kid=signer.kid, public_key=public, sign=sign)
        self.issuer = WorkAccessWitnessIssuer(admissions=self.admissions,
            resolve_authority=lambda _: self.authority, resolve_activation=lambda _: self.activation)

    def issue(self):
        return self.issuer.issue(tenant_id=self.admissions.context.tenant_id,
            project_id=self.admissions.context.project_id,
            work_authority_id=self.authority["authority_id"], skill_activation_id=self.activation["activation_id"],
            invocation_id="inv_" + "1" * 32, request=REQUEST, signers=[self.signer], now=NOW)


def test_real_issuer_preserves_the_signed_professional_execution_scope():
    h = Harness()
    witness = h.issue()
    assert witness["tenant_context"] == h.activation["tenant_context"] == h.authority["tenant_context"]
    assert witness["tenant_context"]["execution_scope"] == _scope().as_dict()
    assert verify_work_access_witness_signatures(witness, {h.signer.kid: h.signer.public_key}) == (h.signer.kid,)
    assert len(h.signatures) == 1


@pytest.mark.parametrize("field,value", [
    ("tenant_id", "tnt_foreign0001"), ("project_id", "prj_foreign0001"),
    ("cell_id", "cell_" + "f" * 32), ("authority_epoch", 8), ("keyset_id", "keyset_rotated.v1"),
])
def test_live_context_change_denies_before_signing(field, value):
    h = Harness()
    current = replace(h.admissions.context, **{field: value})
    h.admissions.current_context = lambda *_: current
    with pytest.raises(WorkAccessWitnessIssuerError):
        h.issue()
    assert h.signatures == []


def test_expired_activation_denies_before_signing():
    h = Harness(activation_now=NOW - timedelta(seconds=20), activation_lifetime=10)
    with pytest.raises(WorkAccessWitnessIssuerError):
        h.issue()
    assert h.signatures == []


def test_signer_cannot_mutate_the_resolved_authority_or_activation_snapshot():
    h = Harness()
    original = copy.deepcopy(h.activation["tenant_context"])
    h.on_sign = lambda: h.activation["tenant_context"]["execution_scope"].update(workspace_id="foreign")
    witness = h.issue()
    assert witness["tenant_context"] == original


def test_witness_lifetime_cannot_outlive_valid_activation():
    h = Harness(activation_lifetime=5)
    with pytest.raises(WorkAccessWitnessIssuerError):
        h.issue()
    assert h.signatures == []


def test_revoked_package_admission_cannot_issue_a_new_witness():
    h = Harness()

    def revoked(**_kwargs):
        raise RuntimeError("admission revoked")

    h.admissions.resolve = revoked
    with pytest.raises(WorkAccessWitnessIssuerError):
        h.issue()
    assert h.signatures == []
