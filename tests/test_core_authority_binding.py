from __future__ import annotations

import base64
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_protocol.core_work_request import core_work_request_material
from agent_protocol.schema import canonical_sha256
from agent_protocol.work_authority import (
    derive_work_authority_id, work_authority_signed_payload_sha256, work_authority_signing_message,
)
from platform_agent.core_authority import CoreAuthorityError, CoreAuthorityVerifier
from platform_agent.skill_activation_issuer import SkillActivationIssuer, SkillActivationIssuerError
from test_core_authority import Transport, binding
from test_skill_activation_issuer import FakeAdmissions, _admission, _package, _signer

NOW = datetime(2026, 11, 6, 12, tzinfo=UTC)
TASK = "tsk_core-bound-0001"
AGENT = "finance-worker"


def signed_authority(**changes: object) -> tuple[dict[str, Any], dict[str, bytes]]:
    b = binding()
    context = {**FakeAdmissions().context.as_dict(), "execution_scope": b.scope.as_dict()}
    request = core_work_request_material(**{
        "tenant_context": context, "execution_job_id": b.execution_job_id,
        "work_node_id": b.work_node_id, "core_authority_ref": b.authority_id,
        "core_agent_ref": b.agent_id, "task_id": TASK, "agent_id": AGENT,
        "professional_role": b.professional_role, "provider_budget_microusd": b.provider_budget_microusd,
        "allowed_actions": b.allowed_actions, **changes,
    })
    document: dict[str, Any] = {
        "schema_version": "work-authority.v1", "authority_id": "",
        "tenant_context": context, "task_id": TASK, "agent_id": AGENT, "role_id": b.scope.role_id,
        "request_sha256": canonical_sha256(request),
        "policy_ref": {"policy_id": "pol_core-binding-test", "policy_sha256": "a" * 64,
                       "jurisdiction": "AT", "constraints": []},
        "issued_at": (NOW - timedelta(seconds=1)).isoformat().replace("+00:00", "Z"),
        "expires_at": (NOW + timedelta(seconds=60)).isoformat().replace("+00:00", "Z"),
        "resources": [{"resource_type": "artifact", "resource_id": "artifact_bound",
                       "actions": ["create"], "data_classification": "confidential"}],
        "tool_ids": ["foundry.provider.execute"], "connector_ids": [],
        "budget": {"max_model_calls": 1, "max_tool_calls": 1,
                   "max_cost_microusd": request["provider_budget_microusd"], "max_wall_seconds": 60},
        "approvals": [], "constraint_evidence": [], "regulated_reviews": [], "signatures": [],
    }
    document["authority_id"] = derive_work_authority_id(document)
    key = Ed25519PrivateKey.generate()
    document["signatures"] = [{"kid": "kid_core-binding-test", "alg": "ed25519",
        "signed_sha256": work_authority_signed_payload_sha256(document),
        "sig_b64": base64.b64encode(key.sign(work_authority_signing_message(document))).decode()}]
    return document, {"kid_core-binding-test": key.public_key().public_bytes_raw()}


def verify(transport: Transport, document: dict[str, Any], keys: dict[str, bytes], *, now=NOW):
    return CoreAuthorityVerifier(
        client=transport.client, binding=binding(), resolve_work_authority=lambda _: document,
        trusted_work_authority_keys=keys, clock=lambda: now,
    )("work-authority", document["authority_id"], FakeAdmissions().context, TASK, AGENT)


def test_canonical_work_identity_and_core_reference_are_separately_verified(monkeypatch) -> None:
    transport = Transport(monkeypatch)
    document, keys = signed_authority()
    assert document["authority_id"] != binding().authority_id
    assert document["agent_id"] != binding().agent_id
    assert verify(transport, document, keys) == binding().scope
    assert transport.requests[0][1].endswith(binding().authority_id)
    transport.document["allowed"] = False
    with pytest.raises(CoreAuthorityError):
        verify(transport, document, keys)
    assert len(transport.requests) == 2


@pytest.mark.parametrize("changes", [
    {"execution_job_id": "foreign_job"}, {"work_node_id": "foreign_node"},
    {"core_authority_ref": "wka_" + "e" * 32}, {"core_agent_ref": "foreign.core_record"},
    {"professional_role": "Other Profession"}, {"provider_budget_microusd": 499999},
    {"allowed_actions": ["produce_artifact"]},
])
def test_valid_signature_for_other_core_work_never_reaches_network(monkeypatch, changes) -> None:
    transport = Transport(monkeypatch)
    document, keys = signed_authority(**changes)
    with pytest.raises(CoreAuthorityError, match="signed canonical"):
        verify(transport, document, keys)
    assert not transport.requests


@pytest.mark.parametrize("problem", ["signature", "key", "expired", "identity"])
def test_invalid_canonical_authority_never_falls_back_to_core_ref(monkeypatch, problem) -> None:
    transport = Transport(monkeypatch)
    document, keys = signed_authority()
    now = NOW
    if problem == "signature":
        document["signatures"][0]["sig_b64"] = base64.b64encode(b"0" * 64).decode()
    elif problem == "key":
        keys = {"untrusted-key": b"0" * 32}
    elif problem == "identity":
        document["authority_id"] = binding().authority_id
    else:
        now += timedelta(seconds=61)
    with pytest.raises(CoreAuthorityError):
        verify(transport, document, keys, now=now)
    assert not transport.requests


def test_actual_activation_signer_requires_both_canonical_signature_and_live_core(monkeypatch) -> None:
    transport = Transport(monkeypatch)
    document, keys = signed_authority()
    admissions, package = FakeAdmissions(), _package()
    admissions.record = _admission(package)
    signer, _ = _signer()
    signatures = []
    def sign(message):
        signatures.append(message)
        return signer.sign(message)
    issuer = SkillActivationIssuer(
        admissions=admissions, verify_authority_binding=CoreAuthorityVerifier(
            client=transport.client, binding=binding(), resolve_work_authority=lambda _: document,
            trusted_work_authority_keys=keys, clock=lambda: NOW,
        ),
    )
    b = binding()
    inputs = dict(tenant_id=b.tenant_id, project_id=b.project_id, role_id=b.scope.role_id,
        skill_id=b.scope.skill_id, package_id=package["package_id"], package=package,
        run_id="run_" + "b" * 32, task_id=TASK, agent_id=AGENT,
        authority_class="work-authority", authority_id=document["authority_id"],
        signers=[replace(signer, sign=sign)], now=NOW)
    activation = issuer.issue(**inputs)
    assert activation["authority_id"] == document["authority_id"] != b.authority_id
    assert activation["agent_id"] == AGENT != b.agent_id
    assert len(signatures) == 1
    transport.document["allowed"] = False
    with pytest.raises(SkillActivationIssuerError):
        issuer.issue(**inputs)
    assert len(signatures) == 1
