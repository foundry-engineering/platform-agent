from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from agent_protocol.work_authority import verify_work_authority_signatures
from platform_agent.core_work_authority_issuer import (
    ArtifactWorkPolicy, CoreWorkAuthorityIssuer, CoreWorkAuthorityIssuerError, CoreWorkAuthoritySigner,
)
from test_core_authority import Transport, binding
from test_skill_activation_issuer import FakeAdmissions, _admission, _package, _signer

NOW = datetime(2026, 11, 6, 12, tzinfo=UTC)


class Harness:
    def __init__(self, monkeypatch):
        self.transport = Transport(monkeypatch)
        self.binding = replace(binding(), artifact_id="artifact_core_target")
        self.transport.document["artifactId"] = self.binding.artifact_id
        self.admissions = FakeAdmissions()
        self.package = _package()
        self.admissions.record = _admission(self.package)
        signer, public = _signer()
        self.calls = []
        self.on_sign = lambda: None
        def sign(message):
            self.calls.append(message)
            self.on_sign()
            return signer.sign(message)
        self.signer = CoreWorkAuthoritySigner(signer.kid, public, sign)
        self.current = NOW
        self.issuer = CoreWorkAuthorityIssuer(
            client=self.transport.client, admissions=self.admissions,
            policy=ArtifactWorkPolicy("pol_core-artifact.v1", "a" * 64, "AT"),
            clock=lambda: self.current,
        )

    def issue(self, **changes):
        args = dict(binding=self.binding, task_id="tsk_core-artifact-0001", agent_id="artifact-worker",
                    package_id=self.package["package_id"], signers=[self.signer])
        args.update(changes)
        return self.issuer.issue(**args)


def test_actual_issuer_produces_verified_exact_core_artifact_authority(monkeypatch):
    h = Harness(monkeypatch)
    document = h.issue()
    assert document["authority_id"] != h.binding.authority_id
    assert document["agent_id"] != h.binding.agent_id
    assert document["resources"] == [{"resource_type": "artifact", "resource_id": "artifact_core_target",
                                       "actions": ["create"], "data_classification": "restricted"}]
    assert document["budget"]["max_cost_microusd"] == h.binding.provider_budget_microusd
    assert document["tool_ids"] == ["foundry.provider.execute"] and document["connector_ids"] == []
    assert document["approvals"] == document["regulated_reviews"] == []
    assert verify_work_authority_signatures(document, {h.signer.kid: h.signer.public_key}) == (h.signer.kid,)
    assert len(h.calls) == 1 and len(h.transport.requests) == 3


@pytest.mark.parametrize("field,value", [
    ("artifactId", "other_artifact"), ("allowed", False),
    ("providerBudgetMicrousd", "500001"), ("professionalRole", "Other Profession"),
])
def test_core_mismatch_denies_before_external_signer(monkeypatch, field, value):
    h = Harness(monkeypatch)
    h.transport.document[field] = value
    with pytest.raises(CoreWorkAuthorityIssuerError):
        h.issue()
    assert not h.calls


@pytest.mark.parametrize("changes", [
    {"task_id": "node_not_a_canonical_task"}, {"agent_id": "core.agent_record"},
    {"package_id": "not-a-package"}, {"signers": []}, {"signers": ["model-created-key"]},
])
def test_invalid_requests_never_reach_core_or_signer(monkeypatch, changes):
    h = Harness(monkeypatch)
    with pytest.raises(CoreWorkAuthorityIssuerError):
        h.issue(**changes)
    assert not h.calls and not h.transport.requests


def test_missing_claimed_artifact_cannot_mint_broad_authority(monkeypatch):
    h = Harness(monkeypatch)
    with pytest.raises(CoreWorkAuthorityIssuerError):
        h.issue(binding=replace(h.binding, artifact_id=None))
    assert not h.calls


def test_manifest_must_match_the_admitted_package_before_any_core_call(monkeypatch):
    h = Harness(monkeypatch)
    changed = replace(h.binding, scope=replace(h.binding.scope, skill_manifest_ref="sha256:" + "9" * 64))
    with pytest.raises(CoreWorkAuthorityIssuerError):
        h.issue(binding=changed)
    assert not h.calls and not h.transport.requests


@pytest.mark.parametrize("change", ["core", "tenant", "package", "epoch", "deadline"])
def test_revocation_or_scope_change_while_signing_returns_no_authority(monkeypatch, change):
    h = Harness(monkeypatch)
    def revoke():
        if change == "core":
            h.transport.document["allowed"] = False
        elif change == "tenant":
            h.admissions.active = False
        elif change == "package":
            h.admissions.record = replace(h.admissions.record, status="revoked")
        elif change == "epoch":
            h.admissions.context = replace(h.admissions.context, authority_epoch=8)
        else:
            h.current = NOW + timedelta(seconds=121)
    h.on_sign = revoke
    with pytest.raises(CoreWorkAuthorityIssuerError):
        h.issue()
    assert len(h.calls) == 1


@pytest.mark.parametrize("result", [b"short", b"0" * 64, "not-signature-bytes"])
def test_incorrect_signer_response_is_never_released(monkeypatch, result):
    h = Harness(monkeypatch)
    with pytest.raises(CoreWorkAuthorityIssuerError):
        h.issue(signers=[replace(h.signer, sign=lambda _: result)])


def test_duplicate_signing_key_ids_are_denied_before_signing(monkeypatch):
    h = Harness(monkeypatch)
    with pytest.raises(CoreWorkAuthorityIssuerError):
        h.issue(signers=[h.signer, h.signer])
    assert not h.calls and not h.transport.requests


def test_package_revocation_before_issue_prevents_any_core_call(monkeypatch):
    h = Harness(monkeypatch)
    h.admissions.record = replace(h.admissions.record, status="revoked")
    with pytest.raises(CoreWorkAuthorityIssuerError):
        h.issue()
    assert not h.calls and not h.transport.requests
