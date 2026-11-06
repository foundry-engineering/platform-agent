from __future__ import annotations

import base64
import hashlib
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_protocol.cost_envelope import validate_cost_envelope_binding
from agent_protocol.skill_package import derive_skill_package_id, skill_package_signed_payload_sha256, skill_package_signing_message
from agent_protocol.work_access_witness import validate_work_access_witness_request, verify_work_access_witness_signatures
from foundry_runner.control_plane_http import ClaimedExecutionJob
from foundry_runner.execution_provider import HttpExecutionProvider
from foundry_runner.network_egress import EgressPolicy
from foundry_runner.skill_runtime_gate import SkillRuntimeAdmissionError
from platform_agent.artifact_execution_store import ArtifactExecutionStateError, SQLiteArtifactExecutionStore
from platform_agent.core_execution_authorizer import ArtifactWorkerBinding, CoreExecutionAuthorizationError, CoreExecutionAuthorizer
from platform_agent.core_authority import CoreAuthorityError
from platform_agent.core_work_authority_issuer import ArtifactWorkPolicy, CoreWorkAuthoritySigner
from platform_agent.skill_admission import SkillAdmissionRevokedError, SQLiteSkillAdmissionStore
from platform_agent.skill_admission_service import GovernedSkillAdmissionService
from platform_agent.tenant_control import SQLiteTenantControlStore
from test_core_authority import Transport, binding
from test_skill_activation_issuer import _contract, _package

NOW = datetime(2026, 11, 6, 17, tzinfo=UTC)


class Registrar:
    def __init__(self):
        self.envelopes = []
        self.callback = lambda: None

    def register(self, envelope):
        self.envelopes.append(envelope)
        self.callback()


class Harness:
    def __init__(self, tmp_path, monkeypatch):
        self.transport = Transport(monkeypatch)
        b = replace(binding(), authority_epoch=1, artifact_id="artifact_worker_target")
        self.transport.document.update(artifactId=b.artifact_id, authorityEpoch=1)
        self.job = ClaimedExecutionJob(
            id=b.execution_job_id, workspace_id=b.scope.workspace_id, project_id=b.project_id,
            work_node_id=b.work_node_id, assignment_id=b.scope.assignment_ref, authority_id=b.authority_id,
            authority_epoch=b.authority_epoch, agent_id=b.agent_id, artifact_id=b.artifact_id,
            objective="Produce the isolated acceptance artifact", professional_role=b.professional_role,
            allowed_actions=b.allowed_actions, budget_minor=1200, provider_budget_microusd=b.provider_budget_microusd,
            currency="EUR",
        )
        self.key = Ed25519PrivateKey.generate()
        self.public = self.key.public_key().public_bytes_raw()
        self.kid = "kid_worker-acceptance.v1"
        self.bytes = b"Isolated signed skill package fixture; never executed."
        sbom, provenance, evidence = b"sbom-fixture", b"provenance-fixture", b"verification-fixture"
        def ref(data):
            return "sha256:" + hashlib.sha256(data).hexdigest()
        self.package = _package()
        self.package.update(required_capabilities=[], resource_types=["artifact"])
        self.package["artifact"].update(digest=ref(self.bytes), size_bytes=len(self.bytes),
                                        sbom_ref=ref(sbom), provenance_ref=ref(provenance))
        self.package["verification"].update(verified_at=NOW.isoformat().replace("+00:00", "Z"), evidence_refs=[ref(evidence)])
        self.package["package_id"] = derive_skill_package_id(self.package)
        self.package["signatures"] = [{"kid": self.kid, "alg": "ed25519",
            "signed_sha256": skill_package_signed_payload_sha256(self.package),
            "sig_b64": base64.b64encode(self.key.sign(skill_package_signing_message(self.package))).decode()}]
        self.tenants = SQLiteTenantControlStore(tmp_path / "tenants.db")
        self.tenants.create_tenant(b.tenant_id, keyset_id="keyset_worker-acceptance.v1")
        self.tenants.create_project(b.tenant_id, b.project_id)
        self.admissions = GovernedSkillAdmissionService(
            tenant_store=self.tenants, admission_store=SQLiteSkillAdmissionStore(tmp_path / "admissions.db"),
        )
        self.record = self.admissions.admit(
            tenant_id=b.tenant_id, project_id=b.project_id, role_id=b.scope.role_id,
            package=self.package, skill_contract=_contract(), trusted_signing_keys={self.kid: self.public},
            artifact_bytes=self.bytes, sbom_bytes=sbom, provenance_bytes=provenance,
            verification_evidence={ref(evidence): evidence}, reason="Isolated concrete worker acceptance", now=NOW,
        )
        self.store = SQLiteArtifactExecutionStore(tmp_path / "execution.db")
        self.registrar = Registrar()
        self.provider = HttpExecutionProvider(endpoint="https://provider.example.test", token_supplier=lambda: "unused",
                                              egress_policy=EgressPolicy(allowed_hosts=frozenset({"provider.example.test"})))
        self.config = ArtifactWorkerBinding(
            b.tenant_id, b.project_id, b.scope.workspace_id, b.agent_id, b.professional_role,
            "artifact-worker", b.scope.role_id, b.scope.role_manifest_ref,
        )
        self.calls = []
        self.on_sign = lambda: None
        def sign(message):
            self.calls.append(message)
            self.on_sign()
            return self.key.sign(message)
        self.signer = CoreWorkAuthoritySigner(self.kid, self.public, sign)
        self.now = NOW
        self.authorizer = self.reopen()

    def reopen(self):
        return CoreExecutionAuthorizer(
            binding=self.config, client=self.transport.client, admissions=self.admissions,
            package=self.package, artifact_bytes=self.bytes, policy=ArtifactWorkPolicy("pol_worker-acceptance.v1", "a" * 64, "AT"),
            signers=[self.signer], store=SQLiteArtifactExecutionStore(self.store.path),
            economics=self.registrar, provider=self.provider, clock=lambda: self.now,
        )

    def request(self, admitted):
        return self.provider.work_request(self.job, tenant_id=self.config.tenant_id, assignment=admitted.profession_assignment)


def test_concrete_authorizer_issues_actual_parent_activation_witness_and_exact_budget(tmp_path, monkeypatch):
    h = Harness(tmp_path, monkeypatch)
    admitted = h.authorizer.admit(h.job)
    request = h.request(admitted)
    authorized = h.authorizer.authorize(h.job, admitted=admitted, request=request)
    assert authorized.admitted == admitted
    validate_cost_envelope_binding(authorized.cost_envelope, tenant_context=admitted.profession_assignment.tenant_context.as_dict(),
                                  run_id=admitted.profession_assignment.run_id, task_id=admitted.profession_assignment.task_id,
                                  agent_id=admitted.profession_assignment.agent_id)
    assert authorized.reservation.estimated_total_microusd == h.job.provider_budget_microusd
    assert authorized.reservation.invocation_id == authorized.witness["invocation_id"]
    assert len(h.calls) == 3 and len(h.registrar.envelopes) == 1
    validate_work_access_witness_request(authorized.witness, request)
    assert verify_work_access_witness_signatures(authorized.witness, h.authorizer.trusted_keys) == (h.kid,)
    assert h.admissions.verify_event_chain(h.config.tenant_id)


def test_restart_reuses_live_admission_without_signing_new_parent_or_resetting_budget(tmp_path, monkeypatch):
    h = Harness(tmp_path, monkeypatch)
    admitted = h.authorizer.admit(h.job)
    assert h.reopen().admit(h.job) == admitted
    assert len(h.calls) == 2 and not h.registrar.envelopes


def test_authorization_is_consumed_once_across_restart(tmp_path, monkeypatch):
    h = Harness(tmp_path, monkeypatch)
    admitted = h.authorizer.admit(h.job)
    h.authorizer.authorize(h.job, admitted=admitted, request=h.request(admitted))
    with pytest.raises(ArtifactExecutionStateError):
        h.reopen().authorize(h.job, admitted=admitted, request=h.request(admitted))
    with pytest.raises(ArtifactExecutionStateError):
        h.reopen().admit(h.job)
    assert len(h.calls) == 3 and len(h.registrar.envelopes) == 1


@pytest.mark.parametrize("field,value", [("objective", "Changed objective"), ("artifact_id", "foreign_target"),
                                        ("provider_budget_microusd", 600000), ("authority_epoch", 2)])
def test_changed_job_cannot_receive_fresh_authority(tmp_path, monkeypatch, field, value):
    h = Harness(tmp_path, monkeypatch)
    h.authorizer.admit(h.job)
    with pytest.raises(ArtifactExecutionStateError):
        h.reopen().admit(replace(h.job, **{field: value}))
    assert len(h.calls) == 2


@pytest.mark.parametrize("field,value", [("project_id", "prj_foreign0001"), ("workspace_id", "foreign_workspace"),
                                        ("agent_id", "foreign_core_agent"), ("professional_role", "Other Profession")])
def test_worker_configuration_cannot_be_replaced_by_claim(tmp_path, monkeypatch, field, value):
    h = Harness(tmp_path, monkeypatch)
    with pytest.raises(CoreExecutionAuthorizationError):
        h.authorizer.admit(replace(h.job, **{field: value}))
    assert not h.calls


def test_changed_request_never_receives_paid_authorization(tmp_path, monkeypatch):
    h = Harness(tmp_path, monkeypatch)
    admitted = h.authorizer.admit(h.job)
    request = h.request(admitted)
    request["arguments"]["body"]["objective"] = "Substituted objective"
    with pytest.raises(CoreExecutionAuthorizationError):
        h.authorizer.authorize(h.job, admitted=admitted, request=request)
    assert len(h.calls) == 2 and not h.registrar.envelopes


@pytest.mark.parametrize("change,error", [("package", SkillAdmissionRevokedError), ("core", CoreAuthorityError),
                                         ("expiry", SkillRuntimeAdmissionError)])
def test_revocation_or_expiry_after_admission_prevents_registration_and_witness(tmp_path, monkeypatch, change, error):
    h = Harness(tmp_path, monkeypatch)
    admitted = h.authorizer.admit(h.job)
    if change == "package":
        h.admissions.revoke(h.record.admission_id, reason="Isolated revocation")
    elif change == "core":
        h.transport.document["allowed"] = False
    else:
        h.now += timedelta(seconds=121)
    with pytest.raises(error):
        h.authorizer.authorize(h.job, admitted=admitted, request=h.request(admitted))
    assert len(h.calls) == 2 and not h.registrar.envelopes


def test_failed_signing_is_sticky_and_does_not_reissue_after_restart(tmp_path, monkeypatch):
    h = Harness(tmp_path, monkeypatch)
    def fail():
        raise RuntimeError("isolated signer interruption")
    h.on_sign = fail
    with pytest.raises(CoreExecutionAuthorizationError):
        h.authorizer.admit(h.job)
    with pytest.raises(ArtifactExecutionStateError):
        h.reopen().admit(h.job)
    assert len(h.calls) == 1


def test_package_revoked_during_registration_prevents_witness_and_retry(tmp_path, monkeypatch):
    h = Harness(tmp_path, monkeypatch)
    admitted = h.authorizer.admit(h.job)
    h.registrar.callback = lambda: h.admissions.revoke(h.record.admission_id, reason="During registration")
    with pytest.raises(CoreExecutionAuthorizationError):
        h.authorizer.authorize(h.job, admitted=admitted, request=h.request(admitted))
    with pytest.raises(ArtifactExecutionStateError):
        h.reopen().authorize(h.job, admitted=admitted, request=h.request(admitted))
    assert len(h.calls) == 2


def test_parallel_authorizers_can_consume_only_one_issuance_state(tmp_path):
    path = tmp_path / "parallel.db"
    first = SQLiteArtifactExecutionStore(path)
    assert first.begin("job", "digest") == (True, {})
    first.transition("job", before="issuing", after="admitted", documents={"isolated": True})
    def consume(_):
        try:
            SQLiteArtifactExecutionStore(path).transition("job", before="admitted", after="authorizing")
            return True
        except ArtifactExecutionStateError:
            return False
    with ThreadPoolExecutor(max_workers=4) as pool:
        assert sum(pool.map(consume, range(4))) == 1
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT status FROM artifact_execution").fetchone() == ("authorizing",)
