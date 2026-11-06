from __future__ import annotations

import copy
import json
import ssl
from dataclasses import replace
from typing import Any

import pytest

from platform_agent.core_authority import (
    ClaimedCoreAuthority, CoreAuthorityClient, CoreAuthorityError, CoreAuthorityVerifier,
)
from platform_agent.skill_activation_issuer import SkillActivationIssuer, SkillActivationIssuerError
from test_skill_activation_issuer import FakeAdmissions, _admission, _package, _scope, _signer


def binding() -> ClaimedCoreAuthority:
    return ClaimedCoreAuthority(
        tenant_id="tnt_fixture0001", project_id="prj_fixture0001",
        execution_job_id="job_fixture", work_node_id="node_fixture",
        agent_id="agent_finance.worker", authority_id="wka_" + "f" * 32,
        authority_epoch=7, professional_role="Bookkeeper", provider_budget_microusd=500_000,
        allowed_actions=("read_context", "produce_artifact"), scope=_scope(),
    )


def snapshot(b: ClaimedCoreAuthority) -> dict[str, Any]:
    return {
        "schemaVersion": "foundry.core-runtime-authority.v1",
        "tenantId": b.tenant_id, "workspaceId": b.scope.workspace_id,
        "projectId": b.project_id, "executionJobId": b.execution_job_id,
        "workNodeId": b.work_node_id, "assignmentId": b.scope.assignment_ref,
        "agentId": b.agent_id, "authorityId": b.authority_id,
        "authorityEpoch": b.authority_epoch, "professionalRole": b.professional_role,
        "roleManifestRef": b.scope.role_manifest_ref, "skillIds": [b.scope.skill_id],
        "allowedActions": list(b.allowed_actions), "providerBudgetMicrousd": "500000",
        "status": "active", "allowed": True, "revokedAt": None,
    }


class Transport:
    def __init__(self, monkeypatch):
        self.document = snapshot(binding())
        self.body = None
        self.status = 200
        self.mime = "application/json; charset=utf-8"
        self.requests = []
        self.connections = []
        owner = self

        class Connection:
            def __init__(self, host, port, *, context, timeout):
                assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname
                assert timeout <= 10
                self.sock = None
                self.closed = False
                self.response = None
                owner.connections.append(self)

            def request(self, method, path, *, headers):
                owner.requests.append((method, path, headers))

            def getresponse(self):
                self.response = Response()
                return self.response

            def close(self):
                self.closed = True

        class Response:
            def __init__(self):
                self.status = owner.status
                self.data = owner.body if owner.body is not None else json.dumps(owner.document).encode()
                self.offset = 0

            def getheader(self, key, default=""):
                return owner.mime if key == "Content-Type" else default

            def read1(self, size):
                value = self.data[self.offset:self.offset + size]
                self.offset += len(value)
                return value

        monkeypatch.setattr("platform_agent.core_authority.HTTPSConnection", Connection)
        self.client = CoreAuthorityClient(origin="https://core.example.test", token_supplier=lambda: "service-test-credential")

    def verify(self):
        return CoreAuthorityVerifier(client=self.client, binding=binding())(
            "work-authority", binding().authority_id, FakeAdmissions().context,
            binding().work_node_id, binding().agent_id,
        )


def test_exact_core_scope_is_checked_on_every_issuance(monkeypatch):
    transport = Transport(monkeypatch)
    assert transport.verify() == binding().scope
    request = transport.requests[0]
    assert request[:2] == ("GET", "/api/runtime/authority/" + binding().authority_id)
    assert request[2] == {
        "Authorization": "Bearer service-test-credential", "Accept": "application/json",
        "x-foundry-tenant": binding().tenant_id,
        "x-foundry-workspace": binding().scope.workspace_id,
        "x-foundry-execution-job": binding().execution_job_id,
    }
    transport.document["allowed"] = False
    with pytest.raises(CoreAuthorityError):
        transport.verify()
    assert len(transport.requests) == 2
    assert all(connection.closed for connection in transport.connections)


@pytest.mark.parametrize("field,value", [
    ("schemaVersion", "foreign.v1"), ("tenantId", "tnt_other0001"),
    ("workspaceId", "foreign"), ("projectId", "prj_other0001"),
    ("executionJobId", "other-job"), ("workNodeId", "other-node"),
    ("assignmentId", "other-assignment"), ("agentId", "other-agent"),
    ("authorityId", "wka_" + "0" * 32), ("authorityEpoch", True),
    ("authorityEpoch", 6), ("professionalRole", "Financial Controller"),
    ("roleManifestRef", "sha256:" + "0" * 64), ("skillIds", ["finance.write"]),
    ("skillIds", ["finance.reconcile", "finance.reconcile"]), ("skillIds", [None]),
    ("allowedActions", ["read_context", "produce_artifact", "financial"]),
    ("allowedActions", ["produce_artifact", "produce_artifact"]),
    ("providerBudgetMicrousd", "0500000"), ("providerBudgetMicrousd", 500_000.0),
    ("providerBudgetMicrousd", 500_001), ("allowed", 1),
    ("status", "completed"), ("status", {}), ("revokedAt", "2026-11-06T10:00:00Z"),
])
def test_changed_or_inactive_core_material_cannot_grant_scope(monkeypatch, field, value):
    transport = Transport(monkeypatch)
    transport.document[field] = value
    with pytest.raises(CoreAuthorityError):
        transport.verify()


@pytest.mark.parametrize("change", [
    {"authority_class": "execution-grant"}, {"authority_id": "wka_" + "0" * 32},
    {"task_id": "other-node"}, {"agent_id": "other-agent"},
    {"context": replace(FakeAdmissions().context, tenant_id="tnt_other0001")},
    {"context": replace(FakeAdmissions().context, project_id="prj_other0001")},
    {"context": replace(FakeAdmissions().context, authority_epoch=8)},
])
def test_caller_cannot_transplant_job_before_network(monkeypatch, change):
    transport = Transport(monkeypatch)
    args = dict(authority_class="work-authority", authority_id=binding().authority_id,
                context=FakeAdmissions().context, task_id=binding().work_node_id,
                agent_id=binding().agent_id)
    args.update(change)
    with pytest.raises(CoreAuthorityError):
        CoreAuthorityVerifier(client=transport.client, binding=binding())(**args)
    assert transport.requests == []


@pytest.mark.parametrize("body", [
    b'{"allowed":true,"allowed":false}', b'[]', b'null', b'{"allowed":NaN}',
    b'not-json', b'\xff', b'{"padding":"' + b'x' * 65536 + b'"}',
])
def test_ambiguous_malformed_or_oversized_response_is_denied(monkeypatch, body):
    transport = Transport(monkeypatch)
    transport.body = body
    with pytest.raises(CoreAuthorityError):
        transport.verify()
    assert transport.connections[0].closed


@pytest.mark.parametrize("status", [301, 302, 307, 401, 403, 404, 500])
def test_redirects_and_errors_are_not_retried(monkeypatch, status):
    transport = Transport(monkeypatch)
    transport.status = status
    with pytest.raises(CoreAuthorityError):
        transport.verify()
    assert len(transport.requests) == 1


@pytest.mark.parametrize("origin", ["http://core.test", "https://user:password@core.test",
    "https://core.test/path", "https://core.test?query", "https://core.test#fragment"])
def test_invalid_origin_is_rejected(origin):
    with pytest.raises(ValueError):
        CoreAuthorityClient(origin=origin, token_supplier=lambda: "credential-not-sent")


def test_insecure_tls_context_is_rejected():
    with pytest.raises(ValueError):
        CoreAuthorityClient(origin="https://core.test", token_supplier=lambda: "credential-not-sent",
                            ssl_context=ssl._create_unverified_context())


@pytest.mark.parametrize("credential", ["short", "service-secret\r\nInjected: header", "service-secret €"])
def test_invalid_secret_is_never_transmitted_or_echoed(monkeypatch, credential):
    transport = Transport(monkeypatch)
    client = CoreAuthorityClient(origin="https://core.test", token_supplier=lambda: credential)
    with pytest.raises(CoreAuthorityError) as caught:
        client.read(binding())
    assert credential not in str(caught.value)
    assert transport.connections == []


def test_core_verifier_controls_actual_activation_signing(monkeypatch):
    transport = Transport(monkeypatch)
    package, admissions = _package(), FakeAdmissions()
    admissions.record = _admission(package)
    signer, _public = _signer()
    signatures = []

    def sign(message):
        signatures.append(message)
        return signer.sign(message)

    issuer = SkillActivationIssuer(
        admissions=admissions,
        verify_authority_binding=CoreAuthorityVerifier(client=transport.client, binding=binding()),
    )
    from datetime import UTC, datetime
    inputs = dict(tenant_id=binding().tenant_id, project_id=binding().project_id,
        role_id=binding().scope.role_id, skill_id=binding().scope.skill_id,
        package_id=package["package_id"], package=copy.deepcopy(package),
        run_id="run_" + "b" * 32, task_id=binding().work_node_id, agent_id=binding().agent_id,
        authority_class="work-authority", authority_id=binding().authority_id,
        signers=[replace(signer, sign=sign)], now=datetime(2026, 9, 16, 10, 12, tzinfo=UTC))
    result = issuer.issue(**inputs)
    assert result["tenant_context"]["execution_scope"] == binding().scope.as_dict()
    assert len(signatures) == 1
    transport.document["allowed"] = False
    with pytest.raises(SkillActivationIssuerError):
        issuer.issue(**inputs)
    assert len(signatures) == 1, "revocation must stop issuance before the signer"
