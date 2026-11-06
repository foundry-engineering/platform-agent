"""Native integration probe: actual Platform TLS client against built Core.

The Core HTTPS/PostgreSQL harness sends only isolated fixture material via stdin.
Signing keys and canonical authorities below are explicit isolated fixtures.
No model call, payment or real customer authority is created here.
"""
from __future__ import annotations

import json
import base64
import ssl
import sys
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from agent_protocol.core_work_request import core_work_request_material
from agent_protocol.schema import canonical_sha256
from agent_protocol.work_authority import (
    derive_work_authority_id, work_authority_signed_payload_sha256, work_authority_signing_message,
)

from platform_agent.core_authority import (
    ClaimedCoreAuthority, CoreAuthorityClient, CoreAuthorityError, CoreAuthorityVerifier,
)
from platform_agent.skill_activation_issuer import VerifiedExecutionScope
from platform_agent.tenant_control import TenantContext


def _text(body: dict[str, Any], key: str) -> str:
    value = body[key]
    if not isinstance(value, str) or not value:
        raise ValueError("fixture text is required")
    return value


def _integer(body: dict[str, Any], key: str) -> int:
    value = body[key]
    if type(value) is not int:
        raise ValueError("fixture integer is required")
    return value


def main() -> None:
    data: object = json.loads(sys.stdin.buffer.read(16385))
    if not isinstance(data, dict):
        raise ValueError("bounded fixture object required")
    body: dict[str, Any] = data
    scope = VerifiedExecutionScope(
        workspace_id=_text(body, "workspaceId"), assignment_ref=_text(body, "assignmentId"),
        role_id="test-engineer", role_manifest_ref=_text(body, "roleManifestRef"),
        skill_id=_text(body, "skillId"), skill_manifest_ref="sha256:" + "a" * 64,
    )
    binding = ClaimedCoreAuthority(
        tenant_id=_text(body, "tenantId"), project_id=_text(body, "projectId"),
        execution_job_id=_text(body, "executionJobId"), work_node_id=_text(body, "workNodeId"),
        agent_id=_text(body, "agentId"), authority_id=_text(body, "authorityId"),
        authority_epoch=_integer(body, "authorityEpoch"),
        professional_role=_text(body, "professionalRole"),
        provider_budget_microusd=_integer(body, "providerBudgetMicrousd"),
        allowed_actions=("read_context", "produce_artifact"), scope=scope,
    )
    context = ssl.create_default_context(cafile=_text(body, "caFile"))
    client = CoreAuthorityClient(origin=_text(body, "origin"), ssl_context=context,
                                 token_supplier=lambda: _text(body, "serviceToken"))

    def verify(candidate: ClaimedCoreAuthority, connection: CoreAuthorityClient = client) -> VerifiedExecutionScope:
        tenant = TenantContext(
            tenant_id=candidate.tenant_id, project_id=candidate.project_id,
            cell_id="cell_" + "0" * 32, authority_epoch=candidate.authority_epoch,
            keyset_id="keyset_core-probe.v1",
        )
        return CoreAuthorityVerifier(client=connection, binding=candidate)(
            "work-authority", candidate.authority_id, tenant, candidate.work_node_id, candidate.agent_id,
        )

    assert verify(binding) == scope
    checks = 1
    substitutions = (
        replace(binding, execution_job_id="job_foreign"),
        replace(binding, work_node_id="node_foreign"),
        replace(binding, agent_id="agent_foreign"),
        replace(binding, authority_epoch=binding.authority_epoch + 1),
        replace(binding, provider_budget_microusd=binding.provider_budget_microusd + 1),
        replace(binding, scope=replace(scope, assignment_ref="assignment_foreign")),
        replace(binding, scope=replace(scope, workspace_id="http_other_workspace")),
        replace(binding, scope=replace(scope, role_manifest_ref="sha256:" + "0" * 64)),
    )
    for candidate in substitutions:
        try:
            verify(candidate)
        except CoreAuthorityError:
            checks += 1
        else:
            raise AssertionError("Core/Platform allowed a substituted claimed-job binding")
    untrusted = CoreAuthorityClient(origin=_text(body, "origin"),
                                    token_supplier=lambda: _text(body, "serviceToken"))
    try:
        verify(binding, untrusted)
    except CoreAuthorityError:
        checks += 1
    else:
        raise AssertionError("untrusted Core TLS certificate was accepted")

    def verify_signed(
        candidate: ClaimedCoreAuthority, connection: CoreAuthorityClient = client,
    ) -> VerifiedExecutionScope:
        # Explicit isolated key/authority fixture; all Core reads and signature
        # verification use actual production code, not a verifier double.
        now = datetime.now(UTC).replace(microsecond=0)
        tenant = TenantContext(
            tenant_id=candidate.tenant_id, project_id=candidate.project_id,
            cell_id="cell_" + "0" * 32, authority_epoch=candidate.authority_epoch,
            keyset_id="keyset_core-probe.v1",
        )
        task, agent = "tsk_core-probe-0001", "core-probe-worker"
        context = {**tenant.as_dict(), "execution_scope": candidate.scope.as_dict()}
        material = core_work_request_material(
            tenant_context=context, execution_job_id=candidate.execution_job_id,
            work_node_id=candidate.work_node_id, core_authority_ref=candidate.authority_id,
            core_agent_ref=candidate.agent_id, task_id=task, agent_id=agent,
            professional_role=candidate.professional_role,
            provider_budget_microusd=candidate.provider_budget_microusd,
            allowed_actions=candidate.allowed_actions,
        )
        authority: dict[str, Any] = {
            "schema_version": "work-authority.v1", "authority_id": "",
            "tenant_context": context, "task_id": task, "agent_id": agent,
            "role_id": candidate.scope.role_id, "request_sha256": canonical_sha256(material),
            "policy_ref": {"policy_id": "pol_core-probe", "policy_sha256": "b" * 64,
                           "jurisdiction": "AT", "constraints": []},
            "issued_at": (now - timedelta(seconds=1)).isoformat().replace("+00:00", "Z"),
            "expires_at": (now + timedelta(seconds=60)).isoformat().replace("+00:00", "Z"),
            "resources": [{"resource_type": "artifact", "resource_id": "core-probe-artifact",
                           "actions": ["create"], "data_classification": "confidential"}],
            "tool_ids": ["foundry.provider.execute"], "connector_ids": [],
            "budget": {"max_model_calls": 1, "max_tool_calls": 1,
                       "max_cost_microusd": candidate.provider_budget_microusd, "max_wall_seconds": 60},
            "approvals": [], "constraint_evidence": [], "regulated_reviews": [], "signatures": [],
        }
        authority["authority_id"] = derive_work_authority_id(authority)
        assert authority["authority_id"] != candidate.authority_id
        key = Ed25519PrivateKey.generate()
        authority["signatures"] = [{"kid": "kid_core-probe.v1", "alg": "ed25519",
            "signed_sha256": work_authority_signed_payload_sha256(authority),
            "sig_b64": base64.b64encode(key.sign(work_authority_signing_message(authority))).decode()}]
        return CoreAuthorityVerifier(
            client=connection, binding=candidate, resolve_work_authority=lambda _: authority,
            trusted_work_authority_keys={"kid_core-probe.v1": key.public_key().public_bytes_raw()},
        )("work-authority", authority["authority_id"], tenant, task, agent)

    assert verify_signed(binding) == scope
    checks += 1
    for candidate in substitutions:
        try:
            verify_signed(candidate)
        except CoreAuthorityError:
            checks += 1
        else:
            raise AssertionError("signed canonical authority laundered another Core job")
    try:
        verify_signed(binding, untrusted)
    except CoreAuthorityError:
        checks += 1
    else:
        raise AssertionError("signed authority bypassed Core TLS verification")
    print(json.dumps({"schemaVersion": "foundry.core-authority-acceptance.v1", "checks": checks}))


if __name__ == "__main__":
    main()
