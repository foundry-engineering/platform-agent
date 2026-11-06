"""Native integration probe: actual Platform TLS client against built Core.

The Core HTTPS/PostgreSQL harness sends only isolated fixture material via stdin.
No model call, signer, payment or real customer authority is created here.
"""
from __future__ import annotations

import json
import ssl
import sys
from dataclasses import replace
from typing import Any

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
    for candidate in (
        replace(binding, execution_job_id="job_foreign"),
        replace(binding, work_node_id="node_foreign"),
        replace(binding, agent_id="agent_foreign"),
        replace(binding, authority_epoch=binding.authority_epoch + 1),
        replace(binding, provider_budget_microusd=binding.provider_budget_microusd + 1),
        replace(binding, scope=replace(scope, assignment_ref="assignment_foreign")),
        replace(binding, scope=replace(scope, workspace_id="http_other_workspace")),
        replace(binding, scope=replace(scope, role_manifest_ref="sha256:" + "0" * 64)),
    ):
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
    print(json.dumps({"schemaVersion": "foundry.core-authority-acceptance.v1", "checks": checks}))


if __name__ == "__main__":
    main()
