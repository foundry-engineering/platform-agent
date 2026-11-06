"""Bind Skill Activation issuance to the exact live Core execution job.

This adapter verifies existing authority. It neither creates memberships/jobs nor
chooses a profession, package, budget or signing key on behalf of a caller.
"""
from __future__ import annotations

import json
import re
import ssl
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from http.client import HTTPSConnection
from typing import Any
from urllib.parse import quote, urlsplit

from agent_protocol.core_work_request import (
    core_work_request_material, validate_work_authority_core_request,
)

from platform_agent.skill_activation_issuer import VerifiedExecutionScope
from platform_agent.tenant_control import TenantContext

_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_DIGEST = re.compile(r"sha256:[a-f0-9]{64}\Z")
_ROLE = re.compile(r"[a-z][a-z0-9-]{1,127}\Z")
_SKILL = re.compile(r"[a-z][a-z0-9.-]{1,127}\Z")
_ACTIONS = frozenset({"read_context", "produce_artifact"})
_MAX_BODY = 64 * 1024
_MAX_INTEGER = 2**53 - 1


class CoreAuthorityError(RuntimeError):
    """Live Core authority could not be verified; no activation may be issued."""


def _identifier(value: str) -> bool:
    return isinstance(value, str) and _IDENTIFIER.fullmatch(value) is not None


@dataclass(frozen=True, slots=True)
class ClaimedCoreAuthority:
    """Trusted claimed-job/configuration input, never browser/model authority.

    Core's professional-role display label and Protocol's canonical role ID are
    deliberately separate. The configured manifest digest binds their mapping;
    labels are never lowercased or guessed into a different professional role.
    """

    tenant_id: str
    project_id: str
    execution_job_id: str
    work_node_id: str
    agent_id: str
    authority_id: str
    authority_epoch: int
    professional_role: str
    provider_budget_microusd: int
    allowed_actions: tuple[str, ...]
    scope: VerifiedExecutionScope
    artifact_id: str | None = None

    def __post_init__(self) -> None:
        for name in ("tenant_id", "project_id", "execution_job_id", "work_node_id", "agent_id"):
            if not _identifier(getattr(self, name)):
                raise ValueError("claimed Core binding requires canonical identifiers")
        if not isinstance(self.scope, VerifiedExecutionScope):
            raise ValueError("verified professional execution scope required")
        if self.artifact_id is not None and not _identifier(self.artifact_id):
            raise ValueError("canonical claimed artifact reference required")
        if not re.fullmatch(r"wka_[a-f0-9]{32}", self.authority_id):
            raise ValueError("Core work authority identifier required")
        if type(self.authority_epoch) is not int or not 1 <= self.authority_epoch <= _MAX_INTEGER:
            raise ValueError("bounded Core authority epoch required")
        if type(self.provider_budget_microusd) is not int or not 0 < self.provider_budget_microusd <= _MAX_INTEGER:
            raise ValueError("positive approved provider budget required")
        if (not isinstance(self.professional_role, str) or not self.professional_role
                or self.professional_role.strip() != self.professional_role
                or len(self.professional_role) > 128 or any(ord(c) < 32 for c in self.professional_role)):
            raise ValueError("bounded Core professional role required")
        if (not isinstance(self.allowed_actions, tuple) or not self.allowed_actions
                or len(set(self.allowed_actions)) != len(self.allowed_actions)
                or any(action not in _ACTIONS for action in self.allowed_actions)):
            raise ValueError("ordinary artifact work actions required")
        scope = self.scope
        if (not _identifier(scope.workspace_id) or not _identifier(scope.assignment_ref)
                or _ROLE.fullmatch(scope.role_id) is None or _SKILL.fullmatch(scope.skill_id) is None
                or _DIGEST.fullmatch(scope.role_manifest_ref) is None
                or _DIGEST.fullmatch(scope.skill_manifest_ref) is None
                or (scope.studio_id is not None and not _identifier(scope.studio_id))
                or (scope.tool_id is not None and not _identifier(scope.tool_id))):
            raise ValueError("canonical profession, skill and manifest references required")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CoreAuthorityError("ambiguous Core authority response")
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise CoreAuthorityError("invalid Core authority JSON")


class CoreAuthorityClient:
    """Direct verified TLS transport with no proxy, redirect or retry behavior.

    Connected I/O and total response time are bounded. OS DNS resolution cannot
    be cancelled by http.client's connected socket deadline.
    """

    def __init__(
        self, *, origin: str, token_supplier: Callable[[], str],
        ssl_context: ssl.SSLContext | None = None, timeout_seconds: float = 5,
    ) -> None:
        parsed = urlsplit(origin)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
                or parsed.path not in {"", "/"} or parsed.query or parsed.fragment
                or any(ord(c) < 33 for c in origin)):
            raise ValueError("trusted HTTPS Core origin required")
        if isinstance(timeout_seconds, bool) or not 0 < timeout_seconds <= 10:
            raise ValueError("Core deadline must be within ten seconds")
        context = ssl_context or ssl.create_default_context()
        if context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname:
            raise ValueError("Core TLS certificate and hostname verification required")
        self._host, self._port = parsed.hostname, parsed.port or 443
        self._token_supplier, self._context = token_supplier, context
        self._timeout = timeout_seconds

    def read(self, binding: ClaimedCoreAuthority) -> Mapping[str, Any]:
        try:
            token = self._token_supplier()
        except Exception:
            raise CoreAuthorityError("Core service credential unavailable") from None
        if (not isinstance(token, str) or not 16 <= len(token) <= 8192
                or any(ord(c) < 33 or ord(c) > 126 for c in token)):
            raise CoreAuthorityError("Core service credential unavailable")
        connection = HTTPSConnection(self._host, self._port, context=self._context, timeout=self._timeout)
        deadline = time.monotonic() + self._timeout
        try:
            connection.request("GET", "/api/runtime/authority/" + quote(binding.authority_id, safe=""), headers={
                "Authorization": "Bearer " + token,
                "Accept": "application/json",
                "x-foundry-tenant": binding.tenant_id,
                "x-foundry-workspace": binding.scope.workspace_id,
                "x-foundry-execution-job": binding.execution_job_id,
            })
            self._remaining(connection, deadline)
            response = connection.getresponse()
            if response.status != 200:
                raise CoreAuthorityError("Core did not acknowledge live authority")
            if response.getheader("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
                raise CoreAuthorityError("Core authority response is not JSON")
            body = bytearray()
            while True:
                self._remaining(connection, deadline)
                chunk = response.read1(min(8192, _MAX_BODY + 1 - len(body)))
                if not chunk:
                    break
                body.extend(chunk)
                if len(body) > _MAX_BODY:
                    raise CoreAuthorityError("Core authority response exceeded its bound")
            self._remaining(connection, deadline)
            document: object = json.loads(body.decode("utf-8"), object_pairs_hook=_unique_object,
                                          parse_constant=_reject_constant)
            if not isinstance(document, dict):
                raise CoreAuthorityError("Core authority response must be an object")
            return document
        except CoreAuthorityError:
            raise
        except Exception:
            # Neither service credentials nor untrusted upstream bodies/errors
            # may reach a model, ordinary log or activation issuer error message.
            raise CoreAuthorityError("Core authority transport failed closed") from None
        finally:
            connection.close()

    @staticmethod
    def _remaining(connection: HTTPSConnection, deadline: float) -> None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise CoreAuthorityError("Core authority response deadline exceeded")
        if connection.sock is not None:
            connection.sock.settimeout(remaining)


class CoreAuthorityVerifier:
    """Direct callback for SkillActivationIssuer.verify_authority_binding."""

    def __init__(
        self, *, client: CoreAuthorityClient, binding: ClaimedCoreAuthority,
        resolve_work_authority: Callable[[str], Mapping[str, Any]] | None = None,
        trusted_work_authority_keys: Mapping[str, bytes] | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if ((resolve_work_authority is None) != (trusted_work_authority_keys is None)
                or (trusted_work_authority_keys is not None and not trusted_work_authority_keys)):
            raise ValueError("signed Core binding needs a resolver and trusted authority keys")
        self._client, self._binding = client, binding
        self._resolve_work_authority = resolve_work_authority
        self._authority_keys = dict(trusted_work_authority_keys or {})
        self._clock = clock or (lambda: datetime.now(UTC))

    def __call__(
        self, authority_class: str, authority_id: str, context: TenantContext,
        task_id: str, agent_id: str,
    ) -> VerifiedExecutionScope:
        binding = self._binding
        if (authority_class != "work-authority"
                or context.tenant_id != binding.tenant_id or context.project_id != binding.project_id
                or context.authority_epoch != binding.authority_epoch):
            raise CoreAuthorityError("activation request differs from the claimed Core job")
        if self._resolve_work_authority is None:
            if (authority_id != binding.authority_id
                    or task_id != binding.work_node_id or agent_id != binding.agent_id):
                raise CoreAuthorityError("activation request differs from the claimed Core job")
        else:
            try:
                request = core_work_request_material(
                    tenant_context={**context.as_dict(), "execution_scope": binding.scope.as_dict()},
                    execution_job_id=binding.execution_job_id, work_node_id=binding.work_node_id,
                    core_authority_ref=binding.authority_id, core_agent_ref=binding.agent_id,
                    task_id=task_id, agent_id=agent_id, professional_role=binding.professional_role,
                    provider_budget_microusd=binding.provider_budget_microusd,
                    allowed_actions=binding.allowed_actions,
                )
                authority = validate_work_authority_core_request(
                    self._resolve_work_authority(authority_id), request,
                    trusted_keys=self._authority_keys, now=self._clock(),
                )
                if authority["authority_id"] != authority_id:
                    raise CoreAuthorityError("resolved authority identity changed")
            except Exception:
                raise CoreAuthorityError("signed canonical authority does not bind this Core job") from None
        response = self._client.read(binding)
        expected = {
            "schemaVersion": "foundry.core-runtime-authority.v1",
            "tenantId": binding.tenant_id, "workspaceId": binding.scope.workspace_id,
            "projectId": binding.project_id, "executionJobId": binding.execution_job_id,
            "workNodeId": binding.work_node_id, "assignmentId": binding.scope.assignment_ref,
            "agentId": binding.agent_id, "authorityId": binding.authority_id,
            "professionalRole": binding.professional_role,
            "roleManifestRef": binding.scope.role_manifest_ref,
        }
        if binding.artifact_id is not None:
            expected["artifactId"] = binding.artifact_id
        if (any(response.get(key) != value for key, value in expected.items())
                or type(response.get("authorityEpoch")) is not int
                or response.get("authorityEpoch") != binding.authority_epoch
                or response.get("allowed") is not True or response.get("revokedAt", "missing") is not None
                or response.get("status") not in ("authorized", "active")):
            raise CoreAuthorityError("Core returned a different or inactive authority binding")
        budget = response.get("providerBudgetMicrousd")
        if isinstance(budget, str) and re.fullmatch(r"0|[1-9][0-9]{0,15}", budget):
            budget = int(budget)
        if type(budget) is not int or budget != binding.provider_budget_microusd:
            raise CoreAuthorityError("Core provider budget differs from the approved ceiling")
        skills, actions = response.get("skillIds"), response.get("allowedActions")
        if (not isinstance(skills, list) or not 1 <= len(skills) <= 256
                or any(not isinstance(skill, str) or _SKILL.fullmatch(skill) is None for skill in skills)
                or len(skills) != len(set(skills)) or binding.scope.skill_id not in skills
                or not isinstance(actions, list) or any(not isinstance(action, str) for action in actions)
                or len(actions) != len(set(actions)) or set(actions) != set(binding.allowed_actions)):
            raise CoreAuthorityError("Core skill or action scope differs from the admitted work")
        return binding.scope
