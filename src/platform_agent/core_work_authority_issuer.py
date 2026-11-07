"""Issue ordinary artifact Work Authority from exact, current Core job approval.

All policy, package and signer configuration is trusted platform configuration.
The model supplies none of it. No execution grant or consequential action is
created here; Core retains business approval and the worker retains paid gates.
"""
from __future__ import annotations

import base64
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from agent_protocol.core_work_request import (
    core_work_request_material, validate_work_authority_core_request,
)
from agent_protocol.schema import canonical_sha256
from agent_protocol.work_authority import (
    derive_work_authority_id, work_authority_signed_payload_sha256, work_authority_signing_message,
)

from .core_authority import ClaimedCoreAuthority, CoreAuthorityClient, CoreAuthorityVerifier
from .skill_admission_service import GovernedSkillAdmissionService


class CoreWorkAuthorityIssuerError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class ArtifactWorkPolicy:
    policy_id: str
    policy_sha256: str
    jurisdiction: str
    lifetime_seconds: int = 120
    max_model_calls: int = 1

    def __post_init__(self) -> None:
        for name, low, high in (("policy_id", 3, 128), ("jurisdiction", 2, 64)):
            value = getattr(self, name)
            if (not isinstance(value, str) or not low <= len(value) <= high
                    or value.strip() != value or any(ord(c) < 32 for c in value)):
                raise ValueError("trusted artifact policy requires bounded canonical text")
        if not isinstance(self.policy_sha256, str) or re.fullmatch(r"[a-f0-9]{64}", self.policy_sha256) is None:
            raise ValueError("trusted artifact policy requires its exact SHA-256")
        if type(self.lifetime_seconds) is not int or not 1 <= self.lifetime_seconds <= 120:
            raise ValueError("artifact authority lifetime must be within 120 seconds")
        if type(self.max_model_calls) is not int or not 1 <= self.max_model_calls <= 6:
            raise ValueError("artifact model calls must be within 1..6")


@dataclass(frozen=True, slots=True)
class CoreWorkAuthoritySigner:
    kid: str
    public_key: bytes
    sign: Callable[[bytes], bytes]

    def __post_init__(self) -> None:
        if (not isinstance(self.kid, str) or not 3 <= len(self.kid) <= 160
                or self.kid.strip() != self.kid or any(ord(c) < 33 for c in self.kid)):
            raise ValueError("canonical Work Authority signing key identifier required")
        if not isinstance(self.public_key, bytes) or len(self.public_key) != 32:
            raise ValueError("Work Authority signer needs its Ed25519 public key")
        if not callable(self.sign):
            raise ValueError("external Work Authority signing callback required")


class CoreWorkAuthorityIssuer:
    def __init__(
        self, *, client: CoreAuthorityClient, admissions: GovernedSkillAdmissionService,
        policy: ArtifactWorkPolicy, clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._client, self._admissions, self._policy = client, admissions, policy
        self._clock = clock or (lambda: datetime.now(UTC))

    def issue(
        self, *, binding: ClaimedCoreAuthority, task_id: str, agent_id: str,
        package_id: str, signers: Sequence[CoreWorkAuthoritySigner],
    ) -> dict[str, Any]:
        if (binding.artifact_id is None or "produce_artifact" not in binding.allowed_actions
                or not all(isinstance(value, str) for value in (task_id, agent_id, package_id))
                or re.fullmatch(r"tsk_[A-Za-z0-9_-]{8,127}", task_id) is None
                or re.fullmatch(r"[a-z][a-z0-9-]{1,63}", agent_id) is None
                or re.fullmatch(r"[a-z][a-z0-9-]{1,63}", binding.scope.role_id) is None
                or re.fullmatch(r"skp_[a-f0-9]{32}", package_id) is None):
            raise CoreWorkAuthorityIssuerError("exact ordinary artifact work and canonical identities required")
        if (not isinstance(signers, Sequence) or not 1 <= len(signers) <= 16
                or any(not isinstance(signer, CoreWorkAuthoritySigner) for signer in signers)):
            raise CoreWorkAuthorityIssuerError("unique trusted Work Authority signers required")
        ordered = tuple(sorted(signers, key=lambda signer: signer.kid))
        if len({signer.kid for signer in ordered}) != len(ordered):
            raise CoreWorkAuthorityIssuerError("unique trusted Work Authority signers required")
        current = self._clock()
        if current.tzinfo is None or current.utcoffset() is None:
            raise CoreWorkAuthorityIssuerError("trusted timezone-aware clock required")
        issued = current.astimezone(UTC).replace(microsecond=0)
        expires = issued + timedelta(seconds=self._policy.lifetime_seconds)
        try:
            context = self._admissions.current_context(binding.tenant_id, binding.project_id)
            admission = self._admissions.resolve(
                tenant_id=binding.tenant_id, project_id=binding.project_id,
                role_id=binding.scope.role_id, skill_id=binding.scope.skill_id, package_id=package_id,
            )
            if (admission.status != "active" or admission.tenant_id != context.tenant_id
                    or admission.project_id != context.project_id or admission.cell_id != context.cell_id
                    or admission.role_id != binding.scope.role_id or admission.skill_id != binding.scope.skill_id
                    or admission.package_id != package_id
                    or binding.scope.skill_manifest_ref != "sha256:" + admission.skill_contract_sha256):
                raise CoreWorkAuthorityIssuerError("current package admission differs from the work")
            verifier = CoreAuthorityVerifier(client=self._client, binding=binding)
            verifier("work-authority", binding.authority_id, context, binding.work_node_id, binding.agent_id)
            scoped = {**context.as_dict(), "execution_scope": binding.scope.as_dict()}
            request = core_work_request_material(
                tenant_context=scoped, execution_job_id=binding.execution_job_id,
                work_node_id=binding.work_node_id, core_authority_ref=binding.authority_id,
                core_agent_ref=binding.agent_id, task_id=task_id, agent_id=agent_id,
                professional_role=binding.professional_role,
                provider_budget_microusd=binding.provider_budget_microusd,
                allowed_actions=binding.allowed_actions,
            )
            admission_snapshot = admission.as_dict()
        except Exception:
            raise CoreWorkAuthorityIssuerError("live Core and package admission could not authorize work") from None

        def recheck() -> None:
            try:
                now = self._clock()
                if (now.tzinfo is None or now.utcoffset() is None
                        or not issued <= now.astimezone(UTC) < expires):
                    raise CoreWorkAuthorityIssuerError("work issuance deadline expired")
                live_context = self._admissions.current_context(binding.tenant_id, binding.project_id)
                live_admission = self._admissions.resolve(
                    tenant_id=binding.tenant_id, project_id=binding.project_id,
                    role_id=binding.scope.role_id, skill_id=binding.scope.skill_id, package_id=package_id,
                )
                if live_context != context or live_admission.as_dict() != admission_snapshot:
                    raise CoreWorkAuthorityIssuerError("live admission changed during issuance")
                verifier("work-authority", binding.authority_id, live_context,
                         binding.work_node_id, binding.agent_id)
            except Exception:
                raise CoreWorkAuthorityIssuerError("current Core/package authority cannot be proven") from None

        document: dict[str, Any] = {
            "schema_version": "work-authority.v1", "authority_id": "", "tenant_context": scoped,
            "task_id": task_id, "agent_id": agent_id, "role_id": binding.scope.role_id,
            "request_sha256": canonical_sha256(request),
            "policy_ref": {"policy_id": self._policy.policy_id, "policy_sha256": self._policy.policy_sha256,
                           "jurisdiction": self._policy.jurisdiction, "constraints": []},
            "issued_at": issued.isoformat().replace("+00:00", "Z"),
            "expires_at": expires.isoformat().replace("+00:00", "Z"),
            "resources": [{"resource_type": "artifact", "resource_id": binding.artifact_id,
                           "actions": ["create"], "data_classification": "restricted"}],
            "tool_ids": ["foundry.provider.execute"], "connector_ids": [],
            "budget": {"max_model_calls": self._policy.max_model_calls, "max_tool_calls": self._policy.max_model_calls,
                       "max_cost_microusd": binding.provider_budget_microusd,
                       "max_wall_seconds": self._policy.lifetime_seconds},
            "approvals": [], "constraint_evidence": [], "regulated_reviews": [], "signatures": [],
        }
        document["authority_id"] = derive_work_authority_id(document)
        digest = work_authority_signed_payload_sha256(document)
        message = work_authority_signing_message(document)
        signatures: list[dict[str, str]] = []
        for signer in ordered:
            recheck()
            try:
                signature = signer.sign(message)
                if not isinstance(signature, bytes) or len(signature) != 64:
                    raise CoreWorkAuthorityIssuerError("signer returned invalid signature bytes")
            except Exception:
                raise CoreWorkAuthorityIssuerError("Work Authority signing failed") from None
            signatures.append({"kid": signer.kid, "alg": "ed25519", "signed_sha256": digest,
                               "sig_b64": base64.b64encode(signature).decode("ascii")})
        document["signatures"] = signatures
        recheck()
        try:
            return validate_work_authority_core_request(
                document, request, trusted_keys={s.kid: s.public_key for s in ordered}, now=self._clock(),
            )
        except Exception:
            raise CoreWorkAuthorityIssuerError("issued Work Authority did not verify") from None
