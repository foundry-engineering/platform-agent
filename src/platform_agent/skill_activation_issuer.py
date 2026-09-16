from __future__ import annotations

import base64
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from agent_protocol.skill_activation import (
    derive_skill_activation_id,
    skill_activation_signed_payload_sha256,
    skill_activation_signing_message,
    validate_skill_activation_against_package,
    verify_skill_activation_signatures,
)
from agent_protocol.skill_package import validate_skill_package
from platform_agent.skill_admission_service import GovernedSkillAdmissionService
from platform_agent.tenant_control import TenantContext


class SkillActivationIssuerError(RuntimeError):
    """Raised when an admitted Skill Package cannot receive runtime activation."""


SignerCallback = Callable[[bytes], bytes]
AuthorityBindingVerifier = Callable[[str, str, TenantContext, str, str], None]


@dataclass(frozen=True, slots=True)
class SkillActivationSigner:
    """External Ed25519 signer used by the control plane.

    Private signing material stays outside Foundry. The issuer verifies every
    returned signature against this public key before returning an activation.
    """

    kid: str
    public_key: bytes
    sign: SignerCallback

    def __post_init__(self) -> None:
        if not self.kid:
            raise ValueError("skill-activation signer key id must not be empty")
        if not isinstance(self.public_key, bytes) or len(self.public_key) != 32:
            raise ValueError("skill-activation signer public key must be 32 Ed25519 bytes")


class SkillActivationIssuer:
    def __init__(
        self,
        *,
        admissions: GovernedSkillAdmissionService,
        verify_authority_binding: AuthorityBindingVerifier,
    ) -> None:
        self._admissions = admissions
        self._verify_authority_binding = verify_authority_binding

    @staticmethod
    def _canonical_utc(value: datetime) -> str:
        if value.tzinfo is None:
            raise ValueError("trusted now must be timezone-aware")
        return value.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")

    @staticmethod
    def _require_identifier(value: str, field: str) -> str:
        if not isinstance(value, str) or not value or value.strip() != value:
            raise ValueError(f"{field} must be non-empty and trimmed")
        if len(value) > 128:
            raise ValueError(f"{field} is too long")
        return value

    def issue(
        self,
        *,
        tenant_id: str,
        project_id: str,
        role_id: str,
        skill_id: str,
        package_id: str,
        package: Mapping[str, Any],
        run_id: str,
        task_id: str,
        agent_id: str,
        authority_class: str,
        authority_id: str,
        signers: Sequence[SkillActivationSigner],
        now: datetime,
        lifetime_seconds: int = 60,
    ) -> dict[str, object]:
        role_id = self._require_identifier(role_id, "role_id")
        skill_id = self._require_identifier(skill_id, "skill_id")
        run_id = self._require_identifier(run_id, "run_id")
        task_id = self._require_identifier(task_id, "task_id")
        agent_id = self._require_identifier(agent_id, "agent_id")
        authority_id = self._require_identifier(authority_id, "authority_id")
        if not isinstance(lifetime_seconds, int) or isinstance(lifetime_seconds, bool):
            raise ValueError("lifetime_seconds must be an integer")
        if lifetime_seconds < 1 or lifetime_seconds > 120:
            raise ValueError("lifetime_seconds must be between 1 and 120")
        if not signers:
            raise SkillActivationIssuerError("at least one Skill Activation signer is required")
        signer_kids = [signer.kid for signer in signers]
        if len(signer_kids) != len(set(signer_kids)):
            raise SkillActivationIssuerError("Skill Activation signer key ids must be unique")

        current = now.astimezone(UTC) if now.tzinfo is not None else None
        if current is None:
            raise ValueError("trusted now must be timezone-aware")
        context = self._admissions.current_context(tenant_id, project_id)
        admission = self._admissions.resolve(
            tenant_id=tenant_id,
            project_id=project_id,
            role_id=role_id,
            skill_id=skill_id,
            package_id=package_id,
        )

        try:
            validate_skill_package(package)
        except Exception as exc:
            raise SkillActivationIssuerError("Skill Package failed canonical validation") from exc

        package_artifact = package.get("artifact")
        if not isinstance(package_artifact, dict):
            raise SkillActivationIssuerError("Skill Package artifact is invalid")
        package_bindings = {
            "package_id": package.get("package_id"),
            "skill_id": package.get("skill_id"),
            "skill_version": package.get("skill_version"),
            "skill_contract_sha256": package.get("skill_contract_sha256"),
            "artifact_digest": package_artifact.get("digest"),
        }
        admission_bindings = {
            "package_id": admission.package_id,
            "skill_id": admission.skill_id,
            "skill_version": admission.skill_version,
            "skill_contract_sha256": admission.skill_contract_sha256,
            "artifact_digest": admission.artifact_digest,
        }
        if package_bindings != admission_bindings:
            raise SkillActivationIssuerError(
                "Skill Package does not match the active persisted admission"
            )
        package_authority_class = package.get("authority_class")
        if package_authority_class != authority_class:
            raise SkillActivationIssuerError(
                "requested authority class does not match the admitted Skill Package"
            )

        try:
            self._verify_authority_binding(
                authority_class,
                authority_id,
                context,
                task_id,
                agent_id,
            )
        except Exception as exc:
            raise SkillActivationIssuerError("governing authority verification failed") from exc

        issued_at = self._canonical_utc(current)
        expires_at = self._canonical_utc(current + timedelta(seconds=lifetime_seconds))
        document: dict[str, object] = {
            "schema_version": "skill-activation.v1",
            "activation_id": "",
            "tenant_context": context.as_dict(),
            "admission_id": admission.admission_id,
            "run_id": run_id,
            "task_id": task_id,
            "agent_id": agent_id,
            "role_id": role_id,
            "skill_id": admission.skill_id,
            "skill_version": admission.skill_version,
            "package_id": admission.package_id,
            "skill_contract_sha256": admission.skill_contract_sha256,
            "artifact_digest": admission.artifact_digest,
            "authority_class": authority_class,
            "authority_id": authority_id,
            "issued_at": issued_at,
            "expires_at": expires_at,
        }
        document["activation_id"] = derive_skill_activation_id(document)
        payload_sha256 = skill_activation_signed_payload_sha256(document)
        message = skill_activation_signing_message(document)

        ordered = tuple(sorted(signers, key=lambda signer: signer.kid))
        signatures: list[dict[str, str]] = []
        for signer in ordered:
            try:
                signature = signer.sign(message)
            except Exception as exc:
                raise SkillActivationIssuerError(
                    f"Skill Activation signer failed: {signer.kid}"
                ) from exc
            if not isinstance(signature, bytes) or len(signature) != 64:
                raise SkillActivationIssuerError(
                    f"Skill Activation signer must return 64 Ed25519 bytes: {signer.kid}"
                )
            signatures.append(
                {
                    "kid": signer.kid,
                    "alg": "ed25519",
                    "signed_sha256": payload_sha256,
                    "sig_b64": base64.b64encode(signature).decode("ascii"),
                }
            )
        document["signatures"] = signatures

        try:
            validate_skill_activation_against_package(document, package)
        except Exception as exc:
            raise SkillActivationIssuerError(
                "issued Skill Activation failed canonical package binding"
            ) from exc

        trusted_keys = {signer.kid: signer.public_key for signer in ordered}
        try:
            verified = verify_skill_activation_signatures(document, trusted_keys)
        except Exception as exc:
            raise SkillActivationIssuerError(
                "Skill Activation signer output failed cryptographic verification"
            ) from exc
        expected = tuple(signer.kid for signer in ordered)
        if tuple(verified) != expected:
            raise SkillActivationIssuerError(
                "Skill Activation signature verification set does not match signers"
            )
        return document
