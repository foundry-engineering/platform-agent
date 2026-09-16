from __future__ import annotations

import base64
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from agent_protocol.work_access_witness import (
    derive_work_access_witness_id,
    validate_work_access_witness_against_activation,
    validate_work_access_witness_against_authority,
    validate_work_access_witness_at,
    validate_work_access_witness_request,
    verify_work_access_witness_signatures,
    work_access_witness_signed_payload_sha256,
    work_access_witness_signing_message,
)
from platform_agent.skill_admission_service import GovernedSkillAdmissionService


class WorkAccessWitnessIssuerError(RuntimeError):
    """Raised when live authority cannot safely authorize one tool invocation."""


SignerCallback = Callable[[bytes], bytes]
AuthorityResolver = Callable[[str], Mapping[str, Any]]
ActivationResolver = Callable[[str], Mapping[str, Any]]


@dataclass(frozen=True, slots=True)
class WorkAccessWitnessSigner:
    kid: str
    public_key: bytes
    sign: SignerCallback

    def __post_init__(self) -> None:
        if not self.kid or self.kid.strip() != self.kid:
            raise ValueError("Work Access Witness signer key id must be non-empty and trimmed")
        if not isinstance(self.public_key, bytes) or len(self.public_key) != 32:
            raise ValueError("Work Access Witness signer public key must be 32 Ed25519 bytes")


class WorkAccessWitnessIssuer:
    """Mint an invocation-scoped witness from current control-plane state.

    The issuer never trusts tenant context supplied by a caller. It resolves the
    current active tenant/project context immediately before minting and binds the
    witness to the exact authority, activation and canonical tool request.
    """

    def __init__(
        self,
        *,
        admissions: GovernedSkillAdmissionService,
        resolve_authority: AuthorityResolver,
        resolve_activation: ActivationResolver,
    ) -> None:
        self._admissions = admissions
        self._resolve_authority = resolve_authority
        self._resolve_activation = resolve_activation

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
        work_authority_id: str,
        skill_activation_id: str,
        invocation_id: str,
        request: Mapping[str, Any],
        signers: Sequence[WorkAccessWitnessSigner],
        now: datetime,
        lifetime_seconds: int = 15,
    ) -> dict[str, object]:
        work_authority_id = self._require_identifier(work_authority_id, "work_authority_id")
        skill_activation_id = self._require_identifier(skill_activation_id, "skill_activation_id")
        invocation_id = self._require_identifier(invocation_id, "invocation_id")
        if now.tzinfo is None:
            raise ValueError("trusted now must be timezone-aware")
        if not isinstance(lifetime_seconds, int) or isinstance(lifetime_seconds, bool):
            raise ValueError("lifetime_seconds must be an integer")
        if lifetime_seconds < 1 or lifetime_seconds > 30:
            raise ValueError("lifetime_seconds must be between 1 and 30")
        if not signers:
            raise WorkAccessWitnessIssuerError("at least one Work Access Witness signer is required")
        kids = [signer.kid for signer in signers]
        if len(kids) != len(set(kids)):
            raise WorkAccessWitnessIssuerError("Work Access Witness signer key ids must be unique")

        # This is deliberately resolved at issuance time. Suspension/revocation or
        # an authority-epoch/keyset rotation therefore invalidates stale callers.
        context = self._admissions.current_context(tenant_id, project_id)
        try:
            authority = dict(self._resolve_authority(work_authority_id))
            activation = dict(self._resolve_activation(skill_activation_id))
        except Exception as exc:
            raise WorkAccessWitnessIssuerError("live authority state could not be resolved") from exc

        if authority.get("authority_id") != work_authority_id:
            raise WorkAccessWitnessIssuerError("resolved Work Authority id does not match request")
        if activation.get("activation_id") != skill_activation_id:
            raise WorkAccessWitnessIssuerError("resolved Skill Activation id does not match request")

        resource = request.get("resource")
        if not isinstance(resource, Mapping):
            raise WorkAccessWitnessIssuerError("tool request resource must be an object")
        tool_id = request.get("tool_id")
        connector_id = request.get("connector_id")
        if not isinstance(tool_id, str) or not tool_id:
            raise WorkAccessWitnessIssuerError("tool request tool_id must be non-empty")
        if connector_id is not None and not isinstance(connector_id, str):
            raise WorkAccessWitnessIssuerError("tool request connector_id must be string or null")

        current = now.astimezone(UTC)
        document: dict[str, object] = {
            "schema_version": "work-access-witness.v1",
            "witness_id": "",
            "tenant_context": context.as_dict(),
            "work_authority_id": work_authority_id,
            "skill_activation_id": skill_activation_id,
            "run_id": activation.get("run_id"),
            "task_id": activation.get("task_id"),
            "agent_id": activation.get("agent_id"),
            "role_id": activation.get("role_id"),
            "invocation_id": invocation_id,
            "tool_id": tool_id,
            "connector_id": connector_id,
            "resource": dict(resource),
            "request_sha256": "",
            "issued_at": self._canonical_utc(current),
            "expires_at": self._canonical_utc(current + timedelta(seconds=lifetime_seconds)),
            "signatures": [],
        }

        # Protocol validation computes the canonical request hash. Keep that logic
        # in agent-protocol rather than duplicating canonicalization here.
        from agent_protocol.schema import canonical_sha256

        document["request_sha256"] = canonical_sha256(request)
        document["witness_id"] = derive_work_access_witness_id(document)
        payload_sha256 = work_access_witness_signed_payload_sha256(document)
        message = work_access_witness_signing_message(document)

        ordered = tuple(sorted(signers, key=lambda signer: signer.kid))
        signatures: list[dict[str, str]] = []
        for signer in ordered:
            try:
                signature = signer.sign(message)
            except Exception as exc:
                raise WorkAccessWitnessIssuerError(
                    f"Work Access Witness signer failed: {signer.kid}"
                ) from exc
            if not isinstance(signature, bytes) or len(signature) != 64:
                raise WorkAccessWitnessIssuerError(
                    f"Work Access Witness signer must return 64 Ed25519 bytes: {signer.kid}"
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
            validate_work_access_witness_against_authority(document, authority)
            validate_work_access_witness_against_activation(document, activation)
            validate_work_access_witness_request(document, request)
            validate_work_access_witness_at(document, now=current)
            verified = verify_work_access_witness_signatures(
                document, {signer.kid: signer.public_key for signer in ordered}
            )
        except Exception as exc:
            raise WorkAccessWitnessIssuerError(
                "issued Work Access Witness failed live authorization validation"
            ) from exc
        expected = tuple(signer.kid for signer in ordered)
        if tuple(verified) != expected:
            raise WorkAccessWitnessIssuerError(
                "Work Access Witness signature verification set does not match signers"
            )
        return document
