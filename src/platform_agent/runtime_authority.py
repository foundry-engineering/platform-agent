from __future__ import annotations

import base64
import importlib
import json
import sqlite3
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol, cast

from platform_agent.tenant_authority import TenantSandboxAdmission
from platform_agent.tenant_control import (
    RunReservation,
    SQLiteTenantControlStore,
    TenantContext,
    TenantExecutionSnapshot,
)


class RuntimeAuthorityError(RuntimeError):
    """Raised when the control plane cannot prove current execution authority."""


class AuthorityStateProvider(Protocol):
    """Online authority-state boundary used immediately before execution."""

    def snapshot(
        self,
        tenant_id: str,
        project_id: str,
        repository_id: str,
    ) -> TenantExecutionSnapshot: ...

    def reservation_is_active(self, reservation: RunReservation) -> bool: ...


@dataclass(frozen=True, slots=True)
class SQLiteAuthorityStateProvider:
    """Live provider for the local/on-prem SQLite tenant control backend."""

    store: SQLiteTenantControlStore

    def snapshot(
        self,
        tenant_id: str,
        project_id: str,
        repository_id: str,
    ) -> TenantExecutionSnapshot:
        return self.store.snapshot(tenant_id, project_id, repository_id)

    def reservation_is_active(self, reservation: RunReservation) -> bool:
        uri = f"file:{self.store.path.as_posix()}?mode=ro"
        db = sqlite3.connect(uri, uri=True, timeout=5.0)
        try:
            row = db.execute(
                "SELECT tenant_id,project_id,run_key FROM run_reservations WHERE reservation_id=?",
                (reservation.reservation_id,),
            ).fetchone()
        finally:
            db.close()
        return row == (reservation.tenant_id, reservation.project_id, reservation.run_key)


@dataclass(frozen=True, slots=True)
class AuthorityWitnessSigner:
    kid: str
    public_key: bytes
    sign: Callable[[bytes], bytes]

    def __post_init__(self) -> None:
        if not self.kid:
            raise ValueError("authority-witness signer kid must not be empty")
        if not isinstance(self.public_key, bytes) or len(self.public_key) != 32:
            raise ValueError("authority-witness signer public key must be 32 raw Ed25519 bytes")


@dataclass(frozen=True, slots=True)
class AuthorityWitnessSignerSet:
    keyset_id: str
    signers: tuple[AuthorityWitnessSigner, ...]


WitnessIdDeriver = Callable[[object], str]
WitnessPayloadHasher = Callable[[object], str]
WitnessSigningMessage = Callable[[object], bytes]
WitnessValidator = Callable[[object], None]
WitnessVerifier = Callable[[object, Mapping[str, bytes]], tuple[str, ...]]


def _protocol_runtime() -> tuple[
    WitnessIdDeriver,
    WitnessPayloadHasher,
    WitnessSigningMessage,
    WitnessValidator,
    WitnessVerifier,
]:
    try:
        module = importlib.import_module("agent_protocol.authority_witness")
    except ModuleNotFoundError as exc:
        raise RuntimeAuthorityError("canonical Authority Witness contract is unavailable") from exc
    names = (
        "derive_authority_witness_id",
        "authority_witness_signed_payload_sha256",
        "authority_witness_signing_message",
        "validate_authority_witness",
        "verify_authority_witness_signatures",
    )
    values = [getattr(module, name, None) for name in names]
    if any(not callable(value) for value in values):
        raise RuntimeAuthorityError("installed agent-protocol lacks Authority Witness v1 support")
    return (
        cast(WitnessIdDeriver, values[0]),
        cast(WitnessPayloadHasher, values[1]),
        cast(WitnessSigningMessage, values[2]),
        cast(WitnessValidator, values[3]),
        cast(WitnessVerifier, values[4]),
    )


def _canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _same_context(left: TenantContext, right: Mapping[str, object]) -> bool:
    return _canonical_json(left.as_dict()) == _canonical_json(right)


def _mapping(value: object, *, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise RuntimeAuthorityError(f"{field} must be an object")
    return cast(Mapping[str, object], value)


def _string(value: object, *, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise RuntimeAuthorityError(f"{field} must be a non-empty string")
    return value


def _grant_in_admission(
    admission: TenantSandboxAdmission,
    grant: Mapping[str, object],
) -> Mapping[str, object]:
    grant_id = _string(grant.get("grant_id"), field="grant.grant_id")
    matches = [
        item
        for item in admission.signed_grants
        if item.get("grant_id") == grant_id
    ]
    if len(matches) != 1 or _canonical_json(matches[0]) != _canonical_json(grant):
        raise RuntimeAuthorityError("Execution Grant is not exactly part of this tenant admission")
    return matches[0]


def issue_authority_witness(
    admission: TenantSandboxAdmission,
    *,
    grant: Mapping[str, object],
    workspace_binding: Mapping[str, object],
    repository_id: str,
    authority_state: AuthorityStateProvider,
    signer_set: AuthorityWitnessSignerSet,
    issued_at: datetime,
    expires_at: datetime,
) -> dict[str, object]:
    """Issue a very short-lived online proof that tenant authority is still current."""
    admitted_grant = _grant_in_admission(admission, grant)
    if signer_set.keyset_id != admission.tenant_context.keyset_id:
        raise RuntimeAuthorityError("Authority Witness keyset does not match tenant keyset")
    if not signer_set.signers:
        raise RuntimeAuthorityError("Authority Witness requires at least one signer")
    if issued_at.tzinfo is None or issued_at.utcoffset() is None:
        raise RuntimeAuthorityError("Authority Witness issued_at must be timezone-aware")
    if expires_at.tzinfo is None or expires_at.utcoffset() is None:
        raise RuntimeAuthorityError("Authority Witness expires_at must be timezone-aware")
    issued = issued_at.astimezone(UTC).replace(microsecond=0)
    expires = expires_at.astimezone(UTC).replace(microsecond=0)
    if expires <= issued or expires - issued > timedelta(seconds=120):
        raise RuntimeAuthorityError("Authority Witness must have a positive lifetime <= 120 seconds")

    current = authority_state.snapshot(
        admission.tenant_context.tenant_id,
        admission.tenant_context.project_id,
        repository_id,
    )
    if _canonical_json(current.context.as_dict()) != _canonical_json(admission.tenant_context.as_dict()):
        raise RuntimeAuthorityError("tenant authority changed before witness issuance")
    if not authority_state.reservation_is_active(admission.reservation):
        raise RuntimeAuthorityError("run reservation is no longer active")

    grant_tenant = _mapping(admitted_grant.get("tenant_context"), field="grant.tenant_context")
    if not _same_context(current.context, grant_tenant):
        raise RuntimeAuthorityError("Execution Grant tenant context is no longer current")
    if _string(admitted_grant.get("repo"), field="grant.repo") != repository_id:
        raise RuntimeAuthorityError("Execution Grant repository does not match witness target")

    binding_tenant = _mapping(
        workspace_binding.get("tenant_context"), field="workspace_binding.tenant_context"
    )
    if not _same_context(current.context, binding_tenant):
        raise RuntimeAuthorityError("Workspace Binding tenant context is no longer current")
    if _string(
        workspace_binding.get("repository_id"), field="workspace_binding.repository_id"
    ) != repository_id:
        raise RuntimeAuthorityError("Workspace Binding repository does not match witness target")

    derive_id, payload_hasher, signing_message, validator, verifier = _protocol_runtime()
    document: dict[str, object] = {
        "schema_version": "tenant-authority-witness.v1",
        "witness_id": "taw_" + "0" * 32,
        "tenant_context": current.context.as_dict(),
        "repository_id": repository_id,
        "workspace_binding_id": _string(
            workspace_binding.get("binding_id"), field="workspace_binding.binding_id"
        ),
        "execution_grant_id": _string(admitted_grant.get("grant_id"), field="grant.grant_id"),
        "reservation_id": admission.reservation.reservation_id,
        "issued_at": issued.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    document["witness_id"] = derive_id(document)
    payload_sha = payload_hasher(document)
    message = signing_message(document)

    ordered = tuple(sorted(signer_set.signers, key=lambda item: item.kid))
    kids = [item.kid for item in ordered]
    if len(kids) != len(set(kids)):
        raise RuntimeAuthorityError("Authority Witness signer key ids must be unique")
    signatures: list[dict[str, str]] = []
    for signer in ordered:
        try:
            signature = signer.sign(message)
        except Exception as exc:
            raise RuntimeAuthorityError(f"Authority Witness signer failed: {signer.kid}") from exc
        if not isinstance(signature, bytes) or len(signature) != 64:
            raise RuntimeAuthorityError(
                f"Authority Witness signer must return 64-byte Ed25519 signature: {signer.kid}"
            )
        signatures.append(
            {
                "kid": signer.kid,
                "alg": "ed25519",
                "signed_sha256": payload_sha,
                "sig_b64": base64.b64encode(signature).decode("ascii"),
            }
        )
    document["signatures"] = signatures
    try:
        validator(document)
        verified = verifier(document, {item.kid: item.public_key for item in ordered})
    except Exception as exc:
        raise RuntimeAuthorityError("Authority Witness failed canonical trust verification") from exc
    if tuple(verified) != tuple(kids):
        raise RuntimeAuthorityError("Authority Witness verification set does not match signers")
    return document
