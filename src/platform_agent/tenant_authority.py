from __future__ import annotations

import base64
import hashlib
import importlib
import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, cast

from platform_agent.capability_router import CapabilityRegistry
from platform_agent.control_plane import DispatchPlan, build_dispatch_plan
from platform_agent.execution_authority import (
    ApprovalVerifier,
    ConstraintEvaluator,
    ExecutionRequest,
    SandboxAdmissionError,
    _admit_request,
    _protocol_runtimes,
    _task_map,
    builtin_constraint_evaluators,
)
from platform_agent.grant_signing import ExecutionGrantSigner, sign_execution_grant
from platform_agent.plan_admission import PlanAdmission
from platform_agent.scope_guard import ScopeGuardError, validate_execution_request_scopes
from platform_agent.tenant_control import (
    RunReservation,
    SQLiteTenantControlStore,
    TenantContext,
    TenantExecutionSnapshot,
)

GrantIdDeriver = Callable[[object], str]
GrantValidator = Callable[[object], None]
WorkspaceIdDeriver = Callable[[object], str]
WorkspacePayloadHasher = Callable[[object], str]
WorkspaceSigningMessage = Callable[[object], bytes]
WorkspaceValidator = Callable[[object], None]
WorkspaceSignatureVerifier = Callable[[object, Mapping[str, bytes]], tuple[str, ...]]
_MAX_WORKSPACE_BINDING_LIFETIME = timedelta(hours=1)


class TenantAuthorityError(SandboxAdmissionError):
    """Raised when tenant-isolated authority cannot be issued safely."""


@dataclass(frozen=True, slots=True)
class TenantSignerSet:
    keyset_id: str
    signers: tuple[ExecutionGrantSigner, ...]


@dataclass(frozen=True, slots=True)
class WorkspaceBindingSigner:
    """External workspace-lease signer with independently verifiable public key."""

    kid: str
    public_key: bytes
    sign: Callable[[bytes], bytes]

    def __post_init__(self) -> None:
        if not self.kid:
            raise ValueError("workspace signer key id must not be empty")
        if not isinstance(self.public_key, bytes) or len(self.public_key) != 32:
            raise ValueError("workspace signer public key must be 32 raw Ed25519 bytes")


@dataclass(frozen=True, slots=True)
class TenantSandboxAdmission:
    schema_version: str
    admission_id: str
    tenant_context: TenantContext
    tenant_snapshot_sha256: str
    reservation: RunReservation
    dispatch: DispatchPlan
    signed_grants: tuple[Mapping[str, object], ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "admission_id": self.admission_id,
            "tenant_context": self.tenant_context.as_dict(),
            "tenant_snapshot_sha256": self.tenant_snapshot_sha256,
            "reservation": self.reservation.as_dict(),
            "dispatch": self.dispatch.as_dict(),
            "signed_grants": [dict(grant) for grant in self.signed_grants],
        }


def _canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _protocol_grant_runtime() -> tuple[GrantIdDeriver, GrantValidator]:
    try:
        module = importlib.import_module("agent_protocol.execution_grant")
    except ModuleNotFoundError as exc:
        raise TenantAuthorityError("canonical tenant-bound Execution Grant contract unavailable") from exc
    deriver = getattr(module, "derive_execution_grant_id", None)
    validator = getattr(module, "validate_execution_grant", None)
    if not callable(deriver) or not callable(validator):
        raise TenantAuthorityError("installed agent-protocol lacks tenant-bound Execution Grant")
    return cast(GrantIdDeriver, deriver), cast(GrantValidator, validator)


def _workspace_protocol_runtime() -> tuple[
    WorkspaceIdDeriver,
    WorkspacePayloadHasher,
    WorkspaceSigningMessage,
    WorkspaceValidator,
    WorkspaceSignatureVerifier,
]:
    try:
        module = importlib.import_module("agent_protocol.workspace_binding")
    except ModuleNotFoundError as exc:
        raise TenantAuthorityError("canonical Workspace Binding contract unavailable") from exc
    deriver = getattr(module, "derive_workspace_binding_id", None)
    hasher = getattr(module, "workspace_binding_signed_payload_sha256", None)
    signing_message = getattr(module, "workspace_binding_signing_message", None)
    validator = getattr(module, "validate_workspace_binding", None)
    verifier = getattr(module, "verify_workspace_binding_signatures", None)
    if not all(callable(item) for item in (deriver, hasher, signing_message, validator, verifier)):
        raise TenantAuthorityError("installed agent-protocol lacks Workspace Binding support")
    return (
        cast(WorkspaceIdDeriver, deriver),
        cast(WorkspacePayloadHasher, hasher),
        cast(WorkspaceSigningMessage, signing_message),
        cast(WorkspaceValidator, validator),
        cast(WorkspaceSignatureVerifier, verifier),
    )


def _same_context(left: TenantContext, right: TenantContext) -> bool:
    return _canonical_json(left.as_dict()) == _canonical_json(right.as_dict())


def _snapshots_for_dispatch(
    store: SQLiteTenantControlStore,
    *,
    tenant_id: str,
    project_id: str,
    requests: Sequence[ExecutionRequest],
) -> tuple[TenantExecutionSnapshot, ...]:
    snapshots: list[TenantExecutionSnapshot] = []
    by_repository: dict[str, TenantExecutionSnapshot] = {}
    for request in requests:
        if request.repo is None:
            raise TenantAuthorityError(
                f"tenant execution request requires repository binding: {request.task_id}"
            )
        if request.repo not in by_repository:
            by_repository[request.repo] = store.snapshot(tenant_id, project_id, request.repo)
        snapshots.append(by_repository[request.repo])
    if not snapshots:
        raise TenantAuthorityError("tenant dispatch contains no execution requests")
    context = snapshots[0].context
    if any(not _same_context(context, item.context) for item in snapshots[1:]):
        raise TenantAuthorityError("tenant snapshots do not share one authority context")
    return tuple(snapshots)


def _unsigned_tenant_grant(
    legacy_grant: object,
    *,
    context: TenantContext,
    derive_id: GrantIdDeriver,
    validator: GrantValidator,
) -> dict[str, object]:
    as_dict = getattr(legacy_grant, "as_dict", None)
    if not callable(as_dict):
        raise TenantAuthorityError("internal execution grant does not serialize canonically")
    raw = as_dict()
    if not isinstance(raw, dict):
        raise TenantAuthorityError("internal execution grant serialization is invalid")
    document: dict[str, object] = dict(raw)
    document["tenant_context"] = context.as_dict()
    document.pop("signatures", None)
    document["grant_id"] = derive_id(document)
    try:
        validator(document)
    except Exception as exc:
        raise TenantAuthorityError("tenant-bound unsigned Execution Grant is invalid") from exc
    return document


def admit_tenant_dispatch(
    plan: object,
    *,
    admission: PlanAdmission,
    registry: CapabilityRegistry,
    tenant_store: SQLiteTenantControlStore,
    tenant_id: str,
    project_id: str,
    requests: Sequence[ExecutionRequest],
    policies: Mapping[str, object],
    signer_set: TenantSignerSet,
    approval_verifiers: Mapping[str, ApprovalVerifier] | None = None,
    constraint_evaluators: Mapping[str, ConstraintEvaluator] | None = None,
    completed: frozenset[str] = frozenset(),
    failed: frozenset[str] = frozenset(),
    satisfied_preconditions: frozenset[str] = frozenset(),
) -> TenantSandboxAdmission:
    """Atomically admit ready work into one tenant isolation cell and sign its authority."""
    try:
        validate_execution_request_scopes(requests)
    except ScopeGuardError as exc:
        raise TenantAuthorityError(str(exc)) from exc

    dispatch = build_dispatch_plan(
        plan,
        admission=admission,
        registry=registry,
        completed=completed,
        failed=failed,
        satisfied_preconditions=satisfied_preconditions,
    )
    plan_map, tasks = _task_map(plan)
    snapshots = _snapshots_for_dispatch(
        tenant_store,
        tenant_id=tenant_id,
        project_id=project_id,
        requests=requests,
    )
    context = snapshots[0].context
    if signer_set.keyset_id != context.keyset_id:
        raise TenantAuthorityError("execution signer keyset does not match current tenant keyset")
    if not signer_set.signers:
        raise TenantAuthorityError("tenant execution authority requires at least one signer")

    by_task: dict[str, ExecutionRequest] = {}
    for request in requests:
        if request.task_id in by_task:
            raise TenantAuthorityError(f"duplicate execution request: {request.task_id}")
        by_task[request.task_id] = request
    assignment_ids = {item.task_id for item in dispatch.assignments}
    if set(by_task) != assignment_ids:
        raise TenantAuthorityError("execution requests must exactly match ready dispatch assignments")

    policy_validator, policy_hasher, _unused_validator, _unused_deriver = _protocol_runtimes()
    canonical_deriver, canonical_validator = _protocol_grant_runtime()
    verifier_map = dict(approval_verifiers or {})
    evaluator_map = builtin_constraint_evaluators()
    evaluator_map.update(constraint_evaluators or {})

    def pretenant_id(value: object) -> str:
        return "sgr_" + _sha256(value)[:32]

    legacy_grants = tuple(
        _admit_request(
            dispatch=dispatch,
            plan_admission=admission,
            registry=registry,
            assignment=assignment,
            task=tasks[assignment.task_id],
            plan=plan_map,
            request=by_task[assignment.task_id],
            policies=policies,
            approval_verifiers=verifier_map,
            constraint_evaluators=evaluator_map,
            policy_validator=policy_validator,
            policy_hasher=policy_hasher,
            grant_validator=lambda value: None,
            grant_deriver=pretenant_id,
        )
        for assignment in dispatch.assignments
    )

    unsigned = tuple(
        _unsigned_tenant_grant(
            item,
            context=context,
            derive_id=canonical_deriver,
            validator=canonical_validator,
        )
        for item in legacy_grants
    )

    repositories = tuple(
        sorted(
            {
                request.repo
                for request in requests
                if isinstance(request.repo, str) and request.repo
            }
        )
    )
    if not repositories:
        raise TenantAuthorityError("tenant dispatch requires repository binding")

    reservation: RunReservation | None = None
    try:
        reservation = tenant_store.reserve_dispatch(
            tenant_id,
            project_id,
            list(repositories),
            run_key=dispatch.dispatch_id,
        )
        signed = tuple(
            sign_execution_grant(document, signers=signer_set.signers)
            for document in unsigned
        )
        current_snapshots = _snapshots_for_dispatch(
            tenant_store,
            tenant_id=tenant_id,
            project_id=project_id,
            requests=requests,
        )
        current = current_snapshots[0]
        if any(not _same_context(context, item.context) for item in current_snapshots):
            raise TenantAuthorityError("tenant authority changed during grant issuance")
        if current.context.keyset_id != signer_set.keyset_id:
            raise TenantAuthorityError("tenant keyset changed during grant issuance")
        if not tenant_store.reservation_is_active(reservation):
            raise TenantAuthorityError("run reservation changed during grant issuance")
    except Exception:
        if reservation is not None:
            try:
                tenant_store.release_run(reservation.reservation_id)
            except Exception as release_exc:
                raise TenantAuthorityError(
                    "grant issuance failed and run reservation cleanup also failed"
                ) from release_exc
        raise

    material = {
        "schema_version": "foundry.tenant-sandbox-admission.v1",
        "tenant_context": context.as_dict(),
        "tenant_snapshot_sha256": current.snapshot_sha256,
        "reservation": reservation.as_dict(),
        "dispatch_id": dispatch.dispatch_id,
        "plan_admission_id": admission.admission_id,
        "candidate_sha256": admission.candidate_sha256,
        "registry_sha256": registry.registry_sha256,
        "grant_ids": [str(item["grant_id"]) for item in signed],
    }
    return TenantSandboxAdmission(
        schema_version="foundry.tenant-sandbox-admission.v1",
        admission_id="tsa_" + _sha256(material)[:32],
        tenant_context=context,
        tenant_snapshot_sha256=current.snapshot_sha256,
        reservation=reservation,
        dispatch=dispatch,
        signed_grants=cast(tuple[Mapping[str, object], ...], signed),
    )


def release_tenant_admission(
    admission: TenantSandboxAdmission,
    *,
    tenant_store: SQLiteTenantControlStore,
) -> None:
    tenant_store.release_run(admission.reservation.reservation_id)


def issue_workspace_binding(
    snapshot: TenantExecutionSnapshot,
    *,
    workspace_id: str,
    base_commit_sha: str,
    issued_at: datetime,
    expires_at: datetime,
    keyset_id: str,
    signers: Sequence[WorkspaceBindingSigner],
) -> dict[str, object]:
    """Issue a short-lived signed workspace lease for one tenant/project/repository."""
    if keyset_id != snapshot.context.keyset_id:
        raise TenantAuthorityError("workspace signer keyset does not match current tenant keyset")
    if not signers:
        raise TenantAuthorityError("workspace binding requires at least one signer")
    if issued_at.tzinfo is None or issued_at.utcoffset() is None:
        raise TenantAuthorityError("workspace binding issued_at must be timezone-aware")
    if expires_at.tzinfo is None or expires_at.utcoffset() is None:
        raise TenantAuthorityError("workspace binding expires_at must be timezone-aware")
    issued = issued_at.astimezone(UTC).replace(microsecond=0)
    expires = expires_at.astimezone(UTC).replace(microsecond=0)
    lifetime = expires - issued
    if lifetime <= timedelta(0):
        raise TenantAuthorityError("workspace binding expiry must be after issue time")
    if lifetime > _MAX_WORKSPACE_BINDING_LIFETIME:
        raise TenantAuthorityError("workspace binding lifetime must not exceed one hour")
    if len(base_commit_sha) != 40 or any(ch not in "0123456789abcdef" for ch in base_commit_sha):
        raise TenantAuthorityError("workspace base commit must be lowercase 40-hex SHA")

    derive_id, payload_hasher, signing_message, validator, verifier = _workspace_protocol_runtime()
    document: dict[str, object] = {
        "schema_version": "workspace-binding.v1",
        "binding_id": "wsb_" + "0" * 32,
        "tenant_context": snapshot.context.as_dict(),
        "workspace_id": workspace_id,
        "repository_id": snapshot.repository_id,
        "base_commit_sha": base_commit_sha,
        "issued_at": issued.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    document["binding_id"] = derive_id(document)
    payload_sha = payload_hasher(document)
    message = signing_message(document)
    kids = [item.kid for item in signers]
    if len(kids) != len(set(kids)):
        raise TenantAuthorityError("workspace signer key ids must be unique")

    ordered_signers = tuple(sorted(signers, key=lambda item: item.kid))
    signatures: list[dict[str, str]] = []
    for signer in ordered_signers:
        try:
            signature = signer.sign(message)
        except Exception as exc:
            raise TenantAuthorityError(f"workspace signer failed: {signer.kid}") from exc
        if not isinstance(signature, bytes) or len(signature) != 64:
            raise TenantAuthorityError(
                f"workspace signer must return 64-byte Ed25519 signature: {signer.kid}"
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
    except Exception as exc:
        raise TenantAuthorityError("signed Workspace Binding failed canonical validation") from exc

    trusted_keys = {signer.kid: signer.public_key for signer in ordered_signers}
    try:
        verified = verifier(document, trusted_keys)
    except Exception as exc:
        raise TenantAuthorityError("workspace signer output failed cryptographic verification") from exc
    expected = tuple(signer.kid for signer in ordered_signers)
    if tuple(verified) != expected:
        raise TenantAuthorityError("workspace signature verification set does not match signers")
    return document
