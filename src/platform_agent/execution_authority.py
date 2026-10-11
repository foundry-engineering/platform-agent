from __future__ import annotations

import hashlib
import importlib
import json
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any, cast

from platform_agent.capability_router import CapabilityRegistry
from platform_agent.control_plane import DispatchPlan, TaskAssignment, build_dispatch_plan
from platform_agent.plan_admission import PlanAdmission

_EXECUTION_POLICY_ID = "https://foundry.engineering/schemas/policy/v1/execution_policy.json"
_EXECUTION_GRANT_ID = "https://foundry.engineering/schemas/execution/v1/execution_grant.json"
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_SHA256_REF_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
_VERIFIER_ID_RE = re.compile(r"^verifier_[a-z0-9._-]+$")
_EVALUATOR_ID_RE = re.compile(r"^evaluator_[a-z0-9._-]+$")

PolicyValidator = Callable[[object], None]
PolicyHasher = Callable[[object], str]
GrantValidator = Callable[[object], None]
GrantIdDeriver = Callable[[object], str]


class SandboxAdmissionError(ValueError):
    """Raised when routed work cannot be safely admitted to execution."""


@dataclass(frozen=True, slots=True)
class ResourceRequest:
    wall_time_seconds: int
    cpu_time_seconds: int
    memory_mb: int
    max_processes: int
    max_output_bytes: int

    def as_dict(self) -> dict[str, int]:
        return {
            "wall_time_seconds": self.wall_time_seconds,
            "cpu_time_seconds": self.cpu_time_seconds,
            "memory_mb": self.memory_mb,
            "max_processes": self.max_processes,
            "max_output_bytes": self.max_output_bytes,
        }


@dataclass(frozen=True, slots=True)
class ApprovalGrant:
    """Untrusted approval claim supplied with an execution request."""

    approval_id: str
    approver_ids: tuple[str, ...]
    evidence_refs: tuple[str, ...]

    def normalized(self) -> ApprovalGrant:
        return ApprovalGrant(
            approval_id=self.approval_id,
            approver_ids=tuple(sorted(self.approver_ids)),
            evidence_refs=tuple(sorted(self.evidence_refs)),
        )

    def as_dict(self) -> dict[str, object]:
        return {
            "approval_id": self.approval_id,
            "approver_ids": list(self.approver_ids),
            "evidence_refs": list(self.evidence_refs),
        }


@dataclass(frozen=True, slots=True)
class ConstraintGrant:
    """Untrusted constraint claim; it becomes evidence only after evaluator verification."""

    constraint: str
    evidence_ref: str | None = None

    def as_dict(self) -> dict[str, object]:
        return {"constraint": self.constraint, "evidence_ref": self.evidence_ref}


@dataclass(frozen=True, slots=True)
class ExecutionRequest:
    task_id: str
    repo: str | None
    read_paths: tuple[str, ...]
    write_paths: tuple[str, ...]
    allow_delete: bool
    max_file_bytes: int
    tool_ids: tuple[str, ...]
    network_hosts: tuple[str, ...]
    network_ports: tuple[int, ...]
    environment_keys: tuple[str, ...]
    resources: ResourceRequest
    approvals: tuple[ApprovalGrant, ...] = ()
    constraints: tuple[ConstraintGrant, ...] = ()

    def normalized(self) -> ExecutionRequest:
        return ExecutionRequest(
            task_id=self.task_id,
            repo=self.repo,
            read_paths=tuple(sorted(self.read_paths)),
            write_paths=tuple(sorted(self.write_paths)),
            allow_delete=self.allow_delete,
            max_file_bytes=self.max_file_bytes,
            tool_ids=tuple(sorted(self.tool_ids)),
            network_hosts=tuple(sorted(self.network_hosts)),
            network_ports=tuple(sorted(self.network_ports)),
            environment_keys=tuple(sorted(self.environment_keys)),
            resources=self.resources,
            approvals=tuple(
                item.normalized() for item in sorted(self.approvals, key=lambda item: item.approval_id)
            ),
            constraints=tuple(sorted(self.constraints, key=lambda item: item.constraint)),
        )

    def as_dict(self) -> dict[str, object]:
        return {
            "task_id": self.task_id,
            "repo": self.repo,
            "read_paths": list(self.read_paths),
            "write_paths": list(self.write_paths),
            "allow_delete": self.allow_delete,
            "max_file_bytes": self.max_file_bytes,
            "tool_ids": list(self.tool_ids),
            "network_hosts": list(self.network_hosts),
            "network_ports": list(self.network_ports),
            "environment_keys": list(self.environment_keys),
            "resources": self.resources.as_dict(),
            "approvals": [item.as_dict() for item in self.approvals],
            "constraints": [item.as_dict() for item in self.constraints],
        }


@dataclass(frozen=True, slots=True)
class ExecutionAuthority:
    dispatch_id: str
    plan_admission_id: str
    candidate_sha256: str
    registry_sha256: str

    def as_dict(self) -> dict[str, str]:
        return {
            "dispatch_id": self.dispatch_id,
            "plan_admission_id": self.plan_admission_id,
            "candidate_sha256": self.candidate_sha256,
            "registry_sha256": self.registry_sha256,
        }


@dataclass(frozen=True, slots=True)
class PolicyRefBinding:
    policy_id: str
    policy_sha256: str
    jurisdiction: str
    constraints: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "policy_id": self.policy_id,
            "policy_sha256": self.policy_sha256,
            "jurisdiction": self.jurisdiction,
            "constraints": list(self.constraints),
        }


@dataclass(frozen=True, slots=True)
class VerifiedApproval:
    approval_id: str
    verifier_id: str
    approver_ids: tuple[str, ...]
    evidence_refs: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "approval_id": self.approval_id,
            "verifier_id": self.verifier_id,
            "approver_ids": list(self.approver_ids),
            "evidence_refs": list(self.evidence_refs),
        }


@dataclass(frozen=True, slots=True)
class VerifiedConstraintEvidence:
    constraint: str
    evaluator_id: str
    evidence_ref: str

    def as_dict(self) -> dict[str, str]:
        return {
            "constraint": self.constraint,
            "evaluator_id": self.evaluator_id,
            "evidence_ref": self.evidence_ref,
        }


@dataclass(frozen=True, slots=True)
class VerificationContext:
    authority: ExecutionAuthority
    task_id: str
    agent_id: str
    policy_ref: PolicyRefBinding
    request_sha256: str
    repo: str | None
    read_paths: tuple[str, ...]
    write_paths: tuple[str, ...]
    allow_delete: bool
    tool_ids: tuple[str, ...]
    network_hosts: tuple[str, ...]
    network_ports: tuple[int, ...]
    environment_keys: tuple[str, ...]
    resources: ResourceRequest

    def evidence_material(self) -> dict[str, object]:
        return {
            "authority": self.authority.as_dict(),
            "task_id": self.task_id,
            "agent_id": self.agent_id,
            "policy_ref": self.policy_ref.as_dict(),
            "request_sha256": self.request_sha256,
            "repo": self.repo,
            "read_paths": list(self.read_paths),
            "write_paths": list(self.write_paths),
            "allow_delete": self.allow_delete,
            "tool_ids": list(self.tool_ids),
            "network_hosts": list(self.network_hosts),
            "network_ports": list(self.network_ports),
            "environment_keys": list(self.environment_keys),
            "resources": self.resources.as_dict(),
        }


ApprovalVerifyFn = Callable[[VerificationContext, ApprovalGrant, Mapping[str, Any]], None]
ConstraintEvaluateFn = Callable[[VerificationContext, ConstraintGrant], str]


@dataclass(frozen=True, slots=True)
class ApprovalVerifier:
    verifier_id: str
    verify: ApprovalVerifyFn

    def __post_init__(self) -> None:
        if _VERIFIER_ID_RE.fullmatch(self.verifier_id) is None:
            raise ValueError(f"invalid approval verifier id: {self.verifier_id!r}")


@dataclass(frozen=True, slots=True)
class ConstraintEvaluator:
    evaluator_id: str
    evaluate: ConstraintEvaluateFn

    def __post_init__(self) -> None:
        if _EVALUATOR_ID_RE.fullmatch(self.evaluator_id) is None:
            raise ValueError(f"invalid constraint evaluator id: {self.evaluator_id!r}")


@dataclass(frozen=True, slots=True)
class ExecutionGrant:
    schema_version: str
    grant_id: str
    authority: ExecutionAuthority
    task_id: str
    agent_id: str
    policy_ref: PolicyRefBinding
    request_sha256: str
    repo: str | None
    read_paths: tuple[str, ...]
    write_paths: tuple[str, ...]
    allow_delete: bool
    max_file_bytes: int
    tool_ids: tuple[str, ...]
    network_hosts: tuple[str, ...]
    network_ports: tuple[int, ...]
    environment_keys: tuple[str, ...]
    resources: ResourceRequest
    approvals: tuple[VerifiedApproval, ...]
    constraint_evidence: tuple[VerifiedConstraintEvidence, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "grant_id": self.grant_id,
            "authority": self.authority.as_dict(),
            "task_id": self.task_id,
            "agent_id": self.agent_id,
            "policy_ref": self.policy_ref.as_dict(),
            "request_sha256": self.request_sha256,
            "repo": self.repo,
            "read_paths": list(self.read_paths),
            "write_paths": list(self.write_paths),
            "allow_delete": self.allow_delete,
            "max_file_bytes": self.max_file_bytes,
            "tool_ids": list(self.tool_ids),
            "network_hosts": list(self.network_hosts),
            "network_ports": list(self.network_ports),
            "environment_keys": list(self.environment_keys),
            "resources": self.resources.as_dict(),
            "approvals": [item.as_dict() for item in self.approvals],
            "constraint_evidence": [item.as_dict() for item in self.constraint_evidence],
        }


@dataclass(frozen=True, slots=True)
class SandboxAdmission:
    schema_version: str
    sandbox_admission_id: str
    dispatch_id: str
    plan_admission_id: str
    candidate_sha256: str
    registry_sha256: str
    grants: tuple[ExecutionGrant, ...]
    dispatch: DispatchPlan

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "sandbox_admission_id": self.sandbox_admission_id,
            "dispatch_id": self.dispatch_id,
            "plan_admission_id": self.plan_admission_id,
            "candidate_sha256": self.candidate_sha256,
            "registry_sha256": self.registry_sha256,
            "grants": [item.as_dict() for item in self.grants],
            "dispatch": self.dispatch.as_dict(),
        }


def _canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _evidence_ref(value: object) -> str:
    return "sha256:" + _sha256(value)


def _require_mapping(value: object, *, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise SandboxAdmissionError(f"{field} must be an object")
    return cast(Mapping[str, Any], value)


def _require_string(value: object, *, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise SandboxAdmissionError(f"{field} must be a non-empty string")
    return value


def _require_sequence(value: object, *, field: str) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise SandboxAdmissionError(f"{field} must be an array")
    return cast(Sequence[object], value)


def _normalize_path(value: str, *, field: str) -> PurePosixPath:
    if not value or "\\" in value or value.startswith("/") or value.endswith("/"):
        raise SandboxAdmissionError(f"{field} must be a canonical relative POSIX path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".."} for part in path.parts):
        raise SandboxAdmissionError(f"{field} contains path traversal")
    if path.as_posix() != value:
        raise SandboxAdmissionError(f"{field} must be canonical POSIX form")
    if path != PurePosixPath(".") and path.parts and path.parts[0] == ".eng":
        raise SandboxAdmissionError(f"{field} cannot target Foundry runtime metadata")
    return path


def _path_covered(path: PurePosixPath, roots: tuple[PurePosixPath, ...]) -> bool:
    return any(
        root == PurePosixPath(".") or path == root or path.is_relative_to(root)
        for root in roots
    )


def _unique_paths(values: tuple[str, ...], *, field: str) -> tuple[PurePosixPath, ...]:
    if len(values) != len(set(values)):
        raise SandboxAdmissionError(f"{field} contains duplicate paths")
    return tuple(_normalize_path(value, field=field) for value in values)


def _validate_request_shape(request: ExecutionRequest) -> None:
    if not request.task_id:
        raise SandboxAdmissionError("execution request task_id must not be empty")
    if request.max_file_bytes <= 0:
        raise SandboxAdmissionError("execution request max_file_bytes must be positive")
    reads = _unique_paths(request.read_paths, field=f"{request.task_id}.read_paths")
    writes = _unique_paths(request.write_paths, field=f"{request.task_id}.write_paths")
    for write_path in writes:
        if not _path_covered(write_path, reads):
            raise SandboxAdmissionError(
                f"task {request.task_id} write path is not covered by requested read scope"
            )
    for values, field in (
        (request.tool_ids, "tool_ids"),
        (request.network_hosts, "network_hosts"),
        (request.environment_keys, "environment_keys"),
    ):
        if len(values) != len(set(values)) or any(not value for value in values):
            raise SandboxAdmissionError(
                f"{request.task_id}.{field} must be unique non-empty strings"
            )
    if len(request.network_ports) != len(set(request.network_ports)):
        raise SandboxAdmissionError(f"{request.task_id}.network_ports contains duplicates")
    if any(port < 1 or port > 65535 for port in request.network_ports):
        raise SandboxAdmissionError(f"{request.task_id}.network_ports contains invalid port")
    if bool(request.network_hosts) != bool(request.network_ports):
        raise SandboxAdmissionError(
            f"{request.task_id} network request must provide both hosts and ports"
        )
    if any(value <= 0 for value in request.resources.as_dict().values()):
        raise SandboxAdmissionError(f"{request.task_id} resource requests must be positive")

    approval_ids = [item.approval_id for item in request.approvals]
    if len(approval_ids) != len(set(approval_ids)):
        raise SandboxAdmissionError(f"{request.task_id} contains duplicate approval claims")
    for approval in request.approvals:
        if not approval.approval_id or not approval.approver_ids:
            raise SandboxAdmissionError(f"{request.task_id} approval claim is incomplete")
        if len(approval.approver_ids) != len(set(approval.approver_ids)):
            raise SandboxAdmissionError(f"{request.task_id} approval approvers must be unique")
        if len(approval.evidence_refs) != len(set(approval.evidence_refs)):
            raise SandboxAdmissionError(f"{request.task_id} approval evidence refs must be unique")
        if any(_SHA256_REF_RE.fullmatch(ref) is None for ref in approval.evidence_refs):
            raise SandboxAdmissionError(f"{request.task_id} approval evidence ref is invalid")

    constraint_names = [item.constraint for item in request.constraints]
    if len(constraint_names) != len(set(constraint_names)):
        raise SandboxAdmissionError(f"{request.task_id} contains duplicate constraint claims")
    for claim in request.constraints:
        if not claim.constraint:
            raise SandboxAdmissionError(f"{request.task_id} constraint claim is invalid")
        if claim.evidence_ref is not None and _SHA256_REF_RE.fullmatch(claim.evidence_ref) is None:
            raise SandboxAdmissionError(f"{request.task_id} constraint evidence ref is invalid")


def _protocol_runtimes() -> tuple[PolicyValidator, PolicyHasher, GrantValidator, GrantIdDeriver]:
    try:
        policy_module = importlib.import_module("agent_protocol.execution_policy")
        grant_module = importlib.import_module("agent_protocol.execution_grant")
    except ModuleNotFoundError as exc:
        raise SandboxAdmissionError(
            "canonical agent-protocol execution contracts are unavailable"
        ) from exc
    policy_validator = getattr(policy_module, "validate_execution_policy", None)
    policy_hasher = getattr(policy_module, "execution_policy_sha256", None)
    grant_validator = getattr(grant_module, "validate_execution_grant", None)
    grant_deriver = getattr(grant_module, "derive_execution_grant_id", None)
    if (
        getattr(policy_module, "EXECUTION_POLICY_ID", None) != _EXECUTION_POLICY_ID
        or getattr(grant_module, "EXECUTION_GRANT_ID", None) != _EXECUTION_GRANT_ID
        or not callable(policy_validator)
        or not callable(policy_hasher)
        or not callable(grant_validator)
        or not callable(grant_deriver)
    ):
        raise SandboxAdmissionError(
            "installed agent-protocol does not provide required execution contracts"
        )
    return (
        cast(PolicyValidator, policy_validator),
        cast(PolicyHasher, policy_hasher),
        cast(GrantValidator, grant_validator),
        cast(GrantIdDeriver, grant_deriver),
    )


def _task_map(plan: object) -> tuple[Mapping[str, Any], dict[str, Mapping[str, Any]]]:
    plan_map = _require_mapping(plan, field="plan")
    tasks: dict[str, Mapping[str, Any]] = {}
    for raw in _require_sequence(plan_map.get("tasks"), field="plan.tasks"):
        task = _require_mapping(raw, field="plan.tasks[]")
        task_id = _require_string(task.get("task_id"), field="task.task_id")
        if task_id in tasks:
            raise SandboxAdmissionError(f"duplicate task_id: {task_id}")
        tasks[task_id] = task
    return plan_map, tasks


def _policy_for_assignment(
    *,
    plan: Mapping[str, Any],
    task: Mapping[str, Any],
    assignment: TaskAssignment,
    policies: Mapping[str, object],
    validator: PolicyValidator,
    hasher: PolicyHasher,
) -> tuple[PolicyRefBinding, Mapping[str, Any]]:
    raw_ref = task.get("policy_ref", plan.get("policy_ref"))
    ref = _require_mapping(raw_ref, field=f"{assignment.task_id}.policy_ref")
    policy_id = _require_string(ref.get("policy_id"), field=f"{assignment.task_id}.policy_id")
    policy_sha256 = _require_string(
        ref.get("policy_sha256"), field=f"{assignment.task_id}.policy_sha256"
    )
    jurisdiction = _require_string(
        ref.get("jurisdiction"), field=f"{assignment.task_id}.jurisdiction"
    )
    if _SHA256_RE.fullmatch(policy_sha256) is None:
        raise SandboxAdmissionError(f"task {assignment.task_id} policy_sha256 is invalid")
    raw_constraints = ref.get("constraints", [])
    constraints = tuple(
        sorted(
            _require_string(value, field=f"{assignment.task_id}.constraints[]")
            for value in _require_sequence(raw_constraints, field=f"{assignment.task_id}.constraints")
        )
    )
    if len(constraints) != len(set(constraints)):
        raise SandboxAdmissionError(f"task {assignment.task_id} contains duplicate constraints")
    if policy_id not in policies:
        raise SandboxAdmissionError(
            f"task {assignment.task_id} execution policy is unavailable: {policy_id}"
        )
    policy = _require_mapping(policies[policy_id], field=f"policy[{policy_id}]")
    try:
        validator(policy)
        actual_hash = hasher(policy)
    except Exception as exc:
        raise SandboxAdmissionError(
            f"task {assignment.task_id} execution policy validation failed"
        ) from exc
    if actual_hash != policy_sha256:
        raise SandboxAdmissionError(
            f"task {assignment.task_id} execution policy hash does not match policy_ref"
        )
    if policy.get("policy_id") != policy_id:
        raise SandboxAdmissionError(
            f"task {assignment.task_id} execution policy_id does not match policy_ref"
        )
    return (
        PolicyRefBinding(
            policy_id=policy_id,
            policy_sha256=policy_sha256,
            jurisdiction=jurisdiction,
            constraints=constraints,
        ),
        policy,
    )


def _target_scope(task: Mapping[str, Any], request: ExecutionRequest) -> tuple[PurePosixPath, ...]:
    filesystem_activity = bool(
        request.repo is not None or request.read_paths or request.write_paths or request.allow_delete
    )
    raw_target = task.get("target")
    if raw_target is None:
        if filesystem_activity:
            raise SandboxAdmissionError(
                f"task {request.task_id} has no canonical target; filesystem execution is denied"
            )
        return ()
    target = _require_mapping(raw_target, field=f"{request.task_id}.target")
    target_repo = _require_string(target.get("repo"), field=f"{request.task_id}.target.repo")
    if request.repo != target_repo:
        raise SandboxAdmissionError(f"task {request.task_id} execution repo does not match target")
    raw_scope = target.get("path_scope")
    if raw_scope is None:
        if filesystem_activity:
            raise SandboxAdmissionError(
                f"task {request.task_id} target has no path_scope; filesystem execution is denied"
            )
        return ()
    roots = tuple(
        _normalize_path(
            _require_string(value, field=f"{request.task_id}.target.path_scope[]"),
            field=f"{request.task_id}.target.path_scope",
        )
        for value in _require_sequence(raw_scope, field=f"{request.task_id}.target.path_scope")
    )
    if len(roots) != len(set(roots)):
        raise SandboxAdmissionError(f"task {request.task_id} target path_scope contains duplicates")
    if not roots and filesystem_activity:
        raise SandboxAdmissionError(
            f"task {request.task_id} target path_scope is empty; filesystem execution is denied"
        )
    return roots


def _policy_roots(
    policy: Mapping[str, Any], *, key: str, task_id: str
) -> tuple[PurePosixPath, ...]:
    sandbox = _require_mapping(policy.get("sandbox"), field=f"{task_id}.policy.sandbox")
    filesystem = _require_mapping(
        sandbox.get("filesystem"), field=f"{task_id}.policy.sandbox.filesystem"
    )
    roots = tuple(
        _normalize_path(
            _require_string(value, field=f"{task_id}.policy.{key}[]"),
            field=f"{task_id}.policy.{key}",
        )
        for value in _require_sequence(filesystem.get(key), field=f"{task_id}.policy.{key}")
    )
    if len(roots) != len(set(roots)):
        raise SandboxAdmissionError(f"task {task_id} policy {key} contains duplicates")
    return roots


def _verify_approvals(
    *,
    context: VerificationContext,
    claims: tuple[ApprovalGrant, ...],
    requirements: Mapping[str, Mapping[str, Any]],
    verifiers: Mapping[str, ApprovalVerifier],
) -> tuple[VerifiedApproval, ...]:
    claims_by_id = {item.approval_id: item for item in claims}
    if set(claims_by_id) != set(requirements):
        raise SandboxAdmissionError(
            f"task {context.task_id} approval claims do not exactly match policy requirements"
        )
    verified: list[VerifiedApproval] = []
    for approval_id in sorted(requirements):
        if approval_id not in verifiers:
            raise SandboxAdmissionError(
                f"task {context.task_id} approval verifier is unavailable: {approval_id}"
            )
        verifier = verifiers[approval_id]
        claim = claims_by_id[approval_id].normalized()
        requirement = requirements[approval_id]
        min_count = requirement.get("min_count")
        if not isinstance(min_count, int) or isinstance(min_count, bool):
            raise SandboxAdmissionError("policy approval min_count is invalid")
        if len(claim.approver_ids) < min_count:
            raise SandboxAdmissionError(f"task {context.task_id} approval count is insufficient")
        if requirement.get("evidence_required") is True and not claim.evidence_refs:
            raise SandboxAdmissionError(f"task {context.task_id} approval evidence is required")
        try:
            verifier.verify(context, claim, requirement)
        except Exception as exc:
            raise SandboxAdmissionError(
                f"task {context.task_id} approval verification failed: {approval_id}"
            ) from exc
        verified.append(
            VerifiedApproval(
                approval_id=approval_id,
                verifier_id=verifier.verifier_id,
                approver_ids=claim.approver_ids,
                evidence_refs=claim.evidence_refs,
            )
        )
    return tuple(verified)


def _evaluate_constraints(
    *,
    context: VerificationContext,
    claims: tuple[ConstraintGrant, ...],
    required: tuple[str, ...],
    evaluators: Mapping[str, ConstraintEvaluator],
) -> tuple[VerifiedConstraintEvidence, ...]:
    claims_by_name = {item.constraint: item for item in claims}
    if set(claims_by_name) != set(required):
        raise SandboxAdmissionError(
            f"task {context.task_id} constraint claims do not exactly match policy_ref"
        )
    evidence: list[VerifiedConstraintEvidence] = []
    for constraint in required:
        if constraint not in evaluators:
            raise SandboxAdmissionError(
                f"task {context.task_id} constraint evaluator is unavailable: {constraint}"
            )
        evaluator = evaluators[constraint]
        try:
            evidence_ref = evaluator.evaluate(context, claims_by_name[constraint])
        except Exception as exc:
            raise SandboxAdmissionError(
                f"task {context.task_id} constraint evaluation failed: {constraint}"
            ) from exc
        if _SHA256_REF_RE.fullmatch(evidence_ref) is None:
            raise SandboxAdmissionError(
                f"task {context.task_id} constraint evaluator returned invalid evidence"
            )
        evidence.append(
            VerifiedConstraintEvidence(
                constraint=constraint,
                evaluator_id=evaluator.evaluator_id,
                evidence_ref=evidence_ref,
            )
        )
    return tuple(evidence)


def builtin_constraint_evaluators() -> dict[str, ConstraintEvaluator]:
    """Deterministic evaluators for constraints proven by admission itself."""

    def scoped_write(context: VerificationContext, claim: ConstraintGrant) -> str:
        if not context.write_paths:
            raise ValueError("fs.write:scoped requires at least one admitted write path")
        return _evidence_ref(
            {
                "evaluator_id": "evaluator_foundry.fs-write-scoped.v1",
                "constraint": claim.constraint,
                "context": context.evidence_material(),
            }
        )

    def network_denied(context: VerificationContext, claim: ConstraintGrant) -> str:
        if context.network_hosts or context.network_ports:
            raise ValueError("network:deny cannot be proven for a network-enabled request")
        return _evidence_ref(
            {
                "evaluator_id": "evaluator_foundry.network-deny.v1",
                "constraint": claim.constraint,
                "context": context.evidence_material(),
            }
        )

    return {
        "fs.write:scoped": ConstraintEvaluator(
            evaluator_id="evaluator_foundry.fs-write-scoped.v1",
            evaluate=scoped_write,
        ),
        "network:deny": ConstraintEvaluator(
            evaluator_id="evaluator_foundry.network-deny.v1",
            evaluate=network_denied,
        ),
    }


def _admit_request(
    *,
    dispatch: DispatchPlan,
    plan_admission: PlanAdmission,
    registry: CapabilityRegistry,
    assignment: TaskAssignment,
    task: Mapping[str, Any],
    plan: Mapping[str, Any],
    request: ExecutionRequest,
    policies: Mapping[str, object],
    approval_verifiers: Mapping[str, ApprovalVerifier],
    constraint_evaluators: Mapping[str, ConstraintEvaluator],
    policy_validator: PolicyValidator,
    policy_hasher: PolicyHasher,
    grant_validator: GrantValidator,
    grant_deriver: GrantIdDeriver,
) -> ExecutionGrant:
    _validate_request_shape(request)
    normalized_request = request.normalized()
    if normalized_request.task_id != assignment.task_id:
        raise SandboxAdmissionError("execution request task_id does not match assignment")

    policy_ref, policy = _policy_for_assignment(
        plan=plan,
        task=task,
        assignment=assignment,
        policies=policies,
        validator=policy_validator,
        hasher=policy_hasher,
    )
    target_roots = _target_scope(task, normalized_request)
    requested_reads = _unique_paths(
        normalized_request.read_paths, field=f"{normalized_request.task_id}.read_paths"
    )
    requested_writes = _unique_paths(
        normalized_request.write_paths, field=f"{normalized_request.task_id}.write_paths"
    )
    policy_read_roots = _policy_roots(policy, key="read_roots", task_id=normalized_request.task_id)
    policy_write_roots = _policy_roots(
        policy, key="write_roots", task_id=normalized_request.task_id
    )
    for path in requested_reads:
        if not _path_covered(path, policy_read_roots):
            raise SandboxAdmissionError(
                f"task {normalized_request.task_id} read path exceeds policy scope"
            )
        if not _path_covered(path, target_roots):
            raise SandboxAdmissionError(
                f"task {normalized_request.task_id} read path exceeds task target scope"
            )
    for path in requested_writes:
        if not _path_covered(path, policy_write_roots):
            raise SandboxAdmissionError(
                f"task {normalized_request.task_id} write path exceeds policy scope"
            )
        if not _path_covered(path, target_roots):
            raise SandboxAdmissionError(
                f"task {normalized_request.task_id} write path exceeds task target scope"
            )

    policy_sandbox = _require_mapping(
        policy.get("sandbox"), field=f"{normalized_request.task_id}.policy.sandbox"
    )
    filesystem = _require_mapping(
        policy_sandbox.get("filesystem"), field=f"{normalized_request.task_id}.policy.filesystem"
    )
    max_file_bytes = filesystem.get("max_file_bytes")
    if not isinstance(max_file_bytes, int) or isinstance(max_file_bytes, bool):
        raise SandboxAdmissionError("policy max_file_bytes is invalid")
    if normalized_request.max_file_bytes > max_file_bytes:
        raise SandboxAdmissionError(
            f"task {normalized_request.task_id} max_file_bytes exceeds policy"
        )
    if normalized_request.allow_delete and filesystem.get("allow_delete") is not True:
        raise SandboxAdmissionError(f"task {normalized_request.task_id} delete is denied by policy")

    tools = _require_mapping(
        policy_sandbox.get("tools"), field=f"{normalized_request.task_id}.policy.tools"
    )
    allowed_tools = {
        _require_string(item, field=f"{normalized_request.task_id}.policy.allowed_tool_ids[]")
        for item in _require_sequence(
            tools.get("allowed_tool_ids"),
            field=f"{normalized_request.task_id}.policy.allowed_tool_ids",
        )
    }
    denied_tools = sorted(set(normalized_request.tool_ids) - allowed_tools)
    if denied_tools:
        raise SandboxAdmissionError(
            f"task {normalized_request.task_id} requests tools denied by policy: "
            + ", ".join(denied_tools)
        )

    network = _require_mapping(
        policy_sandbox.get("network"), field=f"{normalized_request.task_id}.policy.network"
    )
    mode = _require_string(
        network.get("mode"), field=f"{normalized_request.task_id}.policy.network.mode"
    )
    allowed_hosts = {
        _require_string(item, field=f"{normalized_request.task_id}.policy.allowed_hosts[]")
        for item in _require_sequence(
            network.get("allowed_hosts"),
            field=f"{normalized_request.task_id}.policy.allowed_hosts",
        )
    }
    raw_ports = _require_sequence(
        network.get("allowed_ports"), field=f"{normalized_request.task_id}.policy.allowed_ports"
    )
    allowed_ports = {
        item for item in raw_ports if isinstance(item, int) and not isinstance(item, bool)
    }
    if len(allowed_ports) != len(raw_ports):
        raise SandboxAdmissionError("policy allowed_ports contains invalid value")
    if mode == "deny" and (normalized_request.network_hosts or normalized_request.network_ports):
        raise SandboxAdmissionError(
            f"task {normalized_request.task_id} network access is denied by policy"
        )
    if mode == "allowlist" and (
        set(normalized_request.network_hosts) - allowed_hosts
        or set(normalized_request.network_ports) - allowed_ports
    ):
        raise SandboxAdmissionError(
            f"task {normalized_request.task_id} network request exceeds allowlist"
        )

    environment = _require_mapping(
        policy_sandbox.get("environment"),
        field=f"{normalized_request.task_id}.policy.environment",
    )
    allowed_keys = {
        _require_string(item, field=f"{normalized_request.task_id}.policy.allowed_keys[]")
        for item in _require_sequence(
            environment.get("allowed_keys"),
            field=f"{normalized_request.task_id}.policy.allowed_keys",
        )
    }
    denied_keys = {
        _require_string(item, field=f"{normalized_request.task_id}.policy.denied_keys[]")
        for item in _require_sequence(
            environment.get("denied_keys"),
            field=f"{normalized_request.task_id}.policy.denied_keys",
        )
    }
    requested_env = set(normalized_request.environment_keys)
    if requested_env & denied_keys or requested_env - allowed_keys:
        raise SandboxAdmissionError(
            f"task {normalized_request.task_id} environment request is denied by policy"
        )

    resources = _require_mapping(
        policy_sandbox.get("resources"), field=f"{normalized_request.task_id}.policy.resources"
    )
    for key, requested in normalized_request.resources.as_dict().items():
        allowed = resources.get(key)
        if not isinstance(allowed, int) or isinstance(allowed, bool) or requested > allowed:
            raise SandboxAdmissionError(
                f"task {normalized_request.task_id} resource request exceeds policy: {key}"
            )

    required_approvals: dict[str, Mapping[str, Any]] = {}
    for raw in _require_sequence(
        policy.get("approvals"), field=f"{normalized_request.task_id}.approvals"
    ):
        approval = _require_mapping(raw, field=f"{normalized_request.task_id}.approvals[]")
        approval_id = _require_string(
            approval.get("approval_id"), field=f"{normalized_request.task_id}.approval_id"
        )
        if approval_id in required_approvals:
            raise SandboxAdmissionError("policy contains duplicate approval_id")
        required_approvals[approval_id] = approval

    authority = ExecutionAuthority(
        dispatch_id=dispatch.dispatch_id,
        plan_admission_id=plan_admission.admission_id,
        candidate_sha256=plan_admission.candidate_sha256,
        registry_sha256=registry.registry_sha256,
    )
    request_sha256 = _sha256(normalized_request.as_dict())
    context = VerificationContext(
        authority=authority,
        task_id=assignment.task_id,
        agent_id=assignment.agent_id,
        policy_ref=policy_ref,
        request_sha256=request_sha256,
        repo=normalized_request.repo,
        read_paths=normalized_request.read_paths,
        write_paths=normalized_request.write_paths,
        allow_delete=normalized_request.allow_delete,
        tool_ids=normalized_request.tool_ids,
        network_hosts=normalized_request.network_hosts,
        network_ports=normalized_request.network_ports,
        environment_keys=normalized_request.environment_keys,
        resources=normalized_request.resources,
    )
    verified_approvals = _verify_approvals(
        context=context,
        claims=normalized_request.approvals,
        requirements=required_approvals,
        verifiers=approval_verifiers,
    )
    verified_constraints = _evaluate_constraints(
        context=context,
        claims=normalized_request.constraints,
        required=policy_ref.constraints,
        evaluators=constraint_evaluators,
    )

    provisional = ExecutionGrant(
        schema_version="execution-grant.v1",
        grant_id="sgr_" + "0" * 32,
        authority=authority,
        task_id=assignment.task_id,
        agent_id=assignment.agent_id,
        policy_ref=policy_ref,
        request_sha256=request_sha256,
        repo=normalized_request.repo,
        read_paths=normalized_request.read_paths,
        write_paths=normalized_request.write_paths,
        allow_delete=normalized_request.allow_delete,
        max_file_bytes=normalized_request.max_file_bytes,
        tool_ids=normalized_request.tool_ids,
        network_hosts=normalized_request.network_hosts,
        network_ports=normalized_request.network_ports,
        environment_keys=normalized_request.environment_keys,
        resources=normalized_request.resources,
        approvals=verified_approvals,
        constraint_evidence=verified_constraints,
    )
    grant_id = grant_deriver(provisional.as_dict())
    grant = ExecutionGrant(
        schema_version=provisional.schema_version,
        grant_id=grant_id,
        authority=provisional.authority,
        task_id=provisional.task_id,
        agent_id=provisional.agent_id,
        policy_ref=provisional.policy_ref,
        request_sha256=provisional.request_sha256,
        repo=provisional.repo,
        read_paths=provisional.read_paths,
        write_paths=provisional.write_paths,
        allow_delete=provisional.allow_delete,
        max_file_bytes=provisional.max_file_bytes,
        tool_ids=provisional.tool_ids,
        network_hosts=provisional.network_hosts,
        network_ports=provisional.network_ports,
        environment_keys=provisional.environment_keys,
        resources=provisional.resources,
        approvals=provisional.approvals,
        constraint_evidence=provisional.constraint_evidence,
    )
    try:
        grant_validator(grant.as_dict())
    except Exception as exc:
        raise SandboxAdmissionError(
            f"task {normalized_request.task_id} canonical Execution Grant validation failed"
        ) from exc
    return grant


def admit_dispatch_to_sandbox(
    plan: object,
    *,
    admission: PlanAdmission,
    registry: CapabilityRegistry,
    requests: Sequence[ExecutionRequest],
    policies: Mapping[str, object],
    approval_verifiers: Mapping[str, ApprovalVerifier] | None = None,
    constraint_evaluators: Mapping[str, ConstraintEvaluator] | None = None,
    completed: frozenset[str] = frozenset(),
    failed: frozenset[str] = frozenset(),
    satisfied_preconditions: frozenset[str] = frozenset(),
) -> SandboxAdmission:
    """Build dispatch and canonical execution authority atomically for all ready tasks."""
    dispatch = build_dispatch_plan(
        plan,
        admission=admission,
        registry=registry,
        completed=completed,
        failed=failed,
        satisfied_preconditions=satisfied_preconditions,
    )
    plan_map, tasks = _task_map(plan)
    policy_validator, policy_hasher, grant_validator, grant_deriver = _protocol_runtimes()
    verifier_map = dict(approval_verifiers or {})
    evaluator_map = builtin_constraint_evaluators()
    evaluator_map.update(constraint_evaluators or {})

    by_task: dict[str, ExecutionRequest] = {}
    for request in requests:
        if request.task_id in by_task:
            raise SandboxAdmissionError(f"duplicate execution request: {request.task_id}")
        by_task[request.task_id] = request
    assignment_ids = {assignment.task_id for assignment in dispatch.assignments}
    if set(by_task) != assignment_ids:
        missing = sorted(assignment_ids - set(by_task))
        extra = sorted(set(by_task) - assignment_ids)
        details: list[str] = []
        if missing:
            details.append("missing=" + ",".join(missing))
        if extra:
            details.append("extra=" + ",".join(extra))
        raise SandboxAdmissionError(
            "execution requests must exactly match ready assignments: " + "; ".join(details)
        )

    grants = tuple(
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
            grant_validator=grant_validator,
            grant_deriver=grant_deriver,
        )
        for assignment in dispatch.assignments
    )
    material = {
        "schema_version": "foundry.sandbox-admission.v1",
        "dispatch_id": dispatch.dispatch_id,
        "plan_admission_id": admission.admission_id,
        "candidate_sha256": admission.candidate_sha256,
        "registry_sha256": registry.registry_sha256,
        "grant_ids": [grant.grant_id for grant in grants],
    }
    return SandboxAdmission(
        schema_version="foundry.sandbox-admission.v1",
        sandbox_admission_id="sad_" + _sha256(material)[:32],
        dispatch_id=dispatch.dispatch_id,
        plan_admission_id=admission.admission_id,
        candidate_sha256=admission.candidate_sha256,
        registry_sha256=registry.registry_sha256,
        grants=grants,
        dispatch=dispatch,
    )


def verify_sandbox_admission(
    current: SandboxAdmission,
    plan: object,
    *,
    admission: PlanAdmission,
    registry: CapabilityRegistry,
    requests: Sequence[ExecutionRequest],
    policies: Mapping[str, object],
    approval_verifiers: Mapping[str, ApprovalVerifier] | None = None,
    constraint_evaluators: Mapping[str, ConstraintEvaluator] | None = None,
    completed: frozenset[str] = frozenset(),
    failed: frozenset[str] = frozenset(),
    satisfied_preconditions: frozenset[str] = frozenset(),
) -> None:
    """Recompute the complete authority decision and reject stale or tampered grants."""
    expected = admit_dispatch_to_sandbox(
        plan,
        admission=admission,
        registry=registry,
        requests=requests,
        policies=policies,
        approval_verifiers=approval_verifiers,
        constraint_evaluators=constraint_evaluators,
        completed=completed,
        failed=failed,
        satisfied_preconditions=satisfied_preconditions,
    )
    if current.as_dict() != expected.as_dict():
        raise SandboxAdmissionError("sandbox admission does not match recomputed authority")
