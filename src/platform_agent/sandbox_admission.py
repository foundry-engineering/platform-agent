from __future__ import annotations

import hashlib
import importlib
import json
import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any, Mapping, Sequence, cast

from platform_agent.capability_router import CapabilityRegistry
from platform_agent.control_plane import DispatchPlan, TaskAssignment, build_dispatch_plan
from platform_agent.plan_admission import PlanAdmission

_EXECUTION_POLICY_ID = "https://foundry.engineering/schemas/policy/v1/execution_policy.json"
_SHA256_REF_RE = re.compile(r"^sha256:[a-f0-9]{64}$")


class SandboxAdmissionError(ValueError):
    """Raised when routed work cannot be safely admitted to an execution sandbox."""


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
    approval_id: str
    approver_ids: tuple[str, ...]
    evidence_refs: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "approval_id": self.approval_id,
            "approver_ids": list(self.approver_ids),
            "evidence_refs": list(self.evidence_refs),
        }


@dataclass(frozen=True, slots=True)
class ConstraintGrant:
    constraint: str
    evidence_ref: str

    def as_dict(self) -> dict[str, str]:
        return {
            "constraint": self.constraint,
            "evidence_ref": self.evidence_ref,
        }


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
class SandboxGrant:
    schema_version: str
    grant_id: str
    dispatch_id: str
    task_id: str
    agent_id: str
    policy_id: str
    policy_sha256: str
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
    approval_evidence_refs: tuple[str, ...]
    constraint_evidence_refs: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "grant_id": self.grant_id,
            "dispatch_id": self.dispatch_id,
            "task_id": self.task_id,
            "agent_id": self.agent_id,
            "policy_id": self.policy_id,
            "policy_sha256": self.policy_sha256,
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
            "approval_evidence_refs": list(self.approval_evidence_refs),
            "constraint_evidence_refs": list(self.constraint_evidence_refs),
        }


@dataclass(frozen=True, slots=True)
class SandboxAdmission:
    schema_version: str
    sandbox_admission_id: str
    dispatch_id: str
    plan_admission_id: str
    candidate_sha256: str
    registry_sha256: str
    grants: tuple[SandboxGrant, ...]
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
    return any(root == PurePosixPath(".") or path == root or path.is_relative_to(root) for root in roots)


def _normalized_unique_paths(values: tuple[str, ...], *, field: str) -> tuple[PurePosixPath, ...]:
    if len(values) != len(set(values)):
        raise SandboxAdmissionError(f"{field} contains duplicate paths")
    return tuple(_normalize_path(value, field=field) for value in values)


def _validate_request_shape(request: ExecutionRequest) -> None:
    if not request.task_id:
        raise SandboxAdmissionError("execution request task_id must not be empty")
    if request.max_file_bytes <= 0:
        raise SandboxAdmissionError("execution request max_file_bytes must be positive")
    _normalized_unique_paths(request.read_paths, field=f"{request.task_id}.read_paths")
    _normalized_unique_paths(request.write_paths, field=f"{request.task_id}.write_paths")

    for values, field in (
        (request.tool_ids, "tool_ids"),
        (request.network_hosts, "network_hosts"),
        (request.environment_keys, "environment_keys"),
    ):
        if len(values) != len(set(values)) or any(not value for value in values):
            raise SandboxAdmissionError(f"{request.task_id}.{field} must be unique non-empty strings")

    if len(request.network_ports) != len(set(request.network_ports)):
        raise SandboxAdmissionError(f"{request.task_id}.network_ports contains duplicates")
    if any(port < 1 or port > 65535 for port in request.network_ports):
        raise SandboxAdmissionError(f"{request.task_id}.network_ports contains invalid port")
    if bool(request.network_hosts) != bool(request.network_ports):
        raise SandboxAdmissionError(
            f"{request.task_id} network request must provide both hosts and ports"
        )

    resources = request.resources
    if any(
        value <= 0
        for value in (
            resources.wall_time_seconds,
            resources.cpu_time_seconds,
            resources.memory_mb,
            resources.max_processes,
            resources.max_output_bytes,
        )
    ):
        raise SandboxAdmissionError(f"{request.task_id} resource requests must be positive")

    approval_ids = [item.approval_id for item in request.approvals]
    if len(approval_ids) != len(set(approval_ids)):
        raise SandboxAdmissionError(f"{request.task_id} contains duplicate approval grants")
    for approval in request.approvals:
        if not approval.approval_id or not approval.approver_ids:
            raise SandboxAdmissionError(f"{request.task_id} approval grant is incomplete")
        if len(approval.approver_ids) != len(set(approval.approver_ids)):
            raise SandboxAdmissionError(f"{request.task_id} approval approvers must be unique")
        if len(approval.evidence_refs) != len(set(approval.evidence_refs)):
            raise SandboxAdmissionError(f"{request.task_id} approval evidence refs must be unique")
        if any(_SHA256_REF_RE.fullmatch(ref) is None for ref in approval.evidence_refs):
            raise SandboxAdmissionError(f"{request.task_id} approval evidence ref is invalid")

    constraints = [item.constraint for item in request.constraints]
    if len(constraints) != len(set(constraints)):
        raise SandboxAdmissionError(f"{request.task_id} contains duplicate constraint grants")
    for constraint in request.constraints:
        if not constraint.constraint or _SHA256_REF_RE.fullmatch(constraint.evidence_ref) is None:
            raise SandboxAdmissionError(f"{request.task_id} constraint grant is invalid")


def _policy_runtime() -> tuple[object, object]:
    try:
        module = importlib.import_module("agent_protocol.execution_policy")
    except ModuleNotFoundError as exc:
        raise SandboxAdmissionError(
            "canonical agent-protocol Execution Policy validator is unavailable"
        ) from exc

    schema_id = getattr(module, "EXECUTION_POLICY_ID", None)
    validator = getattr(module, "validate_execution_policy", None)
    hasher = getattr(module, "execution_policy_sha256", None)
    if schema_id != _EXECUTION_POLICY_ID or not callable(validator) or not callable(hasher):
        raise SandboxAdmissionError(
            "installed agent-protocol does not provide the required Execution Policy v1 contract"
        )
    return validator, hasher


def _policy_ref(plan: Mapping[str, Any], task: Mapping[str, Any], task_id: str) -> Mapping[str, Any]:
    raw = task.get("policy_ref", plan.get("policy_ref"))
    return _require_mapping(raw, field=f"{task_id}.policy_ref")


def _task_map(plan: object) -> tuple[Mapping[str, Any], dict[str, Mapping[str, Any]]]:
    plan_map = _require_mapping(plan, field="plan")
    raw_tasks = _require_sequence(plan_map.get("tasks"), field="plan.tasks")
    tasks: dict[str, Mapping[str, Any]] = {}
    for raw in raw_tasks:
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
) -> tuple[str, str, Mapping[str, Any], tuple[str, ...]]:
    ref = _policy_ref(plan, task, assignment.task_id)
    policy_id = _require_string(ref.get("policy_id"), field=f"{assignment.task_id}.policy_id")
    policy_sha256 = _require_string(
        ref.get("policy_sha256"), field=f"{assignment.task_id}.policy_sha256"
    )
    if policy_id not in policies:
        raise SandboxAdmissionError(
            f"task {assignment.task_id} execution policy is unavailable: {policy_id}"
        )
    policy = _require_mapping(policies[policy_id], field=f"policy[{policy_id}]")

    validator, hasher = _policy_runtime()
    try:
        validator(policy)
        actual_hash = hasher(policy)
    except Exception as exc:
        raise SandboxAdmissionError(
            f"task {assignment.task_id} execution policy validation failed"
        ) from exc
    if not isinstance(actual_hash, str) or actual_hash != policy_sha256:
        raise SandboxAdmissionError(
            f"task {assignment.task_id} execution policy hash does not match policy_ref"
        )
    if policy.get("policy_id") != policy_id:
        raise SandboxAdmissionError(
            f"task {assignment.task_id} execution policy_id does not match policy_ref"
        )

    raw_constraints = ref.get("constraints")
    if raw_constraints is None:
        constraints: tuple[str, ...] = ()
    else:
        values = _require_sequence(raw_constraints, field=f"{assignment.task_id}.constraints")
        constraints_list: list[str] = []
        for value in values:
            constraints_list.append(
                _require_string(value, field=f"{assignment.task_id}.constraints[]")
            )
        if len(constraints_list) != len(set(constraints_list)):
            raise SandboxAdmissionError(f"task {assignment.task_id} contains duplicate constraints")
        constraints = tuple(sorted(constraints_list))
    return policy_id, policy_sha256, policy, constraints


def _target_scope(
    task: Mapping[str, Any],
    request: ExecutionRequest,
) -> tuple[PurePosixPath, ...]:
    raw_target = task.get("target")
    if raw_target is None:
        if request.repo is not None or request.read_paths or request.write_paths or request.allow_delete:
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
        if request.read_paths or request.write_paths or request.allow_delete:
            raise SandboxAdmissionError(
                f"task {request.task_id} target has no path_scope; filesystem execution is denied"
            )
        return ()

    values = _require_sequence(raw_scope, field=f"{request.task_id}.target.path_scope")
    roots: list[PurePosixPath] = []
    for value in values:
        roots.append(
            _normalize_path(
                _require_string(value, field=f"{request.task_id}.target.path_scope[]"),
                field=f"{request.task_id}.target.path_scope",
            )
        )
    if len(roots) != len(set(roots)):
        raise SandboxAdmissionError(f"task {request.task_id} target path_scope contains duplicates")
    return tuple(roots)


def _policy_roots(policy: Mapping[str, Any], *, key: str, task_id: str) -> tuple[PurePosixPath, ...]:
    sandbox = _require_mapping(policy.get("sandbox"), field=f"{task_id}.policy.sandbox")
    filesystem = _require_mapping(
        sandbox.get("filesystem"), field=f"{task_id}.policy.sandbox.filesystem"
    )
    values = _require_sequence(filesystem.get(key), field=f"{task_id}.policy.{key}")
    roots: list[PurePosixPath] = []
    for value in values:
        roots.append(
            _normalize_path(
                _require_string(value, field=f"{task_id}.policy.{key}[]"),
                field=f"{task_id}.policy.{key}",
            )
        )
    return tuple(roots)


def _admit_request(
    *,
    dispatch: DispatchPlan,
    assignment: TaskAssignment,
    task: Mapping[str, Any],
    plan: Mapping[str, Any],
    request: ExecutionRequest,
    policies: Mapping[str, object],
) -> SandboxGrant:
    _validate_request_shape(request)
    if request.task_id != assignment.task_id:
        raise SandboxAdmissionError("execution request task_id does not match assignment")

    policy_id, policy_sha256, policy, constraints = _policy_for_assignment(
        plan=plan,
        task=task,
        assignment=assignment,
        policies=policies,
    )
    target_roots = _target_scope(task, request)
    requested_reads = _normalized_unique_paths(
        request.read_paths, field=f"{request.task_id}.read_paths"
    )
    requested_writes = _normalized_unique_paths(
        request.write_paths, field=f"{request.task_id}.write_paths"
    )
    policy_read_roots = _policy_roots(policy, key="read_roots", task_id=request.task_id)
    policy_write_roots = _policy_roots(policy, key="write_roots", task_id=request.task_id)

    for path in requested_reads:
        if not _path_covered(path, policy_read_roots):
            raise SandboxAdmissionError(f"task {request.task_id} read path exceeds policy scope")
        if target_roots and not _path_covered(path, target_roots):
            raise SandboxAdmissionError(f"task {request.task_id} read path exceeds task target scope")
    for path in requested_writes:
        if not _path_covered(path, policy_write_roots):
            raise SandboxAdmissionError(f"task {request.task_id} write path exceeds policy scope")
        if target_roots and not _path_covered(path, target_roots):
            raise SandboxAdmissionError(f"task {request.task_id} write path exceeds task target scope")

    sandbox = _require_mapping(policy.get("sandbox"), field=f"{request.task_id}.policy.sandbox")
    filesystem = _require_mapping(
        sandbox.get("filesystem"), field=f"{request.task_id}.policy.filesystem"
    )
    max_file_bytes = filesystem.get("max_file_bytes")
    if not isinstance(max_file_bytes, int) or isinstance(max_file_bytes, bool):
        raise SandboxAdmissionError("policy max_file_bytes is invalid")
    if request.max_file_bytes > max_file_bytes:
        raise SandboxAdmissionError(f"task {request.task_id} max_file_bytes exceeds policy")
    if request.allow_delete and filesystem.get("allow_delete") is not True:
        raise SandboxAdmissionError(f"task {request.task_id} delete is denied by policy")

    tools = _require_mapping(sandbox.get("tools"), field=f"{request.task_id}.policy.tools")
    allowed_tool_ids = {
        _require_string(item, field=f"{request.task_id}.policy.allowed_tool_ids[]")
        for item in _require_sequence(
            tools.get("allowed_tool_ids"), field=f"{request.task_id}.policy.allowed_tool_ids"
        )
    }
    denied_tools = sorted(set(request.tool_ids) - allowed_tool_ids)
    if denied_tools:
        raise SandboxAdmissionError(
            f"task {request.task_id} requests tools denied by policy: {', '.join(denied_tools)}"
        )

    network = _require_mapping(sandbox.get("network"), field=f"{request.task_id}.policy.network")
    mode = _require_string(network.get("mode"), field=f"{request.task_id}.policy.network.mode")
    allowed_hosts = {
        _require_string(item, field=f"{request.task_id}.policy.allowed_hosts[]")
        for item in _require_sequence(
            network.get("allowed_hosts"), field=f"{request.task_id}.policy.allowed_hosts"
        )
    }
    raw_ports = _require_sequence(
        network.get("allowed_ports"), field=f"{request.task_id}.policy.allowed_ports"
    )
    allowed_ports = {
        int(item)
        for item in raw_ports
        if isinstance(item, int) and not isinstance(item, bool)
    }
    if len(allowed_ports) != len(raw_ports):
        raise SandboxAdmissionError("policy allowed_ports contains invalid value")
    if mode == "deny" and (request.network_hosts or request.network_ports):
        raise SandboxAdmissionError(f"task {request.task_id} network access is denied by policy")
    if mode == "allowlist":
        denied_hosts = sorted(set(request.network_hosts) - allowed_hosts)
        denied_ports = sorted(set(request.network_ports) - allowed_ports)
        if denied_hosts or denied_ports:
            raise SandboxAdmissionError(f"task {request.task_id} network request exceeds allowlist")

    environment = _require_mapping(
        sandbox.get("environment"), field=f"{request.task_id}.policy.environment"
    )
    allowed_keys = {
        _require_string(item, field=f"{request.task_id}.policy.allowed_keys[]")
        for item in _require_sequence(
            environment.get("allowed_keys"), field=f"{request.task_id}.policy.allowed_keys"
        )
    }
    denied_keys = {
        _require_string(item, field=f"{request.task_id}.policy.denied_keys[]")
        for item in _require_sequence(
            environment.get("denied_keys"), field=f"{request.task_id}.policy.denied_keys"
        )
    }
    if set(request.environment_keys) & denied_keys or set(request.environment_keys) - allowed_keys:
        raise SandboxAdmissionError(f"task {request.task_id} environment request is denied by policy")

    resources = _require_mapping(
        sandbox.get("resources"), field=f"{request.task_id}.policy.resources"
    )
    for key, requested in request.resources.as_dict().items():
        allowed = resources.get(key)
        if not isinstance(allowed, int) or isinstance(allowed, bool) or requested > allowed:
            raise SandboxAdmissionError(
                f"task {request.task_id} resource request exceeds policy: {key}"
            )

    raw_approvals = _require_sequence(policy.get("approvals"), field=f"{request.task_id}.approvals")
    required_approvals: dict[str, Mapping[str, Any]] = {}
    for raw in raw_approvals:
        approval = _require_mapping(raw, field=f"{request.task_id}.approvals[]")
        approval_id = _require_string(
            approval.get("approval_id"), field=f"{request.task_id}.approval_id"
        )
        required_approvals[approval_id] = approval
    provided_approvals = {item.approval_id: item for item in request.approvals}
    if set(provided_approvals) != set(required_approvals):
        raise SandboxAdmissionError(
            f"task {request.task_id} approval grants do not exactly match policy requirements"
        )
    approval_evidence: list[str] = []
    for approval_id, requirement in required_approvals.items():
        grant = provided_approvals[approval_id]
        min_count = requirement.get("min_count")
        if not isinstance(min_count, int) or isinstance(min_count, bool):
            raise SandboxAdmissionError("policy approval min_count is invalid")
        if len(grant.approver_ids) < min_count:
            raise SandboxAdmissionError(f"task {request.task_id} approval count is insufficient")
        if requirement.get("evidence_required") is True and not grant.evidence_refs:
            raise SandboxAdmissionError(f"task {request.task_id} approval evidence is required")
        approval_evidence.extend(grant.evidence_refs)

    provided_constraints = {item.constraint: item for item in request.constraints}
    if set(provided_constraints) != set(constraints):
        raise SandboxAdmissionError(
            f"task {request.task_id} constraint evidence does not exactly match policy_ref"
        )
    constraint_evidence = [
        provided_constraints[constraint].evidence_ref for constraint in constraints
    ]

    request_sha256 = _sha256(request.as_dict())
    material = {
        "schema_version": "foundry.sandbox-grant.v1",
        "dispatch_id": dispatch.dispatch_id,
        "task_id": assignment.task_id,
        "agent_id": assignment.agent_id,
        "policy_id": policy_id,
        "policy_sha256": policy_sha256,
        "request_sha256": request_sha256,
        "repo": request.repo,
        "read_paths": sorted(request.read_paths),
        "write_paths": sorted(request.write_paths),
        "allow_delete": request.allow_delete,
        "max_file_bytes": request.max_file_bytes,
        "tool_ids": sorted(request.tool_ids),
        "network_hosts": sorted(request.network_hosts),
        "network_ports": sorted(request.network_ports),
        "environment_keys": sorted(request.environment_keys),
        "resources": request.resources.as_dict(),
        "approval_evidence_refs": sorted(approval_evidence),
        "constraint_evidence_refs": sorted(constraint_evidence),
    }
    grant_id = "sgr_" + _sha256(material)[:32]
    return SandboxGrant(
        schema_version="foundry.sandbox-grant.v1",
        grant_id=grant_id,
        dispatch_id=dispatch.dispatch_id,
        task_id=assignment.task_id,
        agent_id=assignment.agent_id,
        policy_id=policy_id,
        policy_sha256=policy_sha256,
        request_sha256=request_sha256,
        repo=request.repo,
        read_paths=tuple(sorted(request.read_paths)),
        write_paths=tuple(sorted(request.write_paths)),
        allow_delete=request.allow_delete,
        max_file_bytes=request.max_file_bytes,
        tool_ids=tuple(sorted(request.tool_ids)),
        network_hosts=tuple(sorted(request.network_hosts)),
        network_ports=tuple(sorted(request.network_ports)),
        environment_keys=tuple(sorted(request.environment_keys)),
        resources=request.resources,
        approval_evidence_refs=tuple(sorted(approval_evidence)),
        constraint_evidence_refs=tuple(sorted(constraint_evidence)),
    )


def admit_dispatch_to_sandbox(
    plan: object,
    *,
    admission: PlanAdmission,
    registry: CapabilityRegistry,
    requests: Sequence[ExecutionRequest],
    policies: Mapping[str, object],
    completed: frozenset[str] = frozenset(),
    failed: frozenset[str] = frozenset(),
    satisfied_preconditions: frozenset[str] = frozenset(),
) -> SandboxAdmission:
    """Build dispatch and grant sandbox authority atomically for every ready task."""
    dispatch = build_dispatch_plan(
        plan,
        admission=admission,
        registry=registry,
        completed=completed,
        failed=failed,
        satisfied_preconditions=satisfied_preconditions,
    )
    plan_map, tasks = _task_map(plan)

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

    grants: list[SandboxGrant] = []
    for assignment in dispatch.assignments:
        try:
            task = tasks[assignment.task_id]
        except KeyError as exc:
            raise SandboxAdmissionError(
                f"dispatch task missing from admitted plan: {assignment.task_id}"
            ) from exc
        grants.append(
            _admit_request(
                dispatch=dispatch,
                assignment=assignment,
                task=task,
                plan=plan_map,
                request=by_task[assignment.task_id],
                policies=policies,
            )
        )

    grants_tuple = tuple(grants)
    material = {
        "schema_version": "foundry.sandbox-admission.v1",
        "dispatch_id": dispatch.dispatch_id,
        "plan_admission_id": admission.admission_id,
        "candidate_sha256": admission.candidate_sha256,
        "registry_sha256": registry.registry_sha256,
        "grant_ids": [grant.grant_id for grant in grants_tuple],
    }
    sandbox_admission_id = "sad_" + _sha256(material)[:32]
    return SandboxAdmission(
        schema_version="foundry.sandbox-admission.v1",
        sandbox_admission_id=sandbox_admission_id,
        dispatch_id=dispatch.dispatch_id,
        plan_admission_id=admission.admission_id,
        candidate_sha256=admission.candidate_sha256,
        registry_sha256=registry.registry_sha256,
        grants=grants_tuple,
        dispatch=dispatch,
    )
