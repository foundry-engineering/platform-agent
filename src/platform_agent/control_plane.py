from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Mapping, Sequence

from platform_agent.admitted_scheduler import AdmittedSchedule, evaluate_admitted_plan
from platform_agent.capability_router import (
    CapabilityRegistry,
    CapabilityRoutingError,
)
from platform_agent.plan_admission import PlanAdmission


class DispatchError(ValueError):
    """Raised when an admitted ready-task set cannot be routed atomically."""


@dataclass(frozen=True, slots=True)
class TaskAssignment:
    task_id: str
    agent_id: str
    required_capabilities: tuple[str, ...]
    admission_id: str
    candidate_sha256: str
    registry_sha256: str

    def as_dict(self) -> dict[str, object]:
        return {
            "task_id": self.task_id,
            "agent_id": self.agent_id,
            "required_capabilities": list(self.required_capabilities),
            "admission_id": self.admission_id,
            "candidate_sha256": self.candidate_sha256,
            "registry_sha256": self.registry_sha256,
        }


@dataclass(frozen=True, slots=True)
class DispatchPlan:
    schema_version: str
    dispatch_id: str
    admission_id: str
    candidate_sha256: str
    registry_sha256: str
    assignments: tuple[TaskAssignment, ...]
    schedule: AdmittedSchedule

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "dispatch_id": self.dispatch_id,
            "admission_id": self.admission_id,
            "candidate_sha256": self.candidate_sha256,
            "registry_sha256": self.registry_sha256,
            "assignments": [item.as_dict() for item in self.assignments],
            "schedule": self.schedule.as_dict(),
        }


def _canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _dispatch_id(material: object) -> str:
    digest = hashlib.sha256(_canonical_json(material).encode("utf-8")).hexdigest()
    return "dsp_" + digest[:32]


def _task_map(plan: object) -> dict[str, Mapping[str, object]]:
    if not isinstance(plan, Mapping):
        raise DispatchError("plan must be an object")
    raw_tasks = plan.get("tasks")
    if not isinstance(raw_tasks, Sequence) or isinstance(raw_tasks, (str, bytes, bytearray)):
        raise DispatchError("plan.tasks must be an array")

    tasks: dict[str, Mapping[str, object]] = {}
    for raw in raw_tasks:
        if not isinstance(raw, Mapping):
            raise DispatchError("every task must be an object")
        task_id = raw.get("task_id")
        if not isinstance(task_id, str) or not task_id:
            raise DispatchError("every task must have a task_id")
        if task_id in tasks:
            raise DispatchError(f"duplicate task_id: {task_id}")
        tasks[task_id] = raw
    return tasks


def _routing(task_id: str, task: Mapping[str, object]) -> tuple[str | None, tuple[str, ...]]:
    routing = task.get("routing")
    if not isinstance(routing, Mapping):
        raise DispatchError(f"task {task_id} routing must be an object")

    raw_owner = routing.get("owner")
    if raw_owner is not None and (not isinstance(raw_owner, str) or not raw_owner):
        raise DispatchError(f"task {task_id} routing.owner must be string|null")
    owner = raw_owner if isinstance(raw_owner, str) else None

    raw_capabilities = routing.get("required_capabilities")
    if not isinstance(raw_capabilities, Sequence) or isinstance(
        raw_capabilities, (str, bytes, bytearray)
    ):
        raise DispatchError(f"task {task_id} required_capabilities must be an array")

    capabilities: list[str] = []
    for capability in raw_capabilities:
        if not isinstance(capability, str) or not capability:
            raise DispatchError(f"task {task_id} contains invalid required capability")
        capabilities.append(capability)
    if len(capabilities) != len(set(capabilities)):
        raise DispatchError(f"task {task_id} contains duplicate required capabilities")
    if owner is None and not capabilities:
        raise DispatchError(f"task {task_id} has neither owner nor required capability")

    return owner, tuple(sorted(capabilities))


def build_dispatch_plan(
    plan: object,
    *,
    admission: PlanAdmission,
    registry: CapabilityRegistry,
    completed: frozenset[str] = frozenset(),
    failed: frozenset[str] = frozenset(),
    satisfied_preconditions: frozenset[str] = frozenset(),
) -> DispatchPlan:
    """Build an all-or-nothing deterministic routing plan for ready tasks.

    This function does not authorize tools or execute agents. A future sandbox/
    policy admission must consume this dispatch before any mutation is allowed.
    """
    schedule = evaluate_admitted_plan(
        plan,
        admission=admission,
        completed=completed,
        failed=failed,
        satisfied_preconditions=satisfied_preconditions,
    )
    tasks = _task_map(plan)

    assignments: list[TaskAssignment] = []
    for task_id in schedule.ready_task_ids:
        try:
            task = tasks[task_id]
        except KeyError as exc:
            raise DispatchError(f"ready task missing from plan: {task_id}") from exc

        owner, required_capabilities = _routing(task_id, task)
        try:
            decision = registry.route(
                required_capabilities,
                preferred_owner=owner,
            )
        except CapabilityRoutingError as exc:
            raise DispatchError(f"task {task_id} cannot be routed: {exc}") from exc

        assignments.append(
            TaskAssignment(
                task_id=task_id,
                agent_id=decision.agent_id,
                required_capabilities=decision.required_capabilities,
                admission_id=admission.admission_id,
                candidate_sha256=admission.candidate_sha256,
                registry_sha256=decision.registry_sha256,
            )
        )

    assignments_tuple = tuple(assignments)
    material = {
        "schema_version": "foundry.dispatch-plan.v1",
        "admission_id": admission.admission_id,
        "candidate_sha256": admission.candidate_sha256,
        "registry_sha256": registry.registry_sha256,
        "assignments": [item.as_dict() for item in assignments_tuple],
        "ready_task_ids": list(schedule.ready_task_ids),
    }
    return DispatchPlan(
        schema_version="foundry.dispatch-plan.v1",
        dispatch_id=_dispatch_id(material),
        admission_id=admission.admission_id,
        candidate_sha256=admission.candidate_sha256,
        registry_sha256=registry.registry_sha256,
        assignments=assignments_tuple,
        schedule=schedule,
    )
