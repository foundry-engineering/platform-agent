from __future__ import annotations

import heapq
from dataclasses import dataclass
from typing import Literal

TaskState = Literal[
    "completed",
    "failed",
    "ready",
    "blocked_dependency",
    "blocked_failed_dependency",
    "blocked_precondition",
    "blocked_missing_gate",
    "blocked_policy",
]


class TaskGraphError(ValueError):
    """Raised when a plan cannot form a deterministic task graph."""


@dataclass(frozen=True, slots=True)
class TaskDecision:
    task_id: str
    state: TaskState
    waiting_on: tuple[str, ...] = ()
    failed_dependencies: tuple[str, ...] = ()
    missing_preconditions: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, object]:
        return {
            "task_id": self.task_id,
            "state": self.state,
            "waiting_on": list(self.waiting_on),
            "failed_dependencies": list(self.failed_dependencies),
            "missing_preconditions": list(self.missing_preconditions),
        }


@dataclass(frozen=True, slots=True)
class TaskGraphSnapshot:
    topological_order: tuple[str, ...]
    decisions: tuple[TaskDecision, ...]

    @property
    def ready_task_ids(self) -> tuple[str, ...]:
        return tuple(
            decision.task_id
            for decision in self.decisions
            if decision.state == "ready"
        )

    def as_dict(self) -> dict[str, object]:
        return {
            "topological_order": list(self.topological_order),
            "ready_task_ids": list(self.ready_task_ids),
            "decisions": [decision.as_dict() for decision in self.decisions],
        }


def _task_map(plan: object) -> dict[str, dict[str, object]]:
    if not isinstance(plan, dict):
        raise TaskGraphError("plan must be an object")

    raw_tasks = plan.get("tasks")
    if not isinstance(raw_tasks, list) or not raw_tasks:
        raise TaskGraphError("plan must contain at least one task")

    result: dict[str, dict[str, object]] = {}
    for raw_task in raw_tasks:
        if not isinstance(raw_task, dict):
            raise TaskGraphError("every task must be an object")

        task_id = raw_task.get("task_id")
        if not isinstance(task_id, str) or not task_id:
            raise TaskGraphError("every task must have a non-empty task_id")
        if task_id in result:
            raise TaskGraphError(f"duplicate task_id: {task_id}")
        result[task_id] = raw_task

    return result


def _dependencies(
    tasks: dict[str, dict[str, object]],
) -> dict[str, tuple[str, ...]]:
    result: dict[str, tuple[str, ...]] = {}

    for task_id, task in tasks.items():
        raw_dependencies = task.get("dependencies")
        if not isinstance(raw_dependencies, list):
            raise TaskGraphError(f"task {task_id} dependencies must be an array")

        dependencies: list[str] = []
        for raw_dependency in raw_dependencies:
            if not isinstance(raw_dependency, str) or not raw_dependency:
                raise TaskGraphError(f"task {task_id} contains an invalid dependency")
            if raw_dependency == task_id:
                raise TaskGraphError(f"task {task_id} depends on itself")
            if raw_dependency not in tasks:
                raise TaskGraphError(
                    f"task {task_id} references unknown dependency {raw_dependency}"
                )
            dependencies.append(raw_dependency)

        if len(dependencies) != len(set(dependencies)):
            raise TaskGraphError(f"task {task_id} contains duplicate dependencies")
        result[task_id] = tuple(sorted(dependencies))

    return result


def _topological_order(
    dependencies: dict[str, tuple[str, ...]],
) -> tuple[str, ...]:
    indegree = {task_id: len(deps) for task_id, deps in dependencies.items()}
    dependents: dict[str, list[str]] = {task_id: [] for task_id in dependencies}

    for task_id, deps in dependencies.items():
        for dependency in deps:
            dependents[dependency].append(task_id)

    ready = [task_id for task_id, degree in indegree.items() if degree == 0]
    heapq.heapify(ready)
    ordered: list[str] = []

    while ready:
        task_id = heapq.heappop(ready)
        ordered.append(task_id)

        for dependent in sorted(dependents[task_id]):
            indegree[dependent] -= 1
            if indegree[dependent] == 0:
                heapq.heappush(ready, dependent)

    if len(ordered) != len(dependencies):
        unresolved = sorted(
            task_id for task_id, degree in indegree.items() if degree > 0
        )
        raise TaskGraphError(
            f"dependency cycle detected among: {', '.join(unresolved)}"
        )

    return tuple(ordered)


def _preconditions(task_id: str, task: dict[str, object]) -> tuple[str, ...]:
    raw = task.get("preconditions")
    if not isinstance(raw, list):
        raise TaskGraphError(f"task {task_id} preconditions must be an array")

    values: list[str] = []
    for item in raw:
        if not isinstance(item, str) or not item:
            raise TaskGraphError(f"task {task_id} contains an invalid precondition")
        values.append(item)

    if len(values) != len(set(values)):
        raise TaskGraphError(f"task {task_id} contains duplicate preconditions")
    return tuple(sorted(values))


def _has_acceptance_gate(task: dict[str, object]) -> bool:
    raw = task.get("acceptance_gates")
    return isinstance(raw, list) and len(raw) > 0


def _has_policy(plan: dict[str, object], task: dict[str, object]) -> bool:
    task_policy = task.get("policy_ref")
    if task_policy is not None:
        return isinstance(task_policy, dict)
    return isinstance(plan.get("policy_ref"), dict)


def evaluate_task_graph(
    plan: object,
    *,
    completed: frozenset[str] = frozenset(),
    failed: frozenset[str] = frozenset(),
    satisfied_preconditions: frozenset[str] = frozenset(),
) -> TaskGraphSnapshot:
    """Evaluate deterministic task readiness without executing any task.

    Runtime state is supplied explicitly. Missing policy, missing gates and
    unsatisfied preconditions fail closed. No task is marked ready merely
    because it appears earlier in the source plan.
    """
    if not isinstance(plan, dict):
        raise TaskGraphError("plan must be an object")

    tasks = _task_map(plan)
    dependencies = _dependencies(tasks)
    ordered = _topological_order(dependencies)

    overlap = completed & failed
    if overlap:
        raise TaskGraphError(
            f"task cannot be both completed and failed: {', '.join(sorted(overlap))}"
        )

    known = set(tasks)
    unknown_runtime = (completed | failed) - known
    if unknown_runtime:
        raise TaskGraphError(
            "runtime state references unknown task(s): "
            + ", ".join(sorted(unknown_runtime))
        )

    decisions: list[TaskDecision] = []
    for task_id in ordered:
        task = tasks[task_id]

        if task_id in completed:
            decisions.append(TaskDecision(task_id=task_id, state="completed"))
            continue

        if task_id in failed:
            decisions.append(TaskDecision(task_id=task_id, state="failed"))
            continue

        deps = dependencies[task_id]
        failed_dependencies = tuple(
            dependency for dependency in deps if dependency in failed
        )
        if failed_dependencies:
            decisions.append(
                TaskDecision(
                    task_id=task_id,
                    state="blocked_failed_dependency",
                    failed_dependencies=failed_dependencies,
                )
            )
            continue

        waiting_on = tuple(
            dependency for dependency in deps if dependency not in completed
        )
        if waiting_on:
            decisions.append(
                TaskDecision(
                    task_id=task_id,
                    state="blocked_dependency",
                    waiting_on=waiting_on,
                )
            )
            continue

        preconditions = _preconditions(task_id, task)
        missing_preconditions = tuple(
            item for item in preconditions if item not in satisfied_preconditions
        )
        if missing_preconditions:
            decisions.append(
                TaskDecision(
                    task_id=task_id,
                    state="blocked_precondition",
                    missing_preconditions=missing_preconditions,
                )
            )
            continue

        if not _has_acceptance_gate(task):
            decisions.append(TaskDecision(task_id=task_id, state="blocked_missing_gate"))
            continue

        if not _has_policy(plan, task):
            decisions.append(TaskDecision(task_id=task_id, state="blocked_policy"))
            continue

        decisions.append(TaskDecision(task_id=task_id, state="ready"))

    return TaskGraphSnapshot(
        topological_order=ordered,
        decisions=tuple(decisions),
    )
