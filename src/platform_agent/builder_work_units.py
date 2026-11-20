"""Operational work units narrow one existing approved Builder job.

The canonical job, grant and durable economic envelope stay unchanged. This
module supplies scheduling data and bounded context, never execution authority.
"""
from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

from engineering_agent.builder import BudgetedPlanner, BuilderBoundaryError, BuilderTask, PlanProposal
from engineering_agent.source_context import MAX_SOURCE_FILES, ScopedSourceContext, SourceSnapshot, source_path

from .task_graph import TaskGraphSnapshot, evaluate_task_graph

_ID = re.compile(r"[a-z][a-z0-9_-]{2,63}\Z")


@dataclass(frozen=True, slots=True)
class BuilderWorkUnit:
    unit_id: str
    objective: str
    source_paths: tuple[str, ...]
    output_paths: tuple[str, ...]
    dependencies: tuple[str, ...]
    max_rounds: int
    check_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.unit_id, str) or not _ID.fullmatch(self.unit_id):
            raise BuilderBoundaryError("invalid Builder work-unit identity")
        if (not isinstance(self.objective, str) or not self.objective
                or self.objective.strip() != self.objective or len(self.objective) > 800
                or any(ord(c) < 32 for c in self.objective)):
            raise BuilderBoundaryError("work-unit objective must be bounded text")
        for values, maximum in ((self.source_paths, MAX_SOURCE_FILES), (self.output_paths, 8),
                                (self.check_ids, 12), (self.dependencies, 5)):
            if (not isinstance(values, tuple) or len(values) > maximum
                    or any(not isinstance(x, str) for x in values)
                    or len(set(values)) != len(values)):
                raise BuilderBoundaryError("work-unit lists must be explicit and unique")
        if not self.source_paths or not self.output_paths or not self.check_ids:
            raise BuilderBoundaryError("work units require source, output and independent checks")
        for path in self.source_paths:
            source_path(path)
        if not set(self.output_paths) <= set(self.source_paths):
            raise BuilderBoundaryError("work-unit outputs must have explicit source snapshots")
        if (any(not _ID.fullmatch(x) for x in (*self.check_ids, *self.dependencies))
                or self.unit_id in self.dependencies
                or type(self.max_rounds) is not int or not 1 <= self.max_rounds <= 6):
            raise BuilderBoundaryError("invalid work-unit dependencies, checks or round limit")
        if len(self.model_instruction()) > 2000:
            raise BuilderBoundaryError("work-unit model instruction exceeds the feedback limit")

    def model_instruction(self, *, include_objective: bool = True) -> str:
        value: dict[str, object] = {"unitId": self.unit_id, "outputPaths": self.output_paths}
        if include_objective:
            value["objective"] = self.objective
        return "Approved work-unit data: " + json.dumps(value, ensure_ascii=False, separators=(",", ":"))

    @classmethod
    def from_payload(cls, value: object) -> BuilderWorkUnit:
        fields = {"unitId", "objective", "sourcePaths", "outputPaths", "dependencies", "maxRounds", "checkIds"}
        if not isinstance(value, dict) or set(value) != fields:
            raise BuilderBoundaryError("exact Builder work-unit profile required")
        for key in ("sourcePaths", "outputPaths", "dependencies", "checkIds"):
            if not isinstance(value[key], list):
                raise BuilderBoundaryError("Builder work-unit profile lists required")
        return cls(value["unitId"], value["objective"], tuple(value["sourcePaths"]),
                   tuple(value["outputPaths"]), tuple(value["dependencies"]),
                   value["maxRounds"], tuple(value["checkIds"]))


def unit_graph(
    units: tuple[BuilderWorkUnit, ...], policy: Mapping[str, Any],
    *, completed: frozenset[str] = frozenset(),
) -> TaskGraphSnapshot:
    return evaluate_task_graph({"policy_ref": dict(policy), "tasks": [
        {"task_id": unit.unit_id, "dependencies": list(unit.dependencies), "preconditions": [],
         "acceptance_gates": list(unit.check_ids)} for unit in units
    ]}, completed=completed)


def validate_work_units(
    task: BuilderTask, source_paths: tuple[str, ...], units: tuple[BuilderWorkUnit, ...],
    policy: Mapping[str, Any],
) -> TaskGraphSnapshot:
    if (not isinstance(units, tuple) or not 1 <= len(units) <= 6
            or any(not isinstance(unit, BuilderWorkUnit) for unit in units)
            or len({unit.unit_id for unit in units}) != len(units)
            or sum(unit.max_rounds for unit in units) > task.max_rounds):
        raise BuilderBoundaryError("work units must fit the approved total model-call limit")
    if (not isinstance(source_paths, tuple) or len(set(source_paths)) != len(source_paths)
            or set(source_paths) != {path for unit in units for path in unit.source_paths}):
        raise BuilderBoundaryError("project source paths must exactly match its work units")
    if any(PurePosixPath(left) in PurePosixPath(right).parents
           for left in source_paths for right in source_paths if left != right):
        raise BuilderBoundaryError("project file paths cannot alias ancestor directories")
    graph = unit_graph(units, policy)
    by_id = {unit.unit_id: unit for unit in units}
    owners: dict[str, str] = {}
    for unit in units:
        for path in unit.output_paths:
            if path in owners:
                raise BuilderBoundaryError("project output paths require a single work-unit owner")
            owners[path] = unit.unit_id
    ancestors: dict[str, set[str]] = {}
    for unit_id in graph.topological_order:
        unit = by_id[unit_id]
        ancestors[unit_id] = set(unit.dependencies)
        for dependency in unit.dependencies:
            ancestors[unit_id].update(ancestors[dependency])
        if any(path in owners and owners[path] != unit_id
               and owners[path] not in ancestors[unit_id] for path in unit.source_paths):
            raise BuilderBoundaryError("work-unit source reads require their producer dependency")
    return graph


class ProjectSourceContext:
    """Collect final explicit project bytes without expanding any model request."""
    def __init__(self, workspace: Path, paths: tuple[str, ...], units: tuple[BuilderWorkUnit, ...]) -> None:
        self._paths = paths
        self._contexts = tuple(ScopedSourceContext(workspace, unit.source_paths) for unit in units)

    def snapshot(self) -> tuple[SourceSnapshot, ...]:
        sources: dict[str, SourceSnapshot] = {}
        for context in self._contexts:
            for item in context.snapshot():
                if item.path in sources and sources[item.path] != item:
                    raise BuilderBoundaryError("project source changed between work-unit snapshots")
                sources[item.path] = item
        return tuple(sources[path] for path in self._paths)


def unit_definitions(units: tuple[BuilderWorkUnit, ...]) -> list[dict[str, Any]]:
    return [asdict(unit) for unit in units]


class WorkUnitPlanner:
    """Add only trusted operational task data to the existing admitted planner."""
    def __init__(self, planner: BudgetedPlanner, unit: BuilderWorkUnit) -> None:
        self._planner, self._unit = planner, unit

    def propose(self, task: BuilderTask, feedback: tuple[str, ...],
                *, remaining_budget_microusd: int) -> PlanProposal:
        instruction = self._unit.model_instruction(include_objective=self._unit.objective != task.goal)
        return self._planner.propose(task, (instruction, *feedback),
            remaining_budget_microusd=remaining_budget_microusd)
