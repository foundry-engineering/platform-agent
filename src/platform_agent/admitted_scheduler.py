from __future__ import annotations

from dataclasses import dataclass

from platform_agent.plan_admission import PlanAdmission, verify_plan_admission
from platform_agent.task_graph import TaskGraphSnapshot, evaluate_task_graph


@dataclass(frozen=True, slots=True)
class AdmittedSchedule:
    admission_id: str
    candidate_sha256: str
    graph: TaskGraphSnapshot

    @property
    def ready_task_ids(self) -> tuple[str, ...]:
        return self.graph.ready_task_ids

    def as_dict(self) -> dict[str, object]:
        return {
            "admission_id": self.admission_id,
            "candidate_sha256": self.candidate_sha256,
            "graph": self.graph.as_dict(),
        }


def evaluate_admitted_plan(
    plan: object,
    *,
    admission: PlanAdmission,
    completed: frozenset[str] = frozenset(),
    failed: frozenset[str] = frozenset(),
    satisfied_preconditions: frozenset[str] = frozenset(),
) -> AdmittedSchedule:
    """Evaluate readiness only after admission is bound to this exact plan.

    Raw parser output is intentionally insufficient for scheduling. Admission
    verification happens before task graph evaluation so stale/tampered plans
    never reach the ready-task set through this control-plane boundary.
    """
    verify_plan_admission(plan, admission)
    graph = evaluate_task_graph(
        plan,
        completed=completed,
        failed=failed,
        satisfied_preconditions=satisfied_preconditions,
    )
    return AdmittedSchedule(
        admission_id=admission.admission_id,
        candidate_sha256=admission.candidate_sha256,
        graph=graph,
    )
