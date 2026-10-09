from __future__ import annotations

import pytest

from platform_agent.admitted_scheduler import evaluate_admitted_plan
from platform_agent.plan_admission import PlanAdmission, PlanAdmissionError, candidate_sha256

A = "tsk_AAAAAAAAAAAAAAAAAAAA"
SOURCE_SHA = "a" * 64
PLAN_GRAPH_ID = "https://foundry.engineering/schemas/plangraph/v1/plan_graph.json"


def _plan() -> dict[str, object]:
    return {
        "plan_id": "pln_ABCDEFGHIJKLMNOPQRSTUVWXYZ12",
        "source": {"sha256": SOURCE_SHA},
        "policy_ref": {"policy_id": "pol_foundry_default"},
        "tasks": [
            {
                "task_id": A,
                "dependencies": [],
                "preconditions": [],
                "acceptance_gates": [{"gate_id": "gate_ok"}],
            }
        ],
    }


def _admission(plan: object) -> PlanAdmission:
    candidate = candidate_sha256(plan)
    material = {
        "schema_version": "foundry.plan-admission.v1",
        "plan_id": "pln_ABCDEFGHIJKLMNOPQRSTUVWXYZ12",
        "source_sha256": SOURCE_SHA,
        "candidate_sha256": candidate,
        "approval_evidence_ref": "sha256:" + "e" * 64,
        "protocol_schema_id": PLAN_GRAPH_ID,
        "dependencies_reviewed": True,
        "routing_reviewed": True,
    }
    import hashlib
    import json

    admission_id = "adm_" + hashlib.sha256(
        json.dumps(material, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()[:32]
    return PlanAdmission(admission_id=admission_id, **material)


def test_admitted_plan_can_produce_ready_task() -> None:
    plan = _plan()
    schedule = evaluate_admitted_plan(plan, admission=_admission(plan))

    assert schedule.ready_task_ids == (A,)
    assert schedule.candidate_sha256 == candidate_sha256(plan)


def test_plan_mutation_invalidates_admission_before_scheduling() -> None:
    plan = _plan()
    admitted = _admission(plan)
    plan["policy_ref"] = {"policy_id": "pol_changed"}

    with pytest.raises(PlanAdmissionError, match="candidate hash mismatch"):
        evaluate_admitted_plan(plan, admission=admitted)
