from __future__ import annotations

import hashlib
import json

import pytest

from platform_agent.capability_router import CapabilityRegistry
from platform_agent.control_plane import DispatchError, build_dispatch_plan
from platform_agent.plan_admission import PlanAdmission, PlanAdmissionError, candidate_sha256

A = "tsk_AAAAAAAAAAAAAAAAAAAA"
B = "tsk_BBBBBBBBBBBBBBBBBBBB"
SOURCE_SHA = "a" * 64
PLAN_GRAPH_ID = "https://foundry.engineering/schemas/plangraph/v1/plan_graph.json"


def _payload(*capability_ids: str) -> dict[str, object]:
    return {
        "type": "capability.advertise",
        "capabilities": [
            {
                "capability_id": capability_id,
                "version": "1.0.0",
                "input_schema": f"schema://{capability_id}/input",
                "output_schema": f"schema://{capability_id}/output",
            }
            for capability_id in capability_ids
        ],
    }


def _task(
    task_id: str,
    *,
    owner: str | None,
    capabilities: list[str],
) -> dict[str, object]:
    return {
        "task_id": task_id,
        "dependencies": [],
        "preconditions": [],
        "acceptance_gates": [{"gate_id": "gate_ok"}],
        "routing": {
            "owner": owner,
            "required_capabilities": capabilities,
        },
    }


def _plan() -> dict[str, object]:
    return {
        "plan_id": "pln_ABCDEFGHIJKLMNOPQRSTUVWXYZ12",
        "source": {"sha256": SOURCE_SHA},
        "policy_ref": {"policy_id": "pol_foundry_default"},
        "tasks": [
            _task(A, owner="backend-agent", capabilities=[]),
            _task(B, owner=None, capabilities=["cap_frontend.web"]),
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
    admission_id = "adm_" + hashlib.sha256(
        json.dumps(material, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()[:32]
    return PlanAdmission(admission_id=admission_id, **material)


def _registry() -> CapabilityRegistry:
    return CapabilityRegistry.from_apv1_payloads(
        {
            "backend-agent": _payload("cap_backend.service"),
            "frontend-agent": _payload("cap_frontend.web"),
        }
    )


def test_dispatch_routes_owner_only_and_capability_only_tasks() -> None:
    plan = _plan()
    dispatch = build_dispatch_plan(
        plan,
        admission=_admission(plan),
        registry=_registry(),
    )

    assert tuple(item.task_id for item in dispatch.assignments) == (A, B)
    assert tuple(item.agent_id for item in dispatch.assignments) == (
        "backend-agent",
        "frontend-agent",
    )
    assert all(
        item.registry_sha256 == dispatch.registry_sha256
        for item in dispatch.assignments
    )
    assert dispatch.dispatch_id.startswith("dsp_")


def test_dispatch_is_deterministic_for_equivalent_registry_order() -> None:
    plan = _plan()
    admitted = _admission(plan)
    first = _registry()
    second = CapabilityRegistry.from_apv1_payloads(
        {
            "frontend-agent": _payload("cap_frontend.web"),
            "backend-agent": _payload("cap_backend.service"),
        }
    )

    left = build_dispatch_plan(plan, admission=admitted, registry=first)
    right = build_dispatch_plan(plan, admission=admitted, registry=second)

    assert left.dispatch_id == right.dispatch_id
    assert left.registry_sha256 == right.registry_sha256


def test_one_unroutable_ready_task_aborts_entire_dispatch() -> None:
    plan = _plan()
    tasks = plan["tasks"]
    assert isinstance(tasks, list)
    second = tasks[1]
    assert isinstance(second, dict)
    second["routing"] = {
        "owner": "missing-agent",
        "required_capabilities": [],
    }
    admitted = _admission(plan)

    with pytest.raises(DispatchError, match="cannot be routed"):
        build_dispatch_plan(plan, admission=admitted, registry=_registry())


def test_stale_admission_blocks_dispatch_before_routing() -> None:
    plan = _plan()
    admitted = _admission(plan)
    plan["policy_ref"] = {"policy_id": "pol_changed"}

    with pytest.raises(PlanAdmissionError, match="candidate hash mismatch"):
        build_dispatch_plan(plan, admission=admitted, registry=_registry())
