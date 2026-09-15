from __future__ import annotations

import pytest

from platform_agent.task_graph import TaskGraphError, evaluate_task_graph

A = "tsk_AAAAAAAAAAAAAAAAAAAA"
B = "tsk_BBBBBBBBBBBBBBBBBBBB"
C = "tsk_CCCCCCCCCCCCCCCCCCCC"


def _task(
    task_id: str,
    dependencies: list[str],
    *,
    preconditions: list[str] | None = None,
) -> dict[str, object]:
    return {
        "task_id": task_id,
        "dependencies": dependencies,
        "preconditions": preconditions or [],
        "acceptance_gates": [{"gate_id": "gate_ok"}],
    }


def _plan(tasks: list[dict[str, object]]) -> dict[str, object]:
    return {
        "policy_ref": {"policy_id": "pol_foundry_default"},
        "tasks": tasks,
    }


def test_chain_readiness_and_resume() -> None:
    plan = _plan([
        _task(C, [B]),
        _task(B, [A]),
        _task(A, []),
    ])

    initial = evaluate_task_graph(plan)
    assert initial.topological_order == (A, B, C)
    assert initial.ready_task_ids == (A,)

    resumed = evaluate_task_graph(plan, completed=frozenset({A}))
    assert resumed.ready_task_ids == (B,)


def test_failed_dependency_blocks_downstream() -> None:
    plan = _plan([
        _task(A, []),
        _task(B, [A]),
    ])

    snapshot = evaluate_task_graph(plan, failed=frozenset({A}))
    decisions = {item.task_id: item for item in snapshot.decisions}

    assert decisions[A].state == "failed"
    assert decisions[B].state == "blocked_failed_dependency"
    assert decisions[B].failed_dependencies == (A,)


def test_precondition_is_fail_closed_until_explicitly_satisfied() -> None:
    plan = _plan([
        _task(A, [], preconditions=["approval:owner"]),
    ])

    blocked = evaluate_task_graph(plan)
    assert blocked.decisions[0].state == "blocked_precondition"

    ready = evaluate_task_graph(
        plan,
        satisfied_preconditions=frozenset({"approval:owner"}),
    )
    assert ready.ready_task_ids == (A,)


def test_missing_gate_and_policy_fail_closed() -> None:
    missing_gate = _plan([_task(A, [])])
    tasks = missing_gate["tasks"]
    assert isinstance(tasks, list)
    tasks[0]["acceptance_gates"] = []
    assert evaluate_task_graph(missing_gate).decisions[0].state == "blocked_missing_gate"

    missing_policy = {"tasks": [_task(A, [])]}
    assert evaluate_task_graph(missing_policy).decisions[0].state == "blocked_policy"


def test_cycle_is_rejected() -> None:
    plan = _plan([
        _task(A, [B]),
        _task(B, [A]),
    ])

    with pytest.raises(TaskGraphError, match="dependency cycle"):
        evaluate_task_graph(plan)


def test_runtime_state_cannot_reference_unknown_task() -> None:
    plan = _plan([_task(A, [])])

    with pytest.raises(TaskGraphError, match="unknown task"):
        evaluate_task_graph(plan, completed=frozenset({B}))
