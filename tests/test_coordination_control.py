from __future__ import annotations

from pathlib import Path

import pytest

from platform_agent.coordination_control import (
    CoordinationConflictError,
    CoordinationControlError,
    PersistentCoordinationStore,
)


class FakeClock:
    def __init__(self) -> None:
        self.value = 1000.0

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


def validate_minimal_work_intent(value: object) -> None:
    if not isinstance(value, dict):
        raise ValueError("intent must be an object")
    required = {
        "intent_id",
        "tenant_context",
        "run_id",
        "task_id",
        "agent_id",
        "execution_grant_id",
        "workspace_binding_id",
        "base_state_sha256",
        "claims",
    }
    if not required.issubset(value):
        raise ValueError("missing Work Intent fields")


def make_intent(
    *,
    intent_id: str,
    task_id: str,
    agent_id: str,
    repository_id: str,
    path: str,
    access: str = "write",
    project_id: str = "prj_fixture0001",
) -> dict[str, object]:
    return {
        "schema_version": "work-intent.v1",
        "intent_id": intent_id,
        "tenant_context": {
            "schema_version": "tenant-context.v1",
            "tenant_id": "tnt_fixture0001",
            "project_id": project_id,
            "cell_id": "cell_" + "a" * 32,
            "authority_epoch": 1,
            "keyset_id": "keyset_fixture.v1",
        },
        "run_id": "run_example0001",
        "task_id": task_id,
        "agent_id": agent_id,
        "execution_grant_id": "sgr_" + "1" * 32,
        "workspace_binding_id": "wsb_" + "2" * 32,
        "base_state_sha256": "3" * 64,
        "claims": [
            {"repository_id": repository_id, "path": path, "access": access}
        ],
    }


def store(tmp_path: Path, clock: FakeClock) -> PersistentCoordinationStore:
    return PersistentCoordinationStore(
        tmp_path / "coordination.sqlite3",
        validate_work_intent=validate_minimal_work_intent,
        max_lease_seconds=60,
        clock=clock,
    )


def test_overlapping_writes_are_rejected_across_store_instances(tmp_path: Path) -> None:
    clock = FakeClock()
    first_store = store(tmp_path, clock)
    second_store = store(tmp_path, clock)

    first = make_intent(
        intent_id="wit_" + "1" * 32,
        task_id="tsk_backend0001",
        agent_id="backend-agent",
        repository_id="foundry-engineering/app",
        path="src/auth",
    )
    second = make_intent(
        intent_id="wit_" + "2" * 32,
        task_id="tsk_frontend001",
        agent_id="frontend-agent",
        repository_id="foundry-engineering/app",
        path="src/auth/session.py",
    )

    first_store.publish(first, lease_seconds=30)
    with pytest.raises(CoordinationConflictError) as exc:
        second_store.publish(second, lease_seconds=30)

    assert exc.value.conflicting_intent_id == first["intent_id"]


def test_parallel_reads_and_different_repositories_are_allowed(tmp_path: Path) -> None:
    clock = FakeClock()
    coordinator = store(tmp_path, clock)

    read_one = make_intent(
        intent_id="wit_" + "1" * 32,
        task_id="tsk_reader0001",
        agent_id="qa-agent",
        repository_id="foundry-engineering/app",
        path="src/service.py",
        access="read",
    )
    read_two = make_intent(
        intent_id="wit_" + "2" * 32,
        task_id="tsk_reader0002",
        agent_id="security-agent",
        repository_id="foundry-engineering/app",
        path="src/service.py",
        access="read",
    )
    other_repo = make_intent(
        intent_id="wit_" + "3" * 32,
        task_id="tsk_docs00001",
        agent_id="documentation-agent",
        repository_id="foundry-engineering/docs",
        path="src",
    )

    coordinator.publish(read_one, lease_seconds=30)
    coordinator.publish(read_two, lease_seconds=30)
    coordinator.publish(other_repo, lease_seconds=30)

    assert len(coordinator.active_leases()) == 3


def test_expired_lease_is_removed_atomically_and_no_longer_blocks(tmp_path: Path) -> None:
    clock = FakeClock()
    coordinator = store(tmp_path, clock)

    first = make_intent(
        intent_id="wit_" + "1" * 32,
        task_id="tsk_backend0001",
        agent_id="backend-agent",
        repository_id="foundry-engineering/app",
        path="src",
    )
    second = make_intent(
        intent_id="wit_" + "2" * 32,
        task_id="tsk_frontend001",
        agent_id="frontend-agent",
        repository_id="foundry-engineering/app",
        path="src/ui",
    )

    coordinator.publish(first, lease_seconds=10)
    clock.advance(11)
    coordinator.publish(second, lease_seconds=10)

    active = coordinator.active_leases()
    assert [lease.intent_id for lease in active] == [second["intent_id"]]


def test_renew_rotates_lease_and_stale_release_fails_closed(tmp_path: Path) -> None:
    clock = FakeClock()
    coordinator = store(tmp_path, clock)
    work = make_intent(
        intent_id="wit_" + "1" * 32,
        task_id="tsk_backend0001",
        agent_id="backend-agent",
        repository_id="foundry-engineering/app",
        path="src",
    )

    first = coordinator.publish(work, lease_seconds=10)
    renewed = coordinator.renew(first.intent_id, first.lease_id, lease_seconds=20)

    assert renewed.generation == 2
    assert renewed.lease_id != first.lease_id
    with pytest.raises(CoordinationControlError, match="stale"):
        coordinator.release(first.intent_id, first.lease_id)

    coordinator.release(renewed.intent_id, renewed.lease_id)
    assert coordinator.active_leases() == ()


def test_same_intent_is_idempotent_but_identity_collision_is_rejected(tmp_path: Path) -> None:
    clock = FakeClock()
    coordinator = store(tmp_path, clock)
    work = make_intent(
        intent_id="wit_" + "1" * 32,
        task_id="tsk_backend0001",
        agent_id="backend-agent",
        repository_id="foundry-engineering/app",
        path="src",
    )

    first = coordinator.publish(work, lease_seconds=30)
    second = coordinator.publish(work, lease_seconds=30)
    assert first == second

    collision = make_intent(
        intent_id=str(work["intent_id"]),
        task_id="tsk_other00001",
        agent_id="frontend-agent",
        repository_id="foundry-engineering/app",
        path="src/ui",
    )
    with pytest.raises(CoordinationControlError, match="collision"):
        coordinator.publish(collision, lease_seconds=30)


def test_symlink_database_path_is_rejected(tmp_path: Path) -> None:
    target = tmp_path / "real.sqlite3"
    target.touch()
    link = tmp_path / "coordination.sqlite3"
    link.symlink_to(target)
    with pytest.raises(CoordinationControlError, match="symlink"):
        PersistentCoordinationStore(
            link,
            validate_work_intent=validate_minimal_work_intent,
        )
