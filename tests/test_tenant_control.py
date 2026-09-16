from __future__ import annotations

from pathlib import Path

import pytest

from platform_agent.tenant_control import (
    SQLiteTenantControlStore,
    TenantControlError,
    TenantNotActiveError,
    TenantQuotaError,
    TenantQuotaLimits,
)

TENANT = "tnt_company0001"
PROJECT = "prj_product0001"
REPO = "customer/example"


def _store(tmp_path: Path, *, quotas: TenantQuotaLimits | None = None) -> SQLiteTenantControlStore:
    store = SQLiteTenantControlStore(tmp_path / "control" / "tenants.sqlite3")
    store.create_tenant(TENANT, keyset_id="keyset_company.v1", quotas=quotas)
    store.create_project(TENANT, PROJECT)
    store.bind_repository(TENANT, PROJECT, REPO)
    return store


def test_snapshot_is_tenant_project_and_repository_bound(tmp_path: Path) -> None:
    store = _store(tmp_path)
    snapshot = store.snapshot(TENANT, PROJECT, REPO)

    assert snapshot.context.tenant_id == TENANT
    assert snapshot.context.project_id == PROJECT
    assert snapshot.context.authority_epoch == 1
    assert snapshot.context.keyset_id == "keyset_company.v1"
    assert snapshot.repository_id == REPO
    assert len(snapshot.context.cell_id) == len("cell_") + 32
    assert len(snapshot.snapshot_sha256) == 64

    with pytest.raises(TenantControlError, match="repository is not bound"):
        store.snapshot(TENANT, PROJECT, "customer/other")


def test_project_cells_and_namespaces_are_isolated(tmp_path: Path) -> None:
    store = _store(tmp_path)
    second = "prj_product0002"
    store.create_project(TENANT, second)
    store.bind_repository(TENANT, second, "customer/second")

    first_snapshot = store.snapshot(TENANT, PROJECT, REPO)
    second_snapshot = store.snapshot(TENANT, second, "customer/second")
    assert first_snapshot.context.cell_id != second_snapshot.context.cell_id
    assert store.namespace(first_snapshot.context, "artifact") != store.namespace(
        second_snapshot.context, "artifact"
    )
    assert store.namespace(first_snapshot.context, "artifact") != store.namespace(
        first_snapshot.context, "audit"
    )


def test_run_quota_is_transactionally_enforced(tmp_path: Path) -> None:
    store = _store(
        tmp_path,
        quotas=TenantQuotaLimits(
            max_active_runs=1,
            max_projects=2,
            max_repositories_per_project=2,
            max_artifact_bytes=1024,
        ),
    )
    reservation = store.reserve_run(TENANT, PROJECT, REPO, run_key="run-one")
    with pytest.raises(TenantQuotaError, match="active-run quota"):
        store.reserve_run(TENANT, PROJECT, REPO, run_key="run-two")

    store.release_run(reservation.reservation_id)
    second = store.reserve_run(TENANT, PROJECT, REPO, run_key="run-two")
    assert second.run_key == "run-two"


def test_revocation_epoch_invalidates_active_reservations(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.reserve_run(TENANT, PROJECT, REPO, run_key="run-one")
    before = store.snapshot(TENANT, PROJECT, REPO)

    epoch = store.bump_authority_epoch(TENANT, reason="security revocation")
    after = store.snapshot(TENANT, PROJECT, REPO)

    assert epoch == before.context.authority_epoch + 1
    assert after.context.authority_epoch == epoch
    assert after.usage.active_runs == 0
    assert store.verify_authority_event_chain(TENANT) is True


def test_key_rotation_and_quota_change_rotate_authority_epoch(tmp_path: Path) -> None:
    store = _store(tmp_path)
    first = store.snapshot(TENANT, PROJECT, REPO).context.authority_epoch
    second = store.rotate_keyset(
        TENANT,
        keyset_id="keyset_company.v2",
        reason="scheduled key rotation",
    )
    third = store.update_quotas(
        TENANT,
        TenantQuotaLimits(max_active_runs=4),
        reason="license changed",
    )

    assert second == first + 1
    assert third == second + 1
    assert store.snapshot(TENANT, PROJECT, REPO).context.keyset_id == "keyset_company.v2"
    assert store.verify_authority_event_chain(TENANT) is True


def test_suspension_blocks_execution_and_rotates_epoch(tmp_path: Path) -> None:
    store = _store(tmp_path)
    before = store.snapshot(TENANT, PROJECT, REPO).context.authority_epoch
    epoch = store.set_tenant_status(TENANT, "suspended", reason="operator suspension")
    assert epoch == before + 1
    with pytest.raises(TenantNotActiveError):
        store.snapshot(TENANT, PROJECT, REPO)


def test_repository_unbind_rotates_epoch_and_blocks_future_snapshot(tmp_path: Path) -> None:
    store = _store(tmp_path)
    before = store.snapshot(TENANT, PROJECT, REPO).context.authority_epoch
    epoch = store.unbind_repository(TENANT, PROJECT, REPO, reason="project removed repository")
    assert epoch == before + 1
    with pytest.raises(TenantControlError, match="repository is not bound"):
        store.snapshot(TENANT, PROJECT, REPO)


def test_artifact_quota_accounting_is_fail_closed(tmp_path: Path) -> None:
    store = _store(
        tmp_path,
        quotas=TenantQuotaLimits(max_artifact_bytes=10),
    )
    assert store.reserve_artifact_bytes(TENANT, 7) == 7
    with pytest.raises(TenantQuotaError, match="artifact-byte quota"):
        store.reserve_artifact_bytes(TENANT, 4)
    assert store.release_artifact_bytes(TENANT, 2) == 5


def test_export_and_control_state_delete_require_drained_tenant(tmp_path: Path) -> None:
    store = _store(tmp_path)
    exported = store.export_tenant_state(TENANT)
    assert exported["schema_version"] == "foundry.tenant-state-export.v1"
    assert len(str(exported["export_sha256"])) == 64

    with pytest.raises(TenantControlError, match="deleting state"):
        store.hard_delete_tenant_state(TENANT, reason="contract ended")

    store.set_tenant_status(TENANT, "deleting", reason="contract ended")
    receipt = store.hard_delete_tenant_state(TENANT, reason="contract ended")
    assert receipt["schema_version"] == "foundry.tenant-control-deletion-receipt.v1"
    assert len(str(receipt["deletion_receipt_sha256"])) == 64
    assert store.verify_authority_event_chain(TENANT) is True
    with pytest.raises(TenantControlError, match="unknown tenant"):
        store.export_tenant_state(TENANT)


def test_database_symlink_is_rejected(tmp_path: Path) -> None:
    target = tmp_path / "real.sqlite3"
    target.touch()
    link = tmp_path / "tenant.sqlite3"
    link.symlink_to(target)
    with pytest.raises(TenantControlError, match="symlink"):
        SQLiteTenantControlStore(link)
