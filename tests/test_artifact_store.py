from __future__ import annotations

from pathlib import Path

import pytest

from platform_agent.artifact_store import (
    ArtifactIntegrityError,
    ArtifactStoreError,
    ContentAddressedArtifactStore,
)
from platform_agent.tenant_control import SQLiteTenantControlStore

REPO = "foundry-engineering/example"


def _tenant(tmp_path: Path, suffix: str):
    control = SQLiteTenantControlStore(tmp_path / f"control-{suffix}.sqlite3")
    tenant_id = f"tnt_{suffix}00000001"
    project_id = f"prj_{suffix}00000001"
    control.create_tenant(tenant_id, keyset_id=f"keyset_{suffix}.v1")
    context = control.create_project(tenant_id, project_id)
    control.bind_repository(tenant_id, project_id, REPO)
    return control, context


def _put(store: ContentAddressedArtifactStore, context, *, name: str = "result.txt"):
    return store.put_bytes(
        context,
        repository_id=REPO,
        data=b"verified artifact\n",
        name=name,
        media_type="text/plain",
        source_run_id="run_" + "a" * 32,
        execution_grant_id="sgr_" + "b" * 32,
    )


def _artifact_bytes(control: SQLiteTenantControlStore, tenant_id: str) -> int:
    exported = control.export_tenant_state(tenant_id)
    tenant = exported["tenant"]
    assert isinstance(tenant, dict)
    value = tenant["artifact_bytes"]
    assert isinstance(value, int)
    return value


def test_content_addressed_artifacts_deduplicate_physical_bytes(tmp_path: Path) -> None:
    control, context = _tenant(tmp_path, "alpha")
    store = ContentAddressedArtifactStore(tmp_path / "artifacts", control)

    first = _put(store, context, name="one.txt")
    second = _put(store, context, name="two.txt")

    assert first.artifact_id != second.artifact_id
    assert first.sha256 == second.sha256
    assert _artifact_bytes(control, context.tenant_id) == len(b"verified artifact\n")
    assert store.read_bytes(context, repository_id=REPO, artifact_id=first.artifact_id) == b"verified artifact\n"
    assert len(store.list_project(context, repository_id=REPO)) == 2


def test_cross_tenant_artifact_read_fails_closed(tmp_path: Path) -> None:
    control = SQLiteTenantControlStore(tmp_path / "control.sqlite3")
    control.create_tenant("tnt_alpha00000001", keyset_id="keyset_alpha.v1")
    alpha = control.create_project("tnt_alpha00000001", "prj_alpha00000001")
    control.bind_repository(alpha.tenant_id, alpha.project_id, REPO)
    control.create_tenant("tnt_beta00000001", keyset_id="keyset_beta.v1")
    beta = control.create_project("tnt_beta00000001", "prj_beta00000001")
    control.bind_repository(beta.tenant_id, beta.project_id, REPO)
    store = ContentAddressedArtifactStore(tmp_path / "artifacts", control)
    record = _put(store, alpha)

    with pytest.raises(ArtifactStoreError, match="authorized tenant workspace"):
        store.read_bytes(beta, repository_id=REPO, artifact_id=record.artifact_id)


def test_stale_tenant_epoch_cannot_read_artifact(tmp_path: Path) -> None:
    control, context = _tenant(tmp_path, "gamma")
    store = ContentAddressedArtifactStore(tmp_path / "artifacts", control)
    record = _put(store, context)
    control.bump_authority_epoch(context.tenant_id, reason="security revocation")

    with pytest.raises(ArtifactStoreError, match="stale"):
        store.read_bytes(context, repository_id=REPO, artifact_id=record.artifact_id)


def test_artifact_tampering_is_detected_on_read_and_scrub(tmp_path: Path) -> None:
    control, context = _tenant(tmp_path, "delta")
    store = ContentAddressedArtifactStore(tmp_path / "artifacts", control)
    record = _put(store, context)
    path = store._object_path(record.namespace, record.sha256)
    path.write_bytes(b"tampered\n")

    with pytest.raises(ArtifactIntegrityError, match="content hash mismatch"):
        store.read_bytes(context, repository_id=REPO, artifact_id=record.artifact_id)
    with pytest.raises(ArtifactIntegrityError, match="content hash mismatch"):
        store.scrub_tenant(context.tenant_id)


def test_shared_object_quota_released_only_after_last_reference(tmp_path: Path) -> None:
    control, context = _tenant(tmp_path, "epsilon")
    store = ContentAddressedArtifactStore(tmp_path / "artifacts", control)
    first = _put(store, context, name="one.txt")
    second = _put(store, context, name="two.txt")
    size = first.size_bytes

    store.delete_artifact(context, repository_id=REPO, artifact_id=first.artifact_id)
    assert _artifact_bytes(control, context.tenant_id) == size
    store.delete_artifact(context, repository_id=REPO, artifact_id=second.artifact_id)
    assert _artifact_bytes(control, context.tenant_id) == 0


def test_reconcile_repairs_conservative_quota_overcount(tmp_path: Path) -> None:
    control, context = _tenant(tmp_path, "zeta")
    store = ContentAddressedArtifactStore(tmp_path / "artifacts", control)
    record = _put(store, context)
    control.reserve_artifact_bytes(context.tenant_id, 123)

    expected = store.reconcile_tenant_accounting(context.tenant_id)

    assert expected == record.size_bytes
    assert _artifact_bytes(control, context.tenant_id) == record.size_bytes


def test_export_and_tenant_purge_are_content_addressed_and_accounted(tmp_path: Path) -> None:
    control, context = _tenant(tmp_path, "theta")
    store = ContentAddressedArtifactStore(tmp_path / "artifacts", control)
    _put(store, context)

    manifest = store.export_project_manifest(context, repository_id=REPO)
    assert manifest["schema_version"] == "foundry.artifact-manifest.v1"
    assert isinstance(manifest["manifest_sha256"], str)

    receipt = store.purge_tenant(context.tenant_id)
    assert receipt["artifact_count"] == 1
    assert isinstance(receipt["receipt_sha256"], str)
    assert _artifact_bytes(control, context.tenant_id) == 0


def test_symlink_store_root_is_rejected(tmp_path: Path) -> None:
    target = tmp_path / "real"
    target.mkdir()
    link = tmp_path / "link"
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("symlinks unavailable on this platform")

    control, _ = _tenant(tmp_path, "iota")
    with pytest.raises(ArtifactStoreError, match="symlink"):
        ContentAddressedArtifactStore(link, control)
