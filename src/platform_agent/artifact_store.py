from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Final

from platform_agent.tenant_control import SQLiteTenantControlStore, TenantContext, TenantControlError

_MAX_ARTIFACT_BYTES: Final = 2 * 1024 * 1024 * 1024  # local/on-prem backend v1
_CHUNK_BYTES: Final = 1024 * 1024


class ArtifactStoreError(RuntimeError):
    """Raised when artifact isolation, integrity or persistence cannot be guaranteed."""


class ArtifactIntegrityError(ArtifactStoreError):
    """Raised when stored bytes do not match their immutable content identity."""


@dataclass(frozen=True, slots=True)
class ArtifactRecord:
    artifact_id: str
    tenant_id: str
    project_id: str
    cell_id: str
    repository_id: str
    namespace: str
    sha256: str
    size_bytes: int
    name: str
    media_type: str
    source_run_id: str
    execution_grant_id: str
    created_at: str

    def as_dict(self) -> dict[str, object]:
        return {
            "artifact_id": self.artifact_id,
            "tenant_id": self.tenant_id,
            "project_id": self.project_id,
            "cell_id": self.cell_id,
            "repository_id": self.repository_id,
            "namespace": self.namespace,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "name": self.name,
            "media_type": self.media_type,
            "source_run_id": self.source_run_id,
            "execution_grant_id": self.execution_grant_id,
            "created_at": self.created_at,
        }


def _canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256_json(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _utc_now() -> str:
    from datetime import UTC, datetime

    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _secure_root(path: Path) -> Path:
    raw = path.expanduser()
    for candidate in (raw, *raw.parents):
        if candidate.exists() and candidate.is_symlink():
            raise ArtifactStoreError(f"artifact store path traverses symlink: {candidate}")
    resolved = raw.resolve(strict=False)
    resolved.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        resolved.chmod(0o700)
    except OSError as exc:
        raise ArtifactStoreError("failed to restrict artifact store directory") from exc
    return resolved


def _validate_label(value: str, *, field: str, max_length: int = 512) -> str:
    if not isinstance(value, str) or not value or len(value) > max_length:
        raise ValueError(f"{field} must be a non-empty bounded string")
    if any(ord(ch) < 32 or ch == "\x7f" for ch in value):
        raise ValueError(f"{field} contains control characters")
    return value


def _require_prefixed_id(value: str, *, prefix: str, field: str) -> str:
    value = _validate_label(value, field=field, max_length=128)
    if not value.startswith(prefix):
        raise ValueError(f"{field} must use {prefix} prefix")
    return value


def _same_context(left: TenantContext, right: TenantContext) -> bool:
    return _canonical_json(left.as_dict()) == _canonical_json(right.as_dict())


class ContentAddressedArtifactStore:
    """Tenant-isolated, content-addressed local/on-prem artifact backend.

    Objects are addressed by SHA-256 inside a tenant isolation namespace. Writes
    are staged privately and atomically promoted; reads re-hash bytes before they
    are returned. The tenant quota is reserved before a new object is activated,
    so an interrupted process can conservatively over-account but never silently
    exceed its storage allowance. The next operation reconciles that safe
    over-accounting against committed artifact metadata.
    """

    def __init__(self, root: Path, tenant_store: SQLiteTenantControlStore) -> None:
        self.root = _secure_root(root)
        self.tenant_store = tenant_store
        self.index_path = self.root / "artifact-index.sqlite3"
        if self.index_path.exists() and self.index_path.is_symlink():
            raise ArtifactStoreError("artifact index must not be a symlink")
        self._staging = self.root / ".staging"
        self._staging.mkdir(mode=0o700, exist_ok=True)
        self._staging.chmod(0o700)
        self._initialize()
        try:
            self.index_path.chmod(0o600)
        except OSError as exc:
            raise ArtifactStoreError("failed to restrict artifact index permissions") from exc

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.index_path, timeout=30.0, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
        db.execute("PRAGMA busy_timeout = 30000")
        db.execute("PRAGMA journal_mode = WAL")
        return db

    def _initialize(self) -> None:
        with closing(self._connect()) as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS objects (
                    namespace TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
                    relative_path TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (namespace, sha256)
                );
                CREATE TABLE IF NOT EXISTS artifacts (
                    artifact_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    project_id TEXT NOT NULL,
                    cell_id TEXT NOT NULL,
                    repository_id TEXT NOT NULL,
                    namespace TEXT NOT NULL,
                    object_sha256 TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
                    name TEXT NOT NULL,
                    media_type TEXT NOT NULL,
                    source_run_id TEXT NOT NULL,
                    execution_grant_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (namespace, object_sha256)
                        REFERENCES objects(namespace, sha256) ON DELETE RESTRICT
                );
                CREATE INDEX IF NOT EXISTS idx_artifacts_tenant
                    ON artifacts(tenant_id, project_id, created_at, artifact_id);
                CREATE INDEX IF NOT EXISTS idx_artifacts_object
                    ON artifacts(namespace, object_sha256);
                """
            )

    def _object_path(self, namespace: str, digest: str) -> Path:
        if not namespace.startswith("ns_artifact_"):
            raise ArtifactStoreError("invalid artifact namespace")
        if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
            raise ArtifactStoreError("invalid artifact digest")
        directory = self.root / "namespaces" / namespace / "objects" / digest[:2]
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        if directory.is_symlink():
            raise ArtifactStoreError("artifact object directory must not be a symlink")
        directory.chmod(0o700)
        path = directory / digest
        if path.exists() and path.is_symlink():
            raise ArtifactStoreError("artifact object must not be a symlink")
        return path

    @staticmethod
    def _record(row: sqlite3.Row) -> ArtifactRecord:
        return ArtifactRecord(
            artifact_id=str(row["artifact_id"]),
            tenant_id=str(row["tenant_id"]),
            project_id=str(row["project_id"]),
            cell_id=str(row["cell_id"]),
            repository_id=str(row["repository_id"]),
            namespace=str(row["namespace"]),
            sha256=str(row["object_sha256"]),
            size_bytes=int(row["size_bytes"]),
            name=str(row["name"]),
            media_type=str(row["media_type"]),
            source_run_id=str(row["source_run_id"]),
            execution_grant_id=str(row["execution_grant_id"]),
            created_at=str(row["created_at"]),
        )

    def _stage_stream(self, stream: BinaryIO) -> tuple[Path, str, int]:
        temp = self._staging / ("stage_" + secrets.token_hex(16))
        digest = hashlib.sha256()
        size = 0
        try:
            fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as output:
                while True:
                    chunk = stream.read(_CHUNK_BYTES)
                    if not chunk:
                        break
                    if not isinstance(chunk, bytes):
                        raise ArtifactStoreError("artifact stream must return bytes")
                    size += len(chunk)
                    if size > _MAX_ARTIFACT_BYTES:
                        raise ArtifactStoreError("artifact exceeds local backend object-size limit")
                    digest.update(chunk)
                    output.write(chunk)
                output.flush()
                os.fsync(output.fileno())
            return temp, digest.hexdigest(), size
        except Exception:
            temp.unlink(missing_ok=True)
            raise

    def _verify_current_context(self, context: TenantContext, repository_id: str) -> None:
        snapshot = self.tenant_store.snapshot(
            context.tenant_id,
            context.project_id,
            repository_id,
        )
        if not _same_context(snapshot.context, context):
            raise ArtifactStoreError("artifact tenant authority is stale or belongs to another project")

    def _authorize_record(
        self,
        context: TenantContext,
        repository_id: str,
        record: ArtifactRecord,
    ) -> None:
        self._verify_current_context(context, repository_id)
        if (
            record.tenant_id != context.tenant_id
            or record.project_id != context.project_id
            or record.cell_id != context.cell_id
            or record.repository_id != repository_id
        ):
            raise ArtifactStoreError("artifact does not belong to the authorized tenant workspace")
        expected_namespace = self.tenant_store.namespace(context, "artifact")
        if record.namespace != expected_namespace:
            raise ArtifactStoreError("artifact namespace does not match tenant isolation cell")

    def put_bytes(
        self,
        context: TenantContext,
        *,
        repository_id: str,
        data: bytes,
        name: str,
        media_type: str,
        source_run_id: str,
        execution_grant_id: str,
    ) -> ArtifactRecord:
        from io import BytesIO

        if not isinstance(data, bytes):
            raise TypeError("artifact data must be bytes")
        return self.put_stream(
            context,
            repository_id=repository_id,
            stream=BytesIO(data),
            name=name,
            media_type=media_type,
            source_run_id=source_run_id,
            execution_grant_id=execution_grant_id,
        )

    def put_file(
        self,
        context: TenantContext,
        *,
        repository_id: str,
        source: Path,
        name: str,
        media_type: str,
        source_run_id: str,
        execution_grant_id: str,
    ) -> ArtifactRecord:
        if source.is_symlink() or not source.is_file():
            raise ArtifactStoreError("artifact source must be a regular non-symlink file")
        with source.open("rb") as stream:
            return self.put_stream(
                context,
                repository_id=repository_id,
                stream=stream,
                name=name,
                media_type=media_type,
                source_run_id=source_run_id,
                execution_grant_id=execution_grant_id,
            )

    def put_stream(
        self,
        context: TenantContext,
        *,
        repository_id: str,
        stream: BinaryIO,
        name: str,
        media_type: str,
        source_run_id: str,
        execution_grant_id: str,
    ) -> ArtifactRecord:
        name = _validate_label(name, field="artifact name")
        media_type = _validate_label(media_type, field="media_type", max_length=256)
        source_run_id = _require_prefixed_id(source_run_id, prefix="run_", field="source_run_id")
        execution_grant_id = _require_prefixed_id(
            execution_grant_id, prefix="sgr_", field="execution_grant_id"
        )
        self._verify_current_context(context, repository_id)
        self.reconcile_tenant_accounting(context.tenant_id)
        namespace = self.tenant_store.namespace(context, "artifact")
        staged, digest, size = self._stage_stream(stream)
        immutable = {
            "schema_version": "foundry.artifact.v1",
            "tenant_context": context.as_dict(),
            "repository_id": repository_id,
            "namespace": namespace,
            "sha256": digest,
            "size_bytes": size,
            "name": name,
            "media_type": media_type,
            "source_run_id": source_run_id,
            "execution_grant_id": execution_grant_id,
        }
        artifact_id = "art_" + _sha256_json(immutable)[:32]
        object_path = self._object_path(namespace, digest)
        reserved = False
        created_object = False
        try:
            with closing(self._connect()) as db:
                db.execute("BEGIN IMMEDIATE")
                existing = db.execute(
                    "SELECT * FROM artifacts WHERE artifact_id=?", (artifact_id,)
                ).fetchone()
                if existing is not None:
                    db.rollback()
                    staged.unlink(missing_ok=True)
                    record = self._record(existing)
                    self._authorize_record(context, repository_id, record)
                    self._verify_object(record.namespace, record.sha256, record.size_bytes)
                    return record

                object_row = db.execute(
                    "SELECT size_bytes FROM objects WHERE namespace=? AND sha256=?",
                    (namespace, digest),
                ).fetchone()
                if object_row is None:
                    self.tenant_store.reserve_artifact_bytes(context.tenant_id, size)
                    reserved = True
                    if object_path.exists():
                        self._verify_path_bytes(object_path, digest, size)
                        staged.unlink(missing_ok=True)
                    else:
                        os.replace(staged, object_path)
                        object_path.chmod(0o600)
                        created_object = True
                    db.execute(
                        "INSERT INTO objects (namespace,sha256,size_bytes,relative_path,created_at) VALUES (?,?,?,?,?)",
                        (
                            namespace,
                            digest,
                            size,
                            object_path.relative_to(self.root).as_posix(),
                            _utc_now(),
                        ),
                    )
                else:
                    if int(object_row["size_bytes"]) != size:
                        raise ArtifactIntegrityError("content-addressed object size mismatch")
                    staged.unlink(missing_ok=True)
                    self._verify_object(namespace, digest, size)

                created_at = _utc_now()
                db.execute(
                    "INSERT INTO artifacts (artifact_id,tenant_id,project_id,cell_id,repository_id,namespace,object_sha256,size_bytes,name,media_type,source_run_id,execution_grant_id,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        artifact_id,
                        context.tenant_id,
                        context.project_id,
                        context.cell_id,
                        repository_id,
                        namespace,
                        digest,
                        size,
                        name,
                        media_type,
                        source_run_id,
                        execution_grant_id,
                        created_at,
                    ),
                )
                db.commit()
                return ArtifactRecord(
                    artifact_id=artifact_id,
                    tenant_id=context.tenant_id,
                    project_id=context.project_id,
                    cell_id=context.cell_id,
                    repository_id=repository_id,
                    namespace=namespace,
                    sha256=digest,
                    size_bytes=size,
                    name=name,
                    media_type=media_type,
                    source_run_id=source_run_id,
                    execution_grant_id=execution_grant_id,
                    created_at=created_at,
                )
        except Exception:
            staged.unlink(missing_ok=True)
            if created_object:
                object_path.unlink(missing_ok=True)
            if reserved:
                try:
                    self.tenant_store.release_artifact_bytes(context.tenant_id, size)
                except Exception as rollback_exc:
                    raise ArtifactStoreError(
                        "artifact write failed and quota rollback also failed; reconciliation required"
                    ) from rollback_exc
            raise

    def _verify_path_bytes(self, path: Path, digest: str, size_bytes: int) -> None:
        if path.is_symlink() or not path.is_file():
            raise ArtifactIntegrityError("artifact object is not a regular file")
        hasher = hashlib.sha256()
        size = 0
        with path.open("rb") as stream:
            while chunk := stream.read(_CHUNK_BYTES):
                size += len(chunk)
                hasher.update(chunk)
        if size != size_bytes or hasher.hexdigest() != digest:
            raise ArtifactIntegrityError("artifact object content hash mismatch")

    def _verify_object(self, namespace: str, digest: str, size_bytes: int) -> Path:
        path = self._object_path(namespace, digest)
        self._verify_path_bytes(path, digest, size_bytes)
        return path

    def _get_record_unchecked(self, artifact_id: str) -> ArtifactRecord:
        with closing(self._connect()) as db:
            row = db.execute("SELECT * FROM artifacts WHERE artifact_id=?", (artifact_id,)).fetchone()
        if row is None:
            raise ArtifactStoreError("unknown artifact")
        return self._record(row)

    def get_record(
        self,
        context: TenantContext,
        *,
        repository_id: str,
        artifact_id: str,
    ) -> ArtifactRecord:
        record = self._get_record_unchecked(artifact_id)
        self._authorize_record(context, repository_id, record)
        return record

    def read_bytes(
        self,
        context: TenantContext,
        *,
        repository_id: str,
        artifact_id: str,
    ) -> bytes:
        record = self.get_record(context, repository_id=repository_id, artifact_id=artifact_id)
        path = self._verify_object(record.namespace, record.sha256, record.size_bytes)
        return path.read_bytes()

    def list_project(
        self,
        context: TenantContext,
        *,
        repository_id: str,
    ) -> tuple[ArtifactRecord, ...]:
        self._verify_current_context(context, repository_id)
        with closing(self._connect()) as db:
            rows = db.execute(
                "SELECT * FROM artifacts WHERE tenant_id=? AND project_id=? AND cell_id=? AND repository_id=? ORDER BY created_at,artifact_id",
                (context.tenant_id, context.project_id, context.cell_id, repository_id),
            ).fetchall()
        return tuple(self._record(row) for row in rows)

    def export_project_manifest(
        self,
        context: TenantContext,
        *,
        repository_id: str,
    ) -> dict[str, object]:
        records = [
            record.as_dict() for record in self.list_project(context, repository_id=repository_id)
        ]
        body = {
            "schema_version": "foundry.artifact-manifest.v1",
            "tenant_context": context.as_dict(),
            "repository_id": repository_id,
            "artifacts": records,
        }
        return {**body, "manifest_sha256": _sha256_json(body)}

    def delete_artifact(
        self,
        context: TenantContext,
        *,
        repository_id: str,
        artifact_id: str,
    ) -> None:
        record = self.get_record(context, repository_id=repository_id, artifact_id=artifact_id)
        delete_object = False
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                db.execute("DELETE FROM artifacts WHERE artifact_id=?", (artifact_id,))
                remaining = int(
                    db.execute(
                        "SELECT COUNT(*) FROM artifacts WHERE namespace=? AND object_sha256=?",
                        (record.namespace, record.sha256),
                    ).fetchone()[0]
                )
                if remaining == 0:
                    db.execute(
                        "DELETE FROM objects WHERE namespace=? AND sha256=?",
                        (record.namespace, record.sha256),
                    )
                    delete_object = True
                db.commit()
            except Exception:
                db.rollback()
                raise

        if delete_object:
            path = self._object_path(record.namespace, record.sha256)
            path.unlink(missing_ok=True)
            self.tenant_store.release_artifact_bytes(record.tenant_id, record.size_bytes)

    def purge_tenant(self, tenant_id: str) -> dict[str, object]:
        """Delete all tenant artifacts before tenant control-state hard deletion."""
        self.reconcile_tenant_accounting(tenant_id)
        with closing(self._connect()) as db:
            rows = db.execute(
                "SELECT DISTINCT namespace,object_sha256,size_bytes FROM artifacts WHERE tenant_id=?",
                (tenant_id,),
            ).fetchall()
            artifact_count = int(
                db.execute("SELECT COUNT(*) FROM artifacts WHERE tenant_id=?", (tenant_id,)).fetchone()[0]
            )
            total_bytes = sum(int(row["size_bytes"]) for row in rows)
            db.execute("BEGIN IMMEDIATE")
            try:
                db.execute("DELETE FROM artifacts WHERE tenant_id=?", (tenant_id,))
                for row in rows:
                    db.execute(
                        "DELETE FROM objects WHERE namespace=? AND sha256=?",
                        (str(row["namespace"]), str(row["object_sha256"])),
                    )
                db.commit()
            except Exception:
                db.rollback()
                raise

        for row in rows:
            self._object_path(str(row["namespace"]), str(row["object_sha256"])).unlink(
                missing_ok=True
            )
        if total_bytes:
            self.tenant_store.release_artifact_bytes(tenant_id, total_bytes)
        body = {
            "schema_version": "foundry.artifact-deletion-receipt.v1",
            "tenant_id": tenant_id,
            "artifact_count": artifact_count,
            "released_bytes": total_bytes,
            "deleted_at": _utc_now(),
        }
        return {**body, "receipt_sha256": _sha256_json(body)}

    def reconcile_tenant_accounting(self, tenant_id: str) -> int:
        """Repair conservative quota accounting left by an interrupted write/delete."""
        with closing(self._connect()) as db:
            expected = int(
                db.execute(
                    "SELECT COALESCE(SUM(size_bytes),0) FROM (SELECT DISTINCT namespace,object_sha256,size_bytes FROM artifacts WHERE tenant_id=?)",
                    (tenant_id,),
                ).fetchone()[0]
            )
        exported = self.tenant_store.export_tenant_state(tenant_id)
        tenant = exported.get("tenant")
        if not isinstance(tenant, dict):
            raise TenantControlError("tenant export is malformed")
        actual = tenant.get("artifact_bytes")
        if not isinstance(actual, int) or isinstance(actual, bool) or actual < 0:
            raise TenantControlError("tenant artifact accounting is malformed")
        if expected > actual:
            self.tenant_store.reserve_artifact_bytes(tenant_id, expected - actual)
        elif actual > expected:
            self.tenant_store.release_artifact_bytes(tenant_id, actual - expected)
        return expected

    def scrub_tenant(self, tenant_id: str) -> dict[str, object]:
        """Re-hash every referenced object and return an integrity receipt."""
        with closing(self._connect()) as db:
            rows = db.execute(
                "SELECT DISTINCT namespace,object_sha256,size_bytes FROM artifacts WHERE tenant_id=? ORDER BY namespace,object_sha256",
                (tenant_id,),
            ).fetchall()
        verified: list[dict[str, object]] = []
        for row in rows:
            namespace = str(row["namespace"])
            digest = str(row["object_sha256"])
            size = int(row["size_bytes"])
            self._verify_object(namespace, digest, size)
            verified.append({"namespace": namespace, "sha256": digest, "size_bytes": size})
        body = {
            "schema_version": "foundry.artifact-scrub.v1",
            "tenant_id": tenant_id,
            "objects": verified,
            "verified_at": _utc_now(),
        }
        return {**body, "scrub_sha256": _sha256_json(body)}
