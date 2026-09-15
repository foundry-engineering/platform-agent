from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, Literal

TenantStatus = Literal["active", "suspended", "deleting", "deleted"]
ProjectStatus = Literal["active", "suspended", "deleting", "deleted"]
NamespaceKind = Literal["policy", "artifact", "audit", "receipt", "workspace", "key-metadata"]

_TENANT_STATUSES: Final = frozenset({"active", "suspended", "deleting", "deleted"})
_PROJECT_STATUSES: Final = frozenset({"active", "suspended", "deleting", "deleted"})
_NAMESPACE_KINDS: Final = frozenset(
    {"policy", "artifact", "audit", "receipt", "workspace", "key-metadata"}
)


class TenantControlError(RuntimeError):
    """Base error for tenant control-plane state failures."""


class TenantNotActiveError(TenantControlError):
    """Raised when execution is attempted for a non-active tenant/project."""


class TenantQuotaError(TenantControlError):
    """Raised when a tenant quota cannot be reserved."""


@dataclass(frozen=True, slots=True)
class TenantQuotaLimits:
    max_active_runs: int = 32
    max_projects: int = 64
    max_repositories_per_project: int = 64
    max_artifact_bytes: int = 107_374_182_400  # 100 GiB

    def __post_init__(self) -> None:
        values = (
            self.max_active_runs,
            self.max_projects,
            self.max_repositories_per_project,
            self.max_artifact_bytes,
        )
        if any(not isinstance(value, int) or isinstance(value, bool) or value < 1 for value in values):
            raise ValueError("tenant quota limits must be positive integers")

    def as_dict(self) -> dict[str, int]:
        return {
            "max_active_runs": self.max_active_runs,
            "max_projects": self.max_projects,
            "max_repositories_per_project": self.max_repositories_per_project,
            "max_artifact_bytes": self.max_artifact_bytes,
        }


@dataclass(frozen=True, slots=True)
class TenantQuotaUsage:
    active_runs: int
    artifact_bytes: int

    def as_dict(self) -> dict[str, int]:
        return {
            "active_runs": self.active_runs,
            "artifact_bytes": self.artifact_bytes,
        }


@dataclass(frozen=True, slots=True)
class TenantContext:
    tenant_id: str
    project_id: str
    cell_id: str
    authority_epoch: int
    keyset_id: str

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": "tenant-context.v1",
            "tenant_id": self.tenant_id,
            "project_id": self.project_id,
            "cell_id": self.cell_id,
            "authority_epoch": self.authority_epoch,
            "keyset_id": self.keyset_id,
        }


@dataclass(frozen=True, slots=True)
class TenantExecutionSnapshot:
    context: TenantContext
    repository_id: str
    tenant_status: TenantStatus
    project_status: ProjectStatus
    quotas: TenantQuotaLimits
    usage: TenantQuotaUsage
    snapshot_sha256: str

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": "foundry.tenant-execution-snapshot.v1",
            "tenant_context": self.context.as_dict(),
            "repository_id": self.repository_id,
            "tenant_status": self.tenant_status,
            "project_status": self.project_status,
            "quotas": self.quotas.as_dict(),
            "usage": self.usage.as_dict(),
            "snapshot_sha256": self.snapshot_sha256,
        }


@dataclass(frozen=True, slots=True)
class RunReservation:
    reservation_id: str
    tenant_id: str
    project_id: str
    run_key: str


def _utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _require_identifier(value: str, *, prefix: str, field: str) -> str:
    if not isinstance(value, str) or not value.startswith(prefix) or len(value) < len(prefix) + 8:
        raise ValueError(f"{field} must start with {prefix!r} and contain at least 8 id characters")
    tail = value[len(prefix) :]
    if any(ch not in "abcdefghijklmnopqrstuvwxyz0123456789_-" for ch in tail):
        raise ValueError(f"{field} contains unsupported characters")
    return value


def _require_keyset_id(value: str) -> str:
    if not value.startswith("keyset_") or len(value) < 11:
        raise ValueError("keyset_id must use keyset_ prefix")
    if any(ch not in "abcdefghijklmnopqrstuvwxyz0123456789._-" for ch in value[7:]):
        raise ValueError("keyset_id contains unsupported characters")
    return value


def _require_repository_id(value: str) -> str:
    parts = value.split("/")
    if len(parts) != 2 or any(not part for part in parts):
        raise ValueError("repository_id must use owner/repository form")
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-")
    if any(any(ch not in allowed for ch in part) for part in parts):
        raise ValueError("repository_id contains unsupported characters")
    return value


class SQLiteTenantControlStore:
    """Persistent single-node/on-prem tenant control plane.

    All quota reservations and authority-epoch mutations use SQLite immediate
    transactions so two local workers cannot over-admit the same quota. The
    interface is intentionally storage-agnostic at call sites; distributed
    deployments can implement the same semantics with a transactional database.
    """

    def __init__(self, path: Path) -> None:
        self.path = path.resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.is_symlink():
            raise TenantControlError("tenant database path must not be a symlink")
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30.0, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 30000")
        connection.execute("PRAGMA journal_mode = WAL")
        return connection

    def _initialize(self) -> None:
        with closing(self._connect()) as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS tenants (
                    tenant_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL CHECK (status IN ('active','suspended','deleting','deleted')),
                    authority_epoch INTEGER NOT NULL CHECK (authority_epoch >= 1),
                    keyset_id TEXT NOT NULL,
                    quotas_json TEXT NOT NULL,
                    artifact_bytes INTEGER NOT NULL DEFAULT 0 CHECK (artifact_bytes >= 0),
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS projects (
                    project_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
                    status TEXT NOT NULL CHECK (status IN ('active','suspended','deleting','deleted')),
                    cell_id TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS repositories (
                    tenant_id TEXT NOT NULL,
                    project_id TEXT NOT NULL REFERENCES projects(project_id) ON DELETE CASCADE,
                    repository_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (tenant_id, project_id, repository_id),
                    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS run_reservations (
                    reservation_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
                    project_id TEXT NOT NULL REFERENCES projects(project_id) ON DELETE CASCADE,
                    run_key TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE (tenant_id, run_key)
                );
                CREATE INDEX IF NOT EXISTS idx_projects_tenant ON projects(tenant_id);
                CREATE INDEX IF NOT EXISTS idx_repositories_project ON repositories(tenant_id, project_id);
                CREATE INDEX IF NOT EXISTS idx_runs_tenant ON run_reservations(tenant_id);
                """
            )

    def create_tenant(
        self,
        tenant_id: str,
        *,
        keyset_id: str,
        quotas: TenantQuotaLimits | None = None,
    ) -> None:
        tenant_id = _require_identifier(tenant_id, prefix="tnt_", field="tenant_id")
        keyset_id = _require_keyset_id(keyset_id)
        limits = quotas or TenantQuotaLimits()
        now = _utc_now()
        with closing(self._connect()) as db:
            try:
                db.execute(
                    "INSERT INTO tenants (tenant_id,status,authority_epoch,keyset_id,quotas_json,created_at,updated_at) VALUES (?,?,?,?,?,?,?)",
                    (tenant_id, "active", 1, keyset_id, _canonical_json(limits.as_dict()), now, now),
                )
            except sqlite3.IntegrityError as exc:
                raise TenantControlError(f"tenant already exists or is invalid: {tenant_id}") from exc

    def create_project(self, tenant_id: str, project_id: str) -> TenantContext:
        tenant_id = _require_identifier(tenant_id, prefix="tnt_", field="tenant_id")
        project_id = _require_identifier(project_id, prefix="prj_", field="project_id")
        now = _utc_now()
        cell_id = "cell_" + secrets.token_hex(16)
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                tenant = db.execute(
                    "SELECT status,authority_epoch,keyset_id,quotas_json FROM tenants WHERE tenant_id=?",
                    (tenant_id,),
                ).fetchone()
                if tenant is None:
                    raise TenantControlError(f"unknown tenant: {tenant_id}")
                if tenant["status"] != "active":
                    raise TenantNotActiveError(f"tenant is not active: {tenant_id}")
                limits = TenantQuotaLimits(**json.loads(str(tenant["quotas_json"])))
                count = int(
                    db.execute(
                        "SELECT COUNT(*) FROM projects WHERE tenant_id=? AND status != 'deleted'",
                        (tenant_id,),
                    ).fetchone()[0]
                )
                if count >= limits.max_projects:
                    raise TenantQuotaError("tenant project quota exceeded")
                db.execute(
                    "INSERT INTO projects (project_id,tenant_id,status,cell_id,created_at,updated_at) VALUES (?,?,?,?,?,?)",
                    (project_id, tenant_id, "active", cell_id, now, now),
                )
                db.commit()
            except Exception:
                db.rollback()
                raise
        return TenantContext(
            tenant_id=tenant_id,
            project_id=project_id,
            cell_id=cell_id,
            authority_epoch=int(tenant["authority_epoch"]),
            keyset_id=str(tenant["keyset_id"]),
        )

    def bind_repository(self, tenant_id: str, project_id: str, repository_id: str) -> None:
        tenant_id = _require_identifier(tenant_id, prefix="tnt_", field="tenant_id")
        project_id = _require_identifier(project_id, prefix="prj_", field="project_id")
        repository_id = _require_repository_id(repository_id)
        now = _utc_now()
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                tenant = db.execute(
                    "SELECT status,quotas_json FROM tenants WHERE tenant_id=?", (tenant_id,)
                ).fetchone()
                project = db.execute(
                    "SELECT tenant_id,status FROM projects WHERE project_id=?", (project_id,)
                ).fetchone()
                if tenant is None or project is None or str(project["tenant_id"]) != tenant_id:
                    raise TenantControlError("unknown tenant/project binding")
                if tenant["status"] != "active" or project["status"] != "active":
                    raise TenantNotActiveError("tenant/project is not active")
                limits = TenantQuotaLimits(**json.loads(str(tenant["quotas_json"])))
                count = int(
                    db.execute(
                        "SELECT COUNT(*) FROM repositories WHERE tenant_id=? AND project_id=?",
                        (tenant_id, project_id),
                    ).fetchone()[0]
                )
                exists = db.execute(
                    "SELECT 1 FROM repositories WHERE tenant_id=? AND project_id=? AND repository_id=?",
                    (tenant_id, project_id, repository_id),
                ).fetchone()
                if exists is not None:
                    db.rollback()
                    return
                if count >= limits.max_repositories_per_project:
                    raise TenantQuotaError("project repository quota exceeded")
                db.execute(
                    "INSERT INTO repositories (tenant_id,project_id,repository_id,created_at) VALUES (?,?,?,?)",
                    (tenant_id, project_id, repository_id, now),
                )
                db.commit()
            except Exception:
                if db.in_transaction:
                    db.rollback()
                raise

    def snapshot(
        self,
        tenant_id: str,
        project_id: str,
        repository_id: str,
    ) -> TenantExecutionSnapshot:
        repository_id = _require_repository_id(repository_id)
        with closing(self._connect()) as db:
            tenant = db.execute(
                "SELECT status,authority_epoch,keyset_id,quotas_json,artifact_bytes FROM tenants WHERE tenant_id=?",
                (tenant_id,),
            ).fetchone()
            project = db.execute(
                "SELECT tenant_id,status,cell_id FROM projects WHERE project_id=?",
                (project_id,),
            ).fetchone()
            repo = db.execute(
                "SELECT 1 FROM repositories WHERE tenant_id=? AND project_id=? AND repository_id=?",
                (tenant_id, project_id, repository_id),
            ).fetchone()
            active_runs = int(
                db.execute(
                    "SELECT COUNT(*) FROM run_reservations WHERE tenant_id=?", (tenant_id,)
                ).fetchone()[0]
            )
        if tenant is None or project is None or str(project["tenant_id"]) != tenant_id:
            raise TenantControlError("unknown tenant/project binding")
        if repo is None:
            raise TenantControlError("repository is not bound to tenant project")
        tenant_status = str(tenant["status"])
        project_status = str(project["status"])
        if tenant_status not in _TENANT_STATUSES or project_status not in _PROJECT_STATUSES:
            raise TenantControlError("stored tenant/project status is invalid")
        if tenant_status != "active" or project_status != "active":
            raise TenantNotActiveError("tenant/project is not active")
        quotas = TenantQuotaLimits(**json.loads(str(tenant["quotas_json"])))
        usage = TenantQuotaUsage(
            active_runs=active_runs,
            artifact_bytes=int(tenant["artifact_bytes"]),
        )
        context = TenantContext(
            tenant_id=tenant_id,
            project_id=project_id,
            cell_id=str(project["cell_id"]),
            authority_epoch=int(tenant["authority_epoch"]),
            keyset_id=str(tenant["keyset_id"]),
        )
        material = {
            "schema_version": "foundry.tenant-execution-snapshot.v1",
            "tenant_context": context.as_dict(),
            "repository_id": repository_id,
            "tenant_status": tenant_status,
            "project_status": project_status,
            "quotas": quotas.as_dict(),
            "usage": usage.as_dict(),
        }
        return TenantExecutionSnapshot(
            context=context,
            repository_id=repository_id,
            tenant_status=cast(TenantStatus, tenant_status),
            project_status=cast(ProjectStatus, project_status),
            quotas=quotas,
            usage=usage,
            snapshot_sha256=_sha256(material),
        )

    def reserve_run(
        self,
        tenant_id: str,
        project_id: str,
        repository_id: str,
        *,
        run_key: str,
    ) -> RunReservation:
        if not run_key or len(run_key) > 256:
            raise ValueError("run_key must be a non-empty bounded string")
        snapshot = self.snapshot(tenant_id, project_id, repository_id)
        reservation_id = "rsv_" + secrets.token_hex(16)
        now = _utc_now()
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                tenant = db.execute(
                    "SELECT status,quotas_json FROM tenants WHERE tenant_id=?", (tenant_id,)
                ).fetchone()
                project = db.execute(
                    "SELECT status,tenant_id FROM projects WHERE project_id=?", (project_id,)
                ).fetchone()
                if (
                    tenant is None
                    or project is None
                    or str(project["tenant_id"]) != tenant_id
                    or tenant["status"] != "active"
                    or project["status"] != "active"
                ):
                    raise TenantNotActiveError("tenant/project became inactive before reservation")
                limits = TenantQuotaLimits(**json.loads(str(tenant["quotas_json"])))
                active = int(
                    db.execute(
                        "SELECT COUNT(*) FROM run_reservations WHERE tenant_id=?", (tenant_id,)
                    ).fetchone()[0]
                )
                if active >= limits.max_active_runs:
                    raise TenantQuotaError("tenant active-run quota exceeded")
                repo = db.execute(
                    "SELECT 1 FROM repositories WHERE tenant_id=? AND project_id=? AND repository_id=?",
                    (tenant_id, project_id, repository_id),
                ).fetchone()
                if repo is None:
                    raise TenantControlError("repository binding disappeared before reservation")
                try:
                    db.execute(
                        "INSERT INTO run_reservations (reservation_id,tenant_id,project_id,run_key,created_at) VALUES (?,?,?,?,?)",
                        (reservation_id, tenant_id, project_id, run_key, now),
                    )
                except sqlite3.IntegrityError as exc:
                    raise TenantControlError("run_key already reserved for tenant") from exc
                db.commit()
            except Exception:
                db.rollback()
                raise
        if snapshot.context.authority_epoch < 1:
            raise TenantControlError("invalid authority epoch")
        return RunReservation(
            reservation_id=reservation_id,
            tenant_id=tenant_id,
            project_id=project_id,
            run_key=run_key,
        )

    def release_run(self, reservation_id: str) -> None:
        if not reservation_id.startswith("rsv_"):
            raise ValueError("invalid reservation_id")
        with closing(self._connect()) as db:
            cursor = db.execute(
                "DELETE FROM run_reservations WHERE reservation_id=?", (reservation_id,)
            )
            if cursor.rowcount != 1:
                raise TenantControlError("unknown run reservation")

    def reserve_artifact_bytes(self, tenant_id: str, byte_count: int) -> int:
        if not isinstance(byte_count, int) or isinstance(byte_count, bool) or byte_count < 0:
            raise ValueError("artifact byte_count must be a non-negative integer")
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                tenant = db.execute(
                    "SELECT status,quotas_json,artifact_bytes FROM tenants WHERE tenant_id=?",
                    (tenant_id,),
                ).fetchone()
                if tenant is None:
                    raise TenantControlError("unknown tenant")
                if tenant["status"] != "active":
                    raise TenantNotActiveError("tenant is not active")
                limits = TenantQuotaLimits(**json.loads(str(tenant["quotas_json"])))
                current = int(tenant["artifact_bytes"])
                updated = current + byte_count
                if updated > limits.max_artifact_bytes:
                    raise TenantQuotaError("tenant artifact-byte quota exceeded")
                db.execute(
                    "UPDATE tenants SET artifact_bytes=?,updated_at=? WHERE tenant_id=?",
                    (updated, _utc_now(), tenant_id),
                )
                db.commit()
                return updated
            except Exception:
                db.rollback()
                raise

    def release_artifact_bytes(self, tenant_id: str, byte_count: int) -> int:
        if not isinstance(byte_count, int) or isinstance(byte_count, bool) or byte_count < 0:
            raise ValueError("artifact byte_count must be a non-negative integer")
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                tenant = db.execute(
                    "SELECT artifact_bytes FROM tenants WHERE tenant_id=?", (tenant_id,)
                ).fetchone()
                if tenant is None:
                    raise TenantControlError("unknown tenant")
                updated = int(tenant["artifact_bytes"]) - byte_count
                if updated < 0:
                    raise TenantControlError("artifact accounting would become negative")
                db.execute(
                    "UPDATE tenants SET artifact_bytes=?,updated_at=? WHERE tenant_id=?",
                    (updated, _utc_now(), tenant_id),
                )
                db.commit()
                return updated
            except Exception:
                db.rollback()
                raise

    def bump_authority_epoch(self, tenant_id: str, *, reason: str) -> int:
        if not reason.strip():
            raise ValueError("revocation reason is required")
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                tenant = db.execute(
                    "SELECT authority_epoch FROM tenants WHERE tenant_id=?", (tenant_id,)
                ).fetchone()
                if tenant is None:
                    raise TenantControlError("unknown tenant")
                updated = int(tenant["authority_epoch"]) + 1
                db.execute(
                    "UPDATE tenants SET authority_epoch=?,updated_at=? WHERE tenant_id=?",
                    (updated, _utc_now(), tenant_id),
                )
                db.execute(
                    "DELETE FROM run_reservations WHERE tenant_id=?", (tenant_id,)
                )
                db.commit()
                return updated
            except Exception:
                db.rollback()
                raise

    def rotate_keyset(self, tenant_id: str, *, keyset_id: str) -> int:
        keyset_id = _require_keyset_id(keyset_id)
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                tenant = db.execute(
                    "SELECT authority_epoch FROM tenants WHERE tenant_id=?", (tenant_id,)
                ).fetchone()
                if tenant is None:
                    raise TenantControlError("unknown tenant")
                epoch = int(tenant["authority_epoch"]) + 1
                db.execute(
                    "UPDATE tenants SET keyset_id=?,authority_epoch=?,updated_at=? WHERE tenant_id=?",
                    (keyset_id, epoch, _utc_now(), tenant_id),
                )
                db.execute("DELETE FROM run_reservations WHERE tenant_id=?", (tenant_id,))
                db.commit()
                return epoch
            except Exception:
                db.rollback()
                raise

    def set_tenant_status(self, tenant_id: str, status: TenantStatus) -> int:
        if status not in _TENANT_STATUSES:
            raise ValueError("invalid tenant status")
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                tenant = db.execute(
                    "SELECT authority_epoch,status FROM tenants WHERE tenant_id=?", (tenant_id,)
                ).fetchone()
                if tenant is None:
                    raise TenantControlError("unknown tenant")
                epoch = int(tenant["authority_epoch"])
                if str(tenant["status"]) != status:
                    epoch += 1
                db.execute(
                    "UPDATE tenants SET status=?,authority_epoch=?,updated_at=? WHERE tenant_id=?",
                    (status, epoch, _utc_now(), tenant_id),
                )
                if status != "active":
                    db.execute("DELETE FROM run_reservations WHERE tenant_id=?", (tenant_id,))
                db.commit()
                return epoch
            except Exception:
                db.rollback()
                raise

    def set_project_status(self, tenant_id: str, project_id: str, status: ProjectStatus) -> int:
        if status not in _PROJECT_STATUSES:
            raise ValueError("invalid project status")
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                project = db.execute(
                    "SELECT tenant_id,status FROM projects WHERE project_id=?", (project_id,)
                ).fetchone()
                tenant = db.execute(
                    "SELECT authority_epoch FROM tenants WHERE tenant_id=?", (tenant_id,)
                ).fetchone()
                if project is None or tenant is None or str(project["tenant_id"]) != tenant_id:
                    raise TenantControlError("unknown tenant/project binding")
                epoch = int(tenant["authority_epoch"])
                if str(project["status"]) != status:
                    epoch += 1
                db.execute(
                    "UPDATE projects SET status=?,updated_at=? WHERE project_id=?",
                    (status, _utc_now(), project_id),
                )
                db.execute(
                    "UPDATE tenants SET authority_epoch=?,updated_at=? WHERE tenant_id=?",
                    (epoch, _utc_now(), tenant_id),
                )
                if status != "active":
                    db.execute(
                        "DELETE FROM run_reservations WHERE tenant_id=? AND project_id=?",
                        (tenant_id, project_id),
                    )
                db.commit()
                return epoch
            except Exception:
                db.rollback()
                raise

    def namespace(self, context: TenantContext, kind: NamespaceKind) -> str:
        if kind not in _NAMESPACE_KINDS:
            raise ValueError("unsupported tenant namespace kind")
        digest = _sha256(
            {
                "schema_version": "foundry.tenant-namespace.v1",
                "cell_id": context.cell_id,
                "kind": kind,
            }
        )[:32]
        return f"ns_{kind.replace('-', '_')}_{digest}"

    def export_tenant_state(self, tenant_id: str) -> dict[str, object]:
        with closing(self._connect()) as db:
            tenant = db.execute(
                "SELECT tenant_id,status,authority_epoch,keyset_id,quotas_json,artifact_bytes,created_at,updated_at FROM tenants WHERE tenant_id=?",
                (tenant_id,),
            ).fetchone()
            if tenant is None:
                raise TenantControlError("unknown tenant")
            projects = db.execute(
                "SELECT project_id,status,cell_id,created_at,updated_at FROM projects WHERE tenant_id=? ORDER BY project_id",
                (tenant_id,),
            ).fetchall()
            repositories = db.execute(
                "SELECT project_id,repository_id,created_at FROM repositories WHERE tenant_id=? ORDER BY project_id,repository_id",
                (tenant_id,),
            ).fetchall()
        body: dict[str, object] = {
            "schema_version": "foundry.tenant-state-export.v1",
            "tenant": {
                "tenant_id": str(tenant["tenant_id"]),
                "status": str(tenant["status"]),
                "authority_epoch": int(tenant["authority_epoch"]),
                "keyset_id": str(tenant["keyset_id"]),
                "quotas": json.loads(str(tenant["quotas_json"])),
                "artifact_bytes": int(tenant["artifact_bytes"]),
                "created_at": str(tenant["created_at"]),
                "updated_at": str(tenant["updated_at"]),
            },
            "projects": [dict(row) for row in projects],
            "repositories": [dict(row) for row in repositories],
        }
        return {**body, "export_sha256": _sha256(body)}
