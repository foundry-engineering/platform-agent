from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, Literal, cast

TenantStatus = Literal["active", "suspended", "deleting", "deleted"]
ProjectStatus = Literal["active", "suspended", "deleting", "deleted"]
NamespaceKind = Literal["policy", "artifact", "audit", "receipt", "workspace", "key-metadata"]

_TENANT_STATUSES: Final = frozenset({"active", "suspended", "deleting", "deleted"})
_PROJECT_STATUSES: Final = frozenset({"active", "suspended", "deleting", "deleted"})
_NAMESPACE_KINDS: Final = frozenset(
    {"policy", "artifact", "audit", "receipt", "workspace", "key-metadata"}
)
_TENANT_TRANSITIONS: Final = {
    "active": frozenset({"suspended", "deleting"}),
    "suspended": frozenset({"active", "deleting"}),
    "deleting": frozenset(),
    "deleted": frozenset(),
}
_PROJECT_TRANSITIONS: Final = {
    "active": frozenset({"suspended", "deleting"}),
    "suspended": frozenset({"active", "deleting"}),
    "deleting": frozenset(),
    "deleted": frozenset(),
}


class TenantControlError(RuntimeError):
    pass


class TenantNotActiveError(TenantControlError):
    pass


class TenantQuotaError(TenantControlError):
    pass


@dataclass(frozen=True, slots=True)
class TenantQuotaLimits:
    max_active_runs: int = 32
    max_projects: int = 64
    max_repositories_per_project: int = 64
    max_artifact_bytes: int = 107_374_182_400

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
        return {"active_runs": self.active_runs, "artifact_bytes": self.artifact_bytes}


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
    repository_ids: tuple[str, ...] = ()
    repository_set_sha256: str = ""

    def as_dict(self) -> dict[str, object]:
        return {
            "reservation_id": self.reservation_id,
            "tenant_id": self.tenant_id,
            "project_id": self.project_id,
            "run_key": self.run_key,
            "repository_ids": list(self.repository_ids),
            "repository_set_sha256": self.repository_set_sha256,
        }


def _utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _repository_set_sha256(repository_ids: tuple[str, ...]) -> str:
    return _sha256(
        {
            "schema_version": "foundry.run-repository-set.v1",
            "repository_ids": list(repository_ids),
        }
    )


def _reject_symlink_path(path: Path) -> Path:
    raw = path.expanduser()
    for candidate in (raw, *raw.parents):
        if candidate.exists() and candidate.is_symlink():
            raise TenantControlError(f"tenant database path traverses symlink: {candidate}")
    return raw.resolve(strict=False)


def _require_identifier(value: str, *, prefix: str, field: str) -> str:
    if not isinstance(value, str) or not value.startswith(prefix) or len(value) < len(prefix) + 8:
        raise ValueError(f"{field} must use {prefix} prefix and at least 8 id characters")
    if any(ch not in "abcdefghijklmnopqrstuvwxyz0123456789_-" for ch in value[len(prefix) :]):
        raise ValueError(f"{field} contains unsupported characters")
    return value


def _require_reason(reason: str) -> str:
    if not isinstance(reason, str) or not reason.strip():
        raise ValueError("authority mutation reason is required")
    if len(reason.strip()) > 2048:
        raise ValueError("authority mutation reason is too long")
    return reason.strip()


def _require_keyset_id(value: str) -> str:
    if not value.startswith("keyset_") or len(value) < 11:
        raise ValueError("keyset_id must use keyset_ prefix")
    if any(ch not in "abcdefghijklmnopqrstuvwxyz0123456789._-" for ch in value[7:]):
        raise ValueError("keyset_id contains unsupported characters")
    return value


def _require_repository_id(value: str) -> str:
    parts = value.split("/")
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-")
    if len(parts) != 2 or any(not part for part in parts):
        raise ValueError("repository_id must use owner/repository form")
    if any(any(ch not in allowed for ch in part) for part in parts):
        raise ValueError("repository_id contains unsupported characters")
    return value


def _canonical_repository_set(values: tuple[str, ...] | list[str]) -> tuple[str, ...]:
    validated = tuple(_require_repository_id(value) for value in values)
    if not validated:
        raise ValueError("run reservation requires at least one repository")
    canonical = tuple(sorted(set(validated)))
    if len(canonical) != len(validated):
        raise ValueError("run reservation repository set contains duplicates")
    if len(canonical) > 256:
        raise ValueError("run reservation repository set is too large")
    return canonical


class SQLiteTenantControlStore:
    """Transactional tenant authority store for single-node/on-prem Foundry.

    The store owns lifecycle state, revocation epochs, quotas, repository bindings,
    short-lived run reservations and the tamper-evident authority event chain.
    Run reservations commit to the complete repository set of a dispatch.
    """

    def __init__(self, path: Path) -> None:
        self.path = _reject_symlink_path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()
        try:
            self.path.chmod(0o600)
        except OSError as exc:
            raise TenantControlError("failed to restrict tenant database permissions") from exc

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=30.0, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
        db.execute("PRAGMA busy_timeout = 30000")
        db.execute("PRAGMA journal_mode = WAL")
        return db

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
                    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
                    project_id TEXT NOT NULL REFERENCES projects(project_id) ON DELETE CASCADE,
                    repository_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (tenant_id, project_id, repository_id)
                );
                CREATE TABLE IF NOT EXISTS run_reservations (
                    reservation_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
                    project_id TEXT NOT NULL REFERENCES projects(project_id) ON DELETE CASCADE,
                    run_key TEXT NOT NULL,
                    repository_ids_json TEXT NOT NULL DEFAULT '[]',
                    repository_set_sha256 TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    UNIQUE (tenant_id, run_key)
                );
                CREATE TABLE IF NOT EXISTS authority_events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL UNIQUE,
                    tenant_id TEXT NOT NULL,
                    project_id TEXT,
                    kind TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    old_epoch INTEGER NOT NULL,
                    new_epoch INTEGER NOT NULL,
                    occurred_at TEXT NOT NULL,
                    prev_event_sha256 TEXT,
                    event_sha256 TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_projects_tenant ON projects(tenant_id);
                CREATE INDEX IF NOT EXISTS idx_repositories_project ON repositories(tenant_id, project_id);
                CREATE INDEX IF NOT EXISTS idx_runs_tenant ON run_reservations(tenant_id);
                CREATE INDEX IF NOT EXISTS idx_authority_events_tenant ON authority_events(tenant_id, sequence);
                """
            )
            columns = {
                str(row[1]) for row in db.execute("PRAGMA table_info(run_reservations)").fetchall()
            }
            if "repository_ids_json" not in columns:
                db.execute(
                    "ALTER TABLE run_reservations ADD COLUMN repository_ids_json TEXT NOT NULL DEFAULT '[]'"
                )
            if "repository_set_sha256" not in columns:
                db.execute(
                    "ALTER TABLE run_reservations ADD COLUMN repository_set_sha256 TEXT NOT NULL DEFAULT ''"
                )
            # Reservations are ephemeral authority. Legacy rows without repository-set
            # commitment are revoked rather than silently upgraded with guessed scope.
            db.execute(
                "DELETE FROM run_reservations WHERE repository_set_sha256='' OR repository_ids_json='[]'"
            )

    def _append_event(
        self,
        db: sqlite3.Connection,
        *,
        tenant_id: str,
        project_id: str | None,
        kind: str,
        reason: str,
        old_epoch: int,
        new_epoch: int,
    ) -> str:
        reason = _require_reason(reason)
        previous = db.execute(
            "SELECT event_sha256 FROM authority_events WHERE tenant_id=? ORDER BY sequence DESC LIMIT 1",
            (tenant_id,),
        ).fetchone()
        prev_sha = None if previous is None else str(previous["event_sha256"])
        occurred_at = _utc_now()
        material = {
            "schema_version": "foundry.authority-event.v1",
            "tenant_id": tenant_id,
            "project_id": project_id,
            "kind": kind,
            "reason": reason,
            "old_epoch": old_epoch,
            "new_epoch": new_epoch,
            "occurred_at": occurred_at,
            "prev_event_sha256": prev_sha,
        }
        event_sha = _sha256(material)
        event_id = "evt_" + event_sha[:32]
        db.execute(
            "INSERT INTO authority_events (event_id,tenant_id,project_id,kind,reason,old_epoch,new_epoch,occurred_at,prev_event_sha256,event_sha256) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                event_id,
                tenant_id,
                project_id,
                kind,
                reason,
                old_epoch,
                new_epoch,
                occurred_at,
                prev_sha,
                event_sha,
            ),
        )
        return event_id

    @staticmethod
    def _limits(row: sqlite3.Row) -> TenantQuotaLimits:
        raw = json.loads(str(row["quotas_json"]))
        if not isinstance(raw, dict):
            raise TenantControlError("stored quota policy is invalid")
        try:
            return TenantQuotaLimits(**raw)
        except (TypeError, ValueError) as exc:
            raise TenantControlError("stored quota policy is invalid") from exc

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
            db.execute("BEGIN IMMEDIATE")
            try:
                db.execute(
                    "INSERT INTO tenants (tenant_id,status,authority_epoch,keyset_id,quotas_json,created_at,updated_at) VALUES (?,?,?,?,?,?,?)",
                    (tenant_id, "active", 1, keyset_id, _canonical_json(limits.as_dict()), now, now),
                )
                self._append_event(
                    db,
                    tenant_id=tenant_id,
                    project_id=None,
                    kind="tenant.create",
                    reason="tenant created",
                    old_epoch=0,
                    new_epoch=1,
                )
                db.commit()
            except sqlite3.IntegrityError as exc:
                db.rollback()
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
                    raise TenantControlError("unknown tenant")
                if tenant["status"] != "active":
                    raise TenantNotActiveError("tenant is not active")
                limits = self._limits(tenant)
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
                epoch = int(tenant["authority_epoch"])
                self._append_event(
                    db,
                    tenant_id=tenant_id,
                    project_id=project_id,
                    kind="project.create",
                    reason="project created",
                    old_epoch=epoch,
                    new_epoch=epoch,
                )
                db.commit()
                return TenantContext(
                    tenant_id=tenant_id,
                    project_id=project_id,
                    cell_id=cell_id,
                    authority_epoch=epoch,
                    keyset_id=str(tenant["keyset_id"]),
                )
            except Exception:
                db.rollback()
                raise

    def bind_repository(self, tenant_id: str, project_id: str, repository_id: str) -> None:
        repository_id = _require_repository_id(repository_id)
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                tenant = db.execute(
                    "SELECT status,authority_epoch,quotas_json FROM tenants WHERE tenant_id=?",
                    (tenant_id,),
                ).fetchone()
                project = db.execute(
                    "SELECT tenant_id,status FROM projects WHERE project_id=?", (project_id,)
                ).fetchone()
                if tenant is None or project is None or str(project["tenant_id"]) != tenant_id:
                    raise TenantControlError("unknown tenant/project binding")
                if tenant["status"] != "active" or project["status"] != "active":
                    raise TenantNotActiveError("tenant/project is not active")
                exists = db.execute(
                    "SELECT 1 FROM repositories WHERE tenant_id=? AND project_id=? AND repository_id=?",
                    (tenant_id, project_id, repository_id),
                ).fetchone()
                if exists is not None:
                    db.rollback()
                    return
                limits = self._limits(tenant)
                count = int(
                    db.execute(
                        "SELECT COUNT(*) FROM repositories WHERE tenant_id=? AND project_id=?",
                        (tenant_id, project_id),
                    ).fetchone()[0]
                )
                if count >= limits.max_repositories_per_project:
                    raise TenantQuotaError("project repository quota exceeded")
                db.execute(
                    "INSERT INTO repositories (tenant_id,project_id,repository_id,created_at) VALUES (?,?,?,?)",
                    (tenant_id, project_id, repository_id, _utc_now()),
                )
                epoch = int(tenant["authority_epoch"])
                self._append_event(
                    db,
                    tenant_id=tenant_id,
                    project_id=project_id,
                    kind="repository.bind",
                    reason=f"repository bound: {repository_id}",
                    old_epoch=epoch,
                    new_epoch=epoch,
                )
                db.commit()
            except Exception:
                if db.in_transaction:
                    db.rollback()
                raise

    def unbind_repository(
        self,
        tenant_id: str,
        project_id: str,
        repository_id: str,
        *,
        reason: str,
    ) -> int:
        repository_id = _require_repository_id(repository_id)
        reason = _require_reason(reason)
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                tenant = db.execute(
                    "SELECT authority_epoch FROM tenants WHERE tenant_id=?", (tenant_id,)
                ).fetchone()
                if tenant is None:
                    raise TenantControlError("unknown tenant")
                cursor = db.execute(
                    "DELETE FROM repositories WHERE tenant_id=? AND project_id=? AND repository_id=?",
                    (tenant_id, project_id, repository_id),
                )
                if cursor.rowcount != 1:
                    raise TenantControlError("repository binding does not exist")
                old_epoch = int(tenant["authority_epoch"])
                new_epoch = old_epoch + 1
                db.execute(
                    "UPDATE tenants SET authority_epoch=?,updated_at=? WHERE tenant_id=?",
                    (new_epoch, _utc_now(), tenant_id),
                )
                db.execute(
                    "DELETE FROM run_reservations WHERE tenant_id=? AND project_id=?",
                    (tenant_id, project_id),
                )
                self._append_event(
                    db,
                    tenant_id=tenant_id,
                    project_id=project_id,
                    kind="repository.unbind",
                    reason=reason,
                    old_epoch=old_epoch,
                    new_epoch=new_epoch,
                )
                db.commit()
                return new_epoch
            except Exception:
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
                "SELECT tenant_id,status,cell_id FROM projects WHERE project_id=?", (project_id,)
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
        quotas = self._limits(tenant)
        usage = TenantQuotaUsage(active_runs=active_runs, artifact_bytes=int(tenant["artifact_bytes"]))
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

    def reserve_dispatch(
        self,
        tenant_id: str,
        project_id: str,
        repository_ids: tuple[str, ...] | list[str],
        *,
        run_key: str,
    ) -> RunReservation:
        if not run_key or len(run_key) > 256:
            raise ValueError("run_key must be a non-empty bounded string")
        repositories = _canonical_repository_set(repository_ids)
        repository_hash = _repository_set_sha256(repositories)
        reservation_id = "rsv_" + secrets.token_hex(16)
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                tenant = db.execute(
                    "SELECT status,quotas_json FROM tenants WHERE tenant_id=?", (tenant_id,)
                ).fetchone()
                project = db.execute(
                    "SELECT status,tenant_id FROM projects WHERE project_id=?", (project_id,)
                ).fetchone()
                bound = {
                    str(row[0])
                    for row in db.execute(
                        "SELECT repository_id FROM repositories WHERE tenant_id=? AND project_id=?",
                        (tenant_id, project_id),
                    ).fetchall()
                }
                if tenant is None or project is None or str(project["tenant_id"]) != tenant_id:
                    raise TenantControlError("unknown tenant/project binding")
                if set(repositories) - bound:
                    raise TenantControlError("run reservation includes repository outside tenant project")
                if tenant["status"] != "active" or project["status"] != "active":
                    raise TenantNotActiveError("tenant/project is not active")
                limits = self._limits(tenant)
                active = int(
                    db.execute(
                        "SELECT COUNT(*) FROM run_reservations WHERE tenant_id=?", (tenant_id,)
                    ).fetchone()[0]
                )
                if active >= limits.max_active_runs:
                    raise TenantQuotaError("tenant active-run quota exceeded")
                try:
                    db.execute(
                        "INSERT INTO run_reservations (reservation_id,tenant_id,project_id,run_key,repository_ids_json,repository_set_sha256,created_at) VALUES (?,?,?,?,?,?,?)",
                        (
                            reservation_id,
                            tenant_id,
                            project_id,
                            run_key,
                            _canonical_json(list(repositories)),
                            repository_hash,
                            _utc_now(),
                        ),
                    )
                except sqlite3.IntegrityError as exc:
                    raise TenantControlError("run_key already reserved for tenant") from exc
                db.commit()
            except Exception:
                db.rollback()
                raise
        return RunReservation(
            reservation_id=reservation_id,
            tenant_id=tenant_id,
            project_id=project_id,
            run_key=run_key,
            repository_ids=repositories,
            repository_set_sha256=repository_hash,
        )

    def reserve_run(
        self,
        tenant_id: str,
        project_id: str,
        repository_id: str,
        *,
        run_key: str,
    ) -> RunReservation:
        """Compatibility wrapper for one-repository runs."""
        return self.reserve_dispatch(
            tenant_id,
            project_id,
            (repository_id,),
            run_key=run_key,
        )

    def reservation_is_active(self, reservation: RunReservation) -> bool:
        with closing(self._connect()) as db:
            row = db.execute(
                "SELECT tenant_id,project_id,run_key,repository_ids_json,repository_set_sha256 FROM run_reservations WHERE reservation_id=?",
                (reservation.reservation_id,),
            ).fetchone()
        if row is None:
            return False
        try:
            stored_list = json.loads(str(row["repository_ids_json"]))
        except json.JSONDecodeError:
            return False
        if not isinstance(stored_list, list) or not all(isinstance(item, str) for item in stored_list):
            return False
        stored_repositories = tuple(stored_list)
        stored_hash = str(row["repository_set_sha256"])
        if stored_hash != _repository_set_sha256(stored_repositories):
            return False
        if reservation.repository_ids and reservation.repository_ids != stored_repositories:
            return False
        if reservation.repository_set_sha256 and reservation.repository_set_sha256 != stored_hash:
            return False
        return (
            str(row["tenant_id"]),
            str(row["project_id"]),
            str(row["run_key"]),
        ) == (reservation.tenant_id, reservation.project_id, reservation.run_key)

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
                updated = int(tenant["artifact_bytes"]) + byte_count
                if updated > self._limits(tenant).max_artifact_bytes:
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

    def _mutate_epoch(
        self,
        db: sqlite3.Connection,
        tenant_id: str,
        *,
        project_id: str | None,
        kind: str,
        reason: str,
    ) -> tuple[int, int]:
        tenant = db.execute(
            "SELECT authority_epoch FROM tenants WHERE tenant_id=?", (tenant_id,)
        ).fetchone()
        if tenant is None:
            raise TenantControlError("unknown tenant")
        old_epoch = int(tenant["authority_epoch"])
        new_epoch = old_epoch + 1
        db.execute(
            "UPDATE tenants SET authority_epoch=?,updated_at=? WHERE tenant_id=?",
            (new_epoch, _utc_now(), tenant_id),
        )
        self._append_event(
            db,
            tenant_id=tenant_id,
            project_id=project_id,
            kind=kind,
            reason=reason,
            old_epoch=old_epoch,
            new_epoch=new_epoch,
        )
        return old_epoch, new_epoch

    def bump_authority_epoch(self, tenant_id: str, *, reason: str) -> int:
        reason = _require_reason(reason)
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                _, epoch = self._mutate_epoch(
                    db,
                    tenant_id,
                    project_id=None,
                    kind="authority.revoke",
                    reason=reason,
                )
                db.execute("DELETE FROM run_reservations WHERE tenant_id=?", (tenant_id,))
                db.commit()
                return epoch
            except Exception:
                db.rollback()
                raise

    def rotate_keyset(self, tenant_id: str, *, keyset_id: str, reason: str) -> int:
        keyset_id = _require_keyset_id(keyset_id)
        reason = _require_reason(reason)
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                _, epoch = self._mutate_epoch(
                    db,
                    tenant_id,
                    project_id=None,
                    kind="keyset.rotate",
                    reason=reason,
                )
                db.execute(
                    "UPDATE tenants SET keyset_id=?,updated_at=? WHERE tenant_id=?",
                    (keyset_id, _utc_now(), tenant_id),
                )
                db.execute("DELETE FROM run_reservations WHERE tenant_id=?", (tenant_id,))
                db.commit()
                return epoch
            except Exception:
                db.rollback()
                raise

    def _quota_usage_for_update(self, db: sqlite3.Connection, tenant_id: str) -> tuple[int, int, int, int]:
        projects = int(
            db.execute(
                "SELECT COUNT(*) FROM projects WHERE tenant_id=? AND status != 'deleted'", (tenant_id,)
            ).fetchone()[0]
        )
        max_repositories = int(
            db.execute(
                "SELECT COALESCE(MAX(repo_count),0) FROM (SELECT COUNT(*) AS repo_count FROM repositories WHERE tenant_id=? GROUP BY project_id)",
                (tenant_id,),
            ).fetchone()[0]
        )
        active_runs = int(
            db.execute(
                "SELECT COUNT(*) FROM run_reservations WHERE tenant_id=?", (tenant_id,)
            ).fetchone()[0]
        )
        tenant = db.execute(
            "SELECT artifact_bytes FROM tenants WHERE tenant_id=?", (tenant_id,)
        ).fetchone()
        if tenant is None:
            raise TenantControlError("unknown tenant")
        return projects, max_repositories, active_runs, int(tenant["artifact_bytes"])

    def update_quotas(
        self,
        tenant_id: str,
        quotas: TenantQuotaLimits,
        *,
        reason: str,
    ) -> int:
        reason = _require_reason(reason)
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                projects, max_repositories, active_runs, artifact_bytes = self._quota_usage_for_update(
                    db, tenant_id
                )
                if projects > quotas.max_projects:
                    raise TenantQuotaError("new project quota is below current project usage")
                if max_repositories > quotas.max_repositories_per_project:
                    raise TenantQuotaError("new repository quota is below current project usage")
                if active_runs > quotas.max_active_runs:
                    raise TenantQuotaError("new active-run quota is below current usage")
                if artifact_bytes > quotas.max_artifact_bytes:
                    raise TenantQuotaError("new artifact quota is below current storage usage")
                _, epoch = self._mutate_epoch(
                    db,
                    tenant_id,
                    project_id=None,
                    kind="quota.update",
                    reason=reason,
                )
                db.execute(
                    "UPDATE tenants SET quotas_json=?,updated_at=? WHERE tenant_id=?",
                    (_canonical_json(quotas.as_dict()), _utc_now(), tenant_id),
                )
                # Any successful quota mutation rotates authority. Existing run
                # reservations are therefore revoked rather than carrying stale limits.
                db.execute("DELETE FROM run_reservations WHERE tenant_id=?", (tenant_id,))
                db.commit()
                return epoch
            except Exception:
                db.rollback()
                raise

    def set_tenant_status(self, tenant_id: str, status: TenantStatus, *, reason: str) -> int:
        if status not in _TENANT_STATUSES:
            raise ValueError("invalid tenant status")
        if status == "deleted":
            raise TenantControlError("deleted is terminal and is reached only by hard deletion")
        reason = _require_reason(reason)
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                tenant = db.execute(
                    "SELECT status,authority_epoch FROM tenants WHERE tenant_id=?", (tenant_id,)
                ).fetchone()
                if tenant is None:
                    raise TenantControlError("unknown tenant")
                old_status = str(tenant["status"])
                if old_status == status:
                    db.rollback()
                    return int(tenant["authority_epoch"])
                allowed = _TENANT_TRANSITIONS.get(old_status, frozenset())
                if status not in allowed:
                    raise TenantControlError(
                        f"invalid tenant lifecycle transition: {old_status}->{status}"
                    )
                _, epoch = self._mutate_epoch(
                    db,
                    tenant_id,
                    project_id=None,
                    kind="tenant.status",
                    reason=f"{reason} ({old_status}->{status})",
                )
                db.execute(
                    "UPDATE tenants SET status=?,updated_at=? WHERE tenant_id=?",
                    (status, _utc_now(), tenant_id),
                )
                db.execute("DELETE FROM run_reservations WHERE tenant_id=?", (tenant_id,))
                db.commit()
                return epoch
            except Exception:
                if db.in_transaction:
                    db.rollback()
                raise

    def set_project_status(
        self,
        tenant_id: str,
        project_id: str,
        status: ProjectStatus,
        *,
        reason: str,
    ) -> int:
        if status not in _PROJECT_STATUSES:
            raise ValueError("invalid project status")
        if status == "deleted":
            raise TenantControlError("deleted is terminal and is reached only by hard deletion")
        reason = _require_reason(reason)
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                project = db.execute(
                    "SELECT tenant_id,status FROM projects WHERE project_id=?", (project_id,)
                ).fetchone()
                if project is None or str(project["tenant_id"]) != tenant_id:
                    raise TenantControlError("unknown tenant/project binding")
                old_status = str(project["status"])
                if old_status == status:
                    tenant = db.execute(
                        "SELECT authority_epoch FROM tenants WHERE tenant_id=?", (tenant_id,)
                    ).fetchone()
                    if tenant is None:
                        raise TenantControlError("unknown tenant")
                    db.rollback()
                    return int(tenant["authority_epoch"])
                allowed = _PROJECT_TRANSITIONS.get(old_status, frozenset())
                if status not in allowed:
                    raise TenantControlError(
                        f"invalid project lifecycle transition: {old_status}->{status}"
                    )
                _, epoch = self._mutate_epoch(
                    db,
                    tenant_id,
                    project_id=project_id,
                    kind="project.status",
                    reason=f"{reason} ({old_status}->{status})",
                )
                db.execute(
                    "UPDATE projects SET status=?,updated_at=? WHERE project_id=?",
                    (status, _utc_now(), project_id),
                )
                db.execute(
                    "DELETE FROM run_reservations WHERE tenant_id=? AND project_id=?",
                    (tenant_id, project_id),
                )
                db.commit()
                return epoch
            except Exception:
                if db.in_transaction:
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

    def _export_body(self, db: sqlite3.Connection, tenant_id: str) -> dict[str, object]:
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
        reservations = db.execute(
            "SELECT reservation_id,project_id,run_key,repository_ids_json,repository_set_sha256,created_at FROM run_reservations WHERE tenant_id=? ORDER BY reservation_id",
            (tenant_id,),
        ).fetchall()
        return {
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
            "run_reservations": [dict(row) for row in reservations],
        }

    def export_tenant_state(self, tenant_id: str) -> dict[str, object]:
        with closing(self._connect()) as db:
            body = self._export_body(db, tenant_id)
        return {**body, "export_sha256": _sha256(body)}

    def hard_delete_tenant_state(self, tenant_id: str, *, reason: str) -> dict[str, object]:
        """Delete persistent tenant control state after isolation data has been drained."""
        reason = _require_reason(reason)
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                tenant = db.execute(
                    "SELECT status,authority_epoch,artifact_bytes FROM tenants WHERE tenant_id=?",
                    (tenant_id,),
                ).fetchone()
                if tenant is None:
                    raise TenantControlError("unknown tenant")
                if tenant["status"] != "deleting":
                    raise TenantControlError("tenant must be in deleting state before hard delete")
                if int(tenant["artifact_bytes"]) != 0:
                    raise TenantControlError("tenant artifacts must be deleted before control-state delete")
                active = int(
                    db.execute(
                        "SELECT COUNT(*) FROM run_reservations WHERE tenant_id=?", (tenant_id,)
                    ).fetchone()[0]
                )
                if active != 0:
                    raise TenantControlError("tenant has active run reservations")
                body = self._export_body(db, tenant_id)
                epoch = int(tenant["authority_epoch"])
                deletion_time = _utc_now()
                receipt_material = {
                    "schema_version": "foundry.tenant-control-deletion-receipt.v1",
                    "tenant_id": tenant_id,
                    "last_authority_epoch": epoch,
                    "final_authority_epoch": epoch + 1,
                    "state_export_sha256": _sha256(body),
                    "reason": reason,
                    "deleted_at": deletion_time,
                }
                self._append_event(
                    db,
                    tenant_id=tenant_id,
                    project_id=None,
                    kind="tenant.delete",
                    reason=reason,
                    old_epoch=epoch,
                    new_epoch=epoch + 1,
                )
                db.execute("DELETE FROM tenants WHERE tenant_id=?", (tenant_id,))
                db.commit()
                return {
                    **receipt_material,
                    "deletion_receipt_sha256": _sha256(receipt_material),
                }
            except Exception:
                db.rollback()
                raise

    def verify_authority_event_chain(self, tenant_id: str) -> bool:
        with closing(self._connect()) as db:
            rows = db.execute(
                "SELECT tenant_id,project_id,kind,reason,old_epoch,new_epoch,occurred_at,prev_event_sha256,event_sha256 FROM authority_events WHERE tenant_id=? ORDER BY sequence",
                (tenant_id,),
            ).fetchall()
        previous: str | None = None
        for row in rows:
            if row["prev_event_sha256"] != previous:
                raise TenantControlError("authority event chain predecessor mismatch")
            material = {
                "schema_version": "foundry.authority-event.v1",
                "tenant_id": str(row["tenant_id"]),
                "project_id": None if row["project_id"] is None else str(row["project_id"]),
                "kind": str(row["kind"]),
                "reason": str(row["reason"]),
                "old_epoch": int(row["old_epoch"]),
                "new_epoch": int(row["new_epoch"]),
                "occurred_at": str(row["occurred_at"]),
                "prev_event_sha256": previous,
            }
            expected = _sha256(material)
            if str(row["event_sha256"]) != expected:
                raise TenantControlError("authority event chain hash mismatch")
            previous = expected
        return True
