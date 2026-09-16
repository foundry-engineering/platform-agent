from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import time
from collections.abc import Callable, Mapping
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

WorkIntentValidator = Callable[[object], None]


class CoordinationControlError(RuntimeError):
    pass


class CoordinationConflictError(CoordinationControlError):
    def __init__(
        self,
        message: str,
        *,
        conflicting_intent_id: str,
        requested_claim: Mapping[str, object],
        active_claim: Mapping[str, object],
    ) -> None:
        super().__init__(message)
        self.conflicting_intent_id = conflicting_intent_id
        self.requested_claim = dict(requested_claim)
        self.active_claim = dict(active_claim)


@dataclass(frozen=True, slots=True)
class CoordinationLease:
    lease_id: str
    intent_id: str
    tenant_id: str
    project_id: str
    run_id: str
    task_id: str
    agent_id: str
    generation: int
    expires_at: float


class PersistentCoordinationStore:
    """Atomic cross-process admission for parallel Foundry work.

    The canonical Work Intent contract is owned by agent-protocol. This store requires
    its caller to supply that validator and never weakens or redefines the contract.
    SQLite is the single-node/on-prem implementation; distributed deployments can
    replace the storage adapter while preserving the same transactional semantics.
    """

    def __init__(
        self,
        db_path: Path,
        *,
        validate_work_intent: WorkIntentValidator,
        max_lease_seconds: float = 300.0,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if max_lease_seconds <= 0:
            raise ValueError("max_lease_seconds must be > 0")
        if db_path.exists() and db_path.is_symlink():
            raise CoordinationControlError("coordination database path must not be a symlink")
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._db_path = db_path
        self._validate_work_intent = validate_work_intent
        self._max_lease_seconds = max_lease_seconds
        self._clock = clock
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=30.0, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA busy_timeout = 30000")
        return conn

    def _initialize(self) -> None:
        with closing(self._connect()) as conn:
            conn.execute("PRAGMA journal_mode = WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS coordination_leases (
                    intent_id TEXT PRIMARY KEY,
                    lease_id TEXT NOT NULL UNIQUE,
                    tenant_id TEXT NOT NULL,
                    project_id TEXT NOT NULL,
                    cell_id TEXT NOT NULL,
                    run_id TEXT NOT NULL,
                    task_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    execution_grant_id TEXT NOT NULL,
                    workspace_binding_id TEXT NOT NULL,
                    base_state_sha256 TEXT NOT NULL,
                    intent_json TEXT NOT NULL,
                    claims_json TEXT NOT NULL,
                    generation INTEGER NOT NULL CHECK (generation >= 1),
                    expires_at REAL NOT NULL,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_coordination_active_scope
                    ON coordination_leases(tenant_id, project_id, cell_id, expires_at);
                CREATE INDEX IF NOT EXISTS idx_coordination_run
                    ON coordination_leases(run_id, expires_at);
                """
            )

    @staticmethod
    def _canonical_json(value: object) -> str:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

    @staticmethod
    def _extract_context(intent: Mapping[str, object]) -> tuple[str, str, str]:
        context = intent.get("tenant_context")
        if not isinstance(context, Mapping):
            raise CoordinationControlError("validated Work Intent is missing tenant_context")
        tenant_id = context.get("tenant_id")
        project_id = context.get("project_id")
        cell_id = context.get("cell_id")
        if not all(isinstance(value, str) and value for value in (tenant_id, project_id, cell_id)):
            raise CoordinationControlError("validated Work Intent has invalid tenant context")
        return str(tenant_id), str(project_id), str(cell_id)

    @staticmethod
    def _claims(intent: Mapping[str, object]) -> list[dict[str, object]]:
        raw = intent.get("claims")
        if not isinstance(raw, list):
            raise CoordinationControlError("validated Work Intent is missing claims")
        result: list[dict[str, object]] = []
        for item in raw:
            if not isinstance(item, Mapping):
                raise CoordinationControlError("validated Work Intent contains invalid claim")
            result.append(dict(item))
        return result

    @staticmethod
    def _paths_overlap(left: str, right: str) -> bool:
        left_parts = PurePosixPath(left).parts
        right_parts = PurePosixPath(right).parts
        shortest = min(len(left_parts), len(right_parts))
        return left_parts[:shortest] == right_parts[:shortest]

    @classmethod
    def _claims_conflict(cls, left: Mapping[str, object], right: Mapping[str, object]) -> bool:
        if left.get("repository_id") != right.get("repository_id"):
            return False
        if left.get("access") == right.get("access") == "read":
            return False
        left_path = left.get("path")
        right_path = right.get("path")
        if not isinstance(left_path, str) or not isinstance(right_path, str):
            raise CoordinationControlError("validated claim has invalid path")
        return cls._paths_overlap(left_path, right_path)

    @staticmethod
    def _new_lease_id(intent_id: str, generation: int) -> str:
        nonce = secrets.token_bytes(32)
        material = intent_id.encode("utf-8") + generation.to_bytes(8, "big") + nonce
        return "ils_" + hashlib.sha256(material).hexdigest()[:32]

    @staticmethod
    def _row_to_lease(row: sqlite3.Row) -> CoordinationLease:
        return CoordinationLease(
            lease_id=str(row["lease_id"]),
            intent_id=str(row["intent_id"]),
            tenant_id=str(row["tenant_id"]),
            project_id=str(row["project_id"]),
            run_id=str(row["run_id"]),
            task_id=str(row["task_id"]),
            agent_id=str(row["agent_id"]),
            generation=int(row["generation"]),
            expires_at=float(row["expires_at"]),
        )

    def publish(self, intent: Mapping[str, object], *, lease_seconds: float) -> CoordinationLease:
        if lease_seconds <= 0 or lease_seconds > self._max_lease_seconds:
            raise ValueError("lease_seconds is outside the configured range")
        self._validate_work_intent(intent)

        intent_id = intent.get("intent_id")
        run_id = intent.get("run_id")
        task_id = intent.get("task_id")
        agent_id = intent.get("agent_id")
        grant_id = intent.get("execution_grant_id")
        workspace_binding_id = intent.get("workspace_binding_id")
        base_state = intent.get("base_state_sha256")
        required = (intent_id, run_id, task_id, agent_id, grant_id, workspace_binding_id, base_state)
        if not all(isinstance(value, str) and value for value in required):
            raise CoordinationControlError("validated Work Intent has missing identity material")

        tenant_id, project_id, cell_id = self._extract_context(intent)
        claims = self._claims(intent)
        intent_json = self._canonical_json(intent)
        claims_json = self._canonical_json(claims)
        now = self._clock()
        expires_at = now + lease_seconds

        with closing(self._connect()) as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute("DELETE FROM coordination_leases WHERE expires_at <= ?", (now,))

                existing = conn.execute(
                    "SELECT * FROM coordination_leases WHERE intent_id = ?",
                    (str(intent_id),),
                ).fetchone()
                if existing is not None:
                    if str(existing["intent_json"]) != intent_json:
                        raise CoordinationControlError("intent_id collision with different content")
                    conn.execute("COMMIT")
                    return self._row_to_lease(existing)

                active_rows = conn.execute(
                    """
                    SELECT intent_id, claims_json
                    FROM coordination_leases
                    WHERE tenant_id = ? AND project_id = ? AND cell_id = ? AND expires_at > ?
                    """,
                    (tenant_id, project_id, cell_id, now),
                ).fetchall()
                for row in active_rows:
                    active_claims = json.loads(str(row["claims_json"]))
                    if not isinstance(active_claims, list):
                        raise CoordinationControlError("stored coordination claims are corrupt")
                    for requested in claims:
                        for active in active_claims:
                            if not isinstance(active, dict):
                                raise CoordinationControlError("stored coordination claim is corrupt")
                            if self._claims_conflict(requested, active):
                                raise CoordinationConflictError(
                                    "parallel work conflicts with an active resource lease",
                                    conflicting_intent_id=str(row["intent_id"]),
                                    requested_claim=requested,
                                    active_claim=active,
                                )

                generation = 1
                lease_id = self._new_lease_id(str(intent_id), generation)
                conn.execute(
                    """
                    INSERT INTO coordination_leases(
                        intent_id, lease_id, tenant_id, project_id, cell_id, run_id, task_id,
                        agent_id, execution_grant_id, workspace_binding_id, base_state_sha256,
                        intent_json, claims_json, generation, expires_at, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(intent_id), lease_id, tenant_id, project_id, cell_id, str(run_id),
                        str(task_id), str(agent_id), str(grant_id), str(workspace_binding_id),
                        str(base_state), intent_json, claims_json, generation, expires_at, now, now,
                    ),
                )
                conn.execute("COMMIT")
                return CoordinationLease(
                    lease_id=lease_id,
                    intent_id=str(intent_id),
                    tenant_id=tenant_id,
                    project_id=project_id,
                    run_id=str(run_id),
                    task_id=str(task_id),
                    agent_id=str(agent_id),
                    generation=generation,
                    expires_at=expires_at,
                )
            except Exception:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise

    def renew(self, intent_id: str, lease_id: str, *, lease_seconds: float) -> CoordinationLease:
        if lease_seconds <= 0 or lease_seconds > self._max_lease_seconds:
            raise ValueError("lease_seconds is outside the configured range")
        now = self._clock()
        expires_at = now + lease_seconds
        with closing(self._connect()) as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                row = conn.execute(
                    "SELECT * FROM coordination_leases WHERE intent_id = ?",
                    (intent_id,),
                ).fetchone()
                if row is None or float(row["expires_at"]) <= now:
                    if row is not None:
                        conn.execute("DELETE FROM coordination_leases WHERE intent_id = ?", (intent_id,))
                    raise CoordinationControlError("coordination lease is missing or expired")
                if str(row["lease_id"]) != lease_id:
                    raise CoordinationControlError("stale coordination lease cannot be renewed")
                generation = int(row["generation"]) + 1
                next_lease_id = self._new_lease_id(intent_id, generation)
                conn.execute(
                    """
                    UPDATE coordination_leases
                    SET lease_id = ?, generation = ?, expires_at = ?, updated_at = ?
                    WHERE intent_id = ? AND lease_id = ?
                    """,
                    (next_lease_id, generation, expires_at, now, intent_id, lease_id),
                )
                updated = conn.execute(
                    "SELECT * FROM coordination_leases WHERE intent_id = ?",
                    (intent_id,),
                ).fetchone()
                if updated is None:
                    raise CoordinationControlError("coordination lease disappeared during renewal")
                conn.execute("COMMIT")
                return self._row_to_lease(updated)
            except Exception:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise

    def release(self, intent_id: str, lease_id: str) -> None:
        with closing(self._connect()) as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                cursor = conn.execute(
                    "DELETE FROM coordination_leases WHERE intent_id = ? AND lease_id = ?",
                    (intent_id, lease_id),
                )
                if cursor.rowcount != 1:
                    raise CoordinationControlError("stale or unknown coordination lease")
                conn.execute("COMMIT")
            except Exception:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise

    def active_leases(self, *, run_id: str | None = None) -> tuple[CoordinationLease, ...]:
        now = self._clock()
        with closing(self._connect()) as conn:
            conn.execute("DELETE FROM coordination_leases WHERE expires_at <= ?", (now,))
            if run_id is None:
                rows = conn.execute(
                    "SELECT * FROM coordination_leases ORDER BY tenant_id, project_id, run_id, task_id"
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM coordination_leases WHERE run_id = ? ORDER BY task_id",
                    (run_id,),
                ).fetchall()
        return tuple(self._row_to_lease(row) for row in rows)
