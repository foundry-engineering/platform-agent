from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Mapping
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, cast

from agent_protocol.schema import canonical_sha256
from agent_protocol.skill_package import (
    derive_skill_package_id,
    validate_skill_package_against_contract,
    verify_sha256_ref,
    verify_skill_package_artifact,
    verify_skill_package_signatures,
)
from platform_agent.tenant_control import TenantContext


class SkillAdmissionError(RuntimeError):
    """Raised when a runtime skill package cannot be admitted or resolved safely."""


class SkillAdmissionConflictError(SkillAdmissionError):
    """Raised when an active skill would be replaced without an explicit rollout."""


class SkillAdmissionRevokedError(SkillAdmissionError):
    """Raised when a caller attempts to resolve a revoked or stale admission."""


_ROLE_CHARS: Final = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-")
_MAX_VERIFICATION_AGE_SECONDS: Final = 30 * 24 * 60 * 60


@dataclass(frozen=True, slots=True)
class SkillAdmissionRecord:
    admission_id: str
    tenant_id: str
    project_id: str
    cell_id: str
    role_id: str
    skill_id: str
    skill_version: str
    package_id: str
    skill_contract_sha256: str
    artifact_digest: str
    source_repository_id: str
    source_commit_sha: str
    verified_signer_kids: tuple[str, ...]
    admitted_at: str
    verification_verified_at: str
    status: str

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": "foundry.skill-admission.v1",
            "admission_id": self.admission_id,
            "tenant_id": self.tenant_id,
            "project_id": self.project_id,
            "cell_id": self.cell_id,
            "role_id": self.role_id,
            "skill_id": self.skill_id,
            "skill_version": self.skill_version,
            "package_id": self.package_id,
            "skill_contract_sha256": self.skill_contract_sha256,
            "artifact_digest": self.artifact_digest,
            "source_repository_id": self.source_repository_id,
            "source_commit_sha": self.source_commit_sha,
            "verified_signer_kids": list(self.verified_signer_kids),
            "admitted_at": self.admitted_at,
            "verification_verified_at": self.verification_verified_at,
            "status": self.status,
        }


def _utc_now(now: datetime | None = None) -> datetime:
    current = datetime.now(UTC) if now is None else now
    if current.tzinfo is None:
        raise ValueError("trusted now must be timezone-aware")
    return current.astimezone(UTC)


def _utc_text(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _parse_utc(value: object, *, field: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise SkillAdmissionError(f"{field} must be canonical UTC")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00").astimezone(UTC)
    except ValueError as exc:
        raise SkillAdmissionError(f"{field} is invalid") from exc
    if _utc_text(parsed) != value:
        raise SkillAdmissionError(f"{field} must use second-precision canonical UTC")
    return parsed


def _canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _reject_symlink_path(path: Path) -> Path:
    raw = path.expanduser()
    for candidate in (raw, *raw.parents):
        if candidate.exists() and candidate.is_symlink():
            raise SkillAdmissionError(f"skill-admission database path traverses symlink: {candidate}")
    return raw.resolve(strict=False)


def _require_role_id(value: str) -> str:
    if not isinstance(value, str) or not (2 <= len(value) <= 128):
        raise ValueError("role_id must be a bounded string")
    if value[0] not in "abcdefghijklmnopqrstuvwxyz":
        raise ValueError("role_id must begin with a lowercase letter")
    if any(char not in _ROLE_CHARS for char in value):
        raise ValueError("role_id contains unsupported characters")
    return value


def _package_fields(package: object) -> tuple[str, str, str, str, str, str, str]:
    if not isinstance(package, dict):
        raise SkillAdmissionError("Skill Package must be an object")
    source = package.get("source")
    artifact = package.get("artifact")
    verification = package.get("verification")
    if not isinstance(source, dict) or not isinstance(artifact, dict) or not isinstance(verification, dict):
        raise SkillAdmissionError("Skill Package is missing canonical source/artifact/verification")
    values = (
        package.get("package_id"),
        package.get("skill_id"),
        package.get("skill_version"),
        package.get("skill_contract_sha256"),
        artifact.get("digest"),
        source.get("repository_id"),
        source.get("commit_sha"),
    )
    if not all(isinstance(value, str) for value in values):
        raise SkillAdmissionError("Skill Package contains invalid immutable bindings")
    return cast(tuple[str, str, str, str, str, str, str], values)


class SQLiteSkillAdmissionStore:
    """Persistent tenant/project admission for immutable, verified runtime Skill Packages."""

    def __init__(self, path: Path) -> None:
        self.path = _reject_symlink_path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()
        try:
            self.path.chmod(0o600)
        except OSError as exc:
            raise SkillAdmissionError("failed to restrict skill-admission database permissions") from exc

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
                CREATE TABLE IF NOT EXISTS skill_admissions (
                    admission_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    project_id TEXT NOT NULL,
                    cell_id TEXT NOT NULL,
                    role_id TEXT NOT NULL,
                    skill_id TEXT NOT NULL,
                    skill_version TEXT NOT NULL,
                    package_id TEXT NOT NULL,
                    skill_contract_sha256 TEXT NOT NULL,
                    artifact_digest TEXT NOT NULL,
                    source_repository_id TEXT NOT NULL,
                    source_commit_sha TEXT NOT NULL,
                    verified_signer_kids_json TEXT NOT NULL,
                    admitted_at TEXT NOT NULL,
                    verification_verified_at TEXT NOT NULL,
                    status TEXT NOT NULL CHECK (status IN ('active','revoked')),
                    revoked_at TEXT,
                    revoke_reason TEXT,
                    UNIQUE (tenant_id, project_id, role_id, skill_id, package_id)
                );
                CREATE UNIQUE INDEX IF NOT EXISTS idx_skill_admission_single_active
                ON skill_admissions (tenant_id, project_id, role_id, skill_id)
                WHERE status='active';

                CREATE TABLE IF NOT EXISTS skill_admission_events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL UNIQUE,
                    tenant_id TEXT NOT NULL,
                    project_id TEXT NOT NULL,
                    admission_id TEXT NOT NULL,
                    kind TEXT NOT NULL CHECK (kind IN ('admit','replace','revoke')),
                    reason TEXT NOT NULL,
                    occurred_at TEXT NOT NULL,
                    prev_event_sha256 TEXT,
                    event_sha256 TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_skill_events_tenant
                ON skill_admission_events (tenant_id, sequence);
                """
            )

    def _append_event(
        self,
        db: sqlite3.Connection,
        *,
        record: SkillAdmissionRecord,
        kind: str,
        reason: str,
        occurred_at: str,
    ) -> str:
        clean_reason = reason.strip()
        if not clean_reason:
            raise ValueError("skill-admission event reason is required")
        previous = db.execute(
            "SELECT event_sha256 FROM skill_admission_events WHERE tenant_id=? ORDER BY sequence DESC LIMIT 1",
            (record.tenant_id,),
        ).fetchone()
        prev_sha = None if previous is None else str(previous["event_sha256"])
        material = {
            "schema_version": "foundry.skill-admission-event.v1",
            "tenant_id": record.tenant_id,
            "project_id": record.project_id,
            "admission_id": record.admission_id,
            "kind": kind,
            "reason": clean_reason,
            "occurred_at": occurred_at,
            "prev_event_sha256": prev_sha,
        }
        event_sha = _sha256(material)
        event_id = "sae_" + event_sha[:32]
        db.execute(
            "INSERT INTO skill_admission_events (event_id,tenant_id,project_id,admission_id,kind,reason,occurred_at,prev_event_sha256,event_sha256) VALUES (?,?,?,?,?,?,?,?,?)",
            (
                event_id,
                record.tenant_id,
                record.project_id,
                record.admission_id,
                kind,
                clean_reason,
                occurred_at,
                prev_sha,
                event_sha,
            ),
        )
        return event_id

    @staticmethod
    def _record(row: sqlite3.Row) -> SkillAdmissionRecord:
        kids = json.loads(str(row["verified_signer_kids_json"]))
        if not isinstance(kids, list) or not all(isinstance(item, str) for item in kids):
            raise SkillAdmissionError("stored signer provenance is invalid")
        return SkillAdmissionRecord(
            admission_id=str(row["admission_id"]),
            tenant_id=str(row["tenant_id"]),
            project_id=str(row["project_id"]),
            cell_id=str(row["cell_id"]),
            role_id=str(row["role_id"]),
            skill_id=str(row["skill_id"]),
            skill_version=str(row["skill_version"]),
            package_id=str(row["package_id"]),
            skill_contract_sha256=str(row["skill_contract_sha256"]),
            artifact_digest=str(row["artifact_digest"]),
            source_repository_id=str(row["source_repository_id"]),
            source_commit_sha=str(row["source_commit_sha"]),
            verified_signer_kids=tuple(cast(list[str], kids)),
            admitted_at=str(row["admitted_at"]),
            verification_verified_at=str(row["verification_verified_at"]),
            status=str(row["status"]),
        )

    def admit(
        self,
        *,
        context: TenantContext,
        role_id: str,
        package: object,
        skill_contract: object,
        trusted_signing_keys: Mapping[str, bytes],
        artifact_bytes: bytes,
        sbom_bytes: bytes,
        provenance_bytes: bytes,
        verification_evidence: Mapping[str, bytes],
        reason: str,
        now: datetime | None = None,
        max_verification_age_seconds: int = _MAX_VERIFICATION_AGE_SECONDS,
        replace_active: bool = False,
    ) -> SkillAdmissionRecord:
        role_id = _require_role_id(role_id)
        if not isinstance(max_verification_age_seconds, int) or isinstance(max_verification_age_seconds, bool) or max_verification_age_seconds < 0:
            raise ValueError("max_verification_age_seconds must be a non-negative integer")

        validate_skill_package_against_contract(package, skill_contract)
        signer_kids = tuple(sorted(verify_skill_package_signatures(package, trusted_signing_keys)))
        if not signer_kids:
            raise SkillAdmissionError("Skill Package has no trusted verified signer")
        verify_skill_package_artifact(package, artifact_bytes)

        if not isinstance(package, dict):
            raise SkillAdmissionError("Skill Package must be an object")
        artifact = package.get("artifact")
        verification = package.get("verification")
        if not isinstance(artifact, dict) or not isinstance(verification, dict):
            raise SkillAdmissionError("Skill Package artifact/verification is invalid")
        verify_sha256_ref(artifact.get("sbom_ref"), sbom_bytes, field="artifact.sbom_ref")
        verify_sha256_ref(
            artifact.get("provenance_ref"), provenance_bytes, field="artifact.provenance_ref"
        )
        evidence_refs = verification.get("evidence_refs")
        if not isinstance(evidence_refs, list) or not all(isinstance(ref, str) for ref in evidence_refs):
            raise SkillAdmissionError("verification evidence refs are invalid")
        supplied_refs = set(verification_evidence)
        expected_refs = set(cast(list[str], evidence_refs))
        if supplied_refs != expected_refs:
            raise SkillAdmissionError("verification evidence must exactly cover package evidence refs")
        for ref in sorted(expected_refs):
            verify_sha256_ref(ref, verification_evidence[ref], field="verification.evidence_ref")

        verified_at = _parse_utc(verification.get("verified_at"), field="verification.verified_at")
        current = _utc_now(now)
        age_seconds = (current - verified_at).total_seconds()
        if age_seconds < 0:
            raise SkillAdmissionError("Skill Package verification timestamp is in the future")
        if age_seconds > max_verification_age_seconds:
            raise SkillAdmissionError("Skill Package verification is stale for tenant policy")

        package_id, skill_id, skill_version, contract_sha, artifact_digest, source_repo, source_commit = _package_fields(package)
        if derive_skill_package_id(package) != package_id:
            raise SkillAdmissionError("Skill Package deterministic identity mismatch")
        if not isinstance(skill_contract, dict) or canonical_sha256(skill_contract) != contract_sha:
            raise SkillAdmissionError("Skill Package contract hash cannot be reproduced")

        admitted_at = _utc_text(current)
        material = {
            "schema_version": "foundry.skill-admission.v1",
            "tenant_id": context.tenant_id,
            "project_id": context.project_id,
            "cell_id": context.cell_id,
            "role_id": role_id,
            "skill_id": skill_id,
            "skill_version": skill_version,
            "package_id": package_id,
            "skill_contract_sha256": contract_sha,
            "artifact_digest": artifact_digest,
            "source_repository_id": source_repo,
            "source_commit_sha": source_commit,
            "verified_signer_kids": list(signer_kids),
            "admitted_at": admitted_at,
            "verification_verified_at": _utc_text(verified_at),
        }
        admission_id = "ska_" + _sha256(material)[:32]
        record = SkillAdmissionRecord(
            admission_id=admission_id,
            tenant_id=context.tenant_id,
            project_id=context.project_id,
            cell_id=context.cell_id,
            role_id=role_id,
            skill_id=skill_id,
            skill_version=skill_version,
            package_id=package_id,
            skill_contract_sha256=contract_sha,
            artifact_digest=artifact_digest,
            source_repository_id=source_repo,
            source_commit_sha=source_commit,
            verified_signer_kids=signer_kids,
            admitted_at=admitted_at,
            verification_verified_at=_utc_text(verified_at),
            status="active",
        )

        clean_reason = reason.strip()
        if not clean_reason:
            raise ValueError("skill admission reason is required")

        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                active = db.execute(
                    "SELECT * FROM skill_admissions WHERE tenant_id=? AND project_id=? AND role_id=? AND skill_id=? AND status='active'",
                    (context.tenant_id, context.project_id, role_id, skill_id),
                ).fetchone()
                if active is not None:
                    existing = self._record(active)
                    if existing.package_id == package_id and existing.cell_id == context.cell_id:
                        db.rollback()
                        return existing
                    if not replace_active:
                        raise SkillAdmissionConflictError(
                            "a different Skill Package is already active; explicit rollout is required"
                        )
                    revoked_at = admitted_at
                    db.execute(
                        "UPDATE skill_admissions SET status='revoked',revoked_at=?,revoke_reason=? WHERE admission_id=?",
                        (revoked_at, f"replaced: {clean_reason}", existing.admission_id),
                    )
                    self._append_event(
                        db,
                        record=existing,
                        kind="replace",
                        reason=clean_reason,
                        occurred_at=revoked_at,
                    )

                db.execute(
                    "INSERT INTO skill_admissions (admission_id,tenant_id,project_id,cell_id,role_id,skill_id,skill_version,package_id,skill_contract_sha256,artifact_digest,source_repository_id,source_commit_sha,verified_signer_kids_json,admitted_at,verification_verified_at,status) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'active')",
                    (
                        record.admission_id,
                        record.tenant_id,
                        record.project_id,
                        record.cell_id,
                        record.role_id,
                        record.skill_id,
                        record.skill_version,
                        record.package_id,
                        record.skill_contract_sha256,
                        record.artifact_digest,
                        record.source_repository_id,
                        record.source_commit_sha,
                        _canonical_json(list(record.verified_signer_kids)),
                        record.admitted_at,
                        record.verification_verified_at,
                    ),
                )
                self._append_event(
                    db,
                    record=record,
                    kind="admit",
                    reason=clean_reason,
                    occurred_at=admitted_at,
                )
                db.commit()
            except Exception:
                db.rollback()
                raise
        return record

    def resolve(
        self,
        *,
        context: TenantContext,
        role_id: str,
        skill_id: str,
        package_id: str | None = None,
    ) -> SkillAdmissionRecord:
        role_id = _require_role_id(role_id)
        with closing(self._connect()) as db:
            row = db.execute(
                "SELECT * FROM skill_admissions WHERE tenant_id=? AND project_id=? AND role_id=? AND skill_id=? AND status='active'",
                (context.tenant_id, context.project_id, role_id, skill_id),
            ).fetchone()
        if row is None:
            raise SkillAdmissionRevokedError("no active Skill Package admission exists")
        record = self._record(row)
        if record.cell_id != context.cell_id:
            raise SkillAdmissionRevokedError("Skill Package admission belongs to a different isolation cell")
        if package_id is not None and record.package_id != package_id:
            raise SkillAdmissionRevokedError("requested package does not match active Skill Package")
        return record

    def revoke(self, admission_id: str, *, reason: str, now: datetime | None = None) -> None:
        if not isinstance(admission_id, str) or not admission_id.startswith("ska_"):
            raise ValueError("invalid skill admission id")
        clean_reason = reason.strip()
        if not clean_reason:
            raise ValueError("skill revocation reason is required")
        occurred_at = _utc_text(_utc_now(now))
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                row = db.execute(
                    "SELECT * FROM skill_admissions WHERE admission_id=?", (admission_id,)
                ).fetchone()
                if row is None:
                    raise SkillAdmissionError("unknown skill admission")
                record = self._record(row)
                if record.status == "revoked":
                    db.rollback()
                    return
                db.execute(
                    "UPDATE skill_admissions SET status='revoked',revoked_at=?,revoke_reason=? WHERE admission_id=?",
                    (occurred_at, clean_reason, admission_id),
                )
                self._append_event(
                    db,
                    record=record,
                    kind="revoke",
                    reason=clean_reason,
                    occurred_at=occurred_at,
                )
                db.commit()
            except Exception:
                db.rollback()
                raise

    def verify_event_chain(self, tenant_id: str) -> bool:
        with closing(self._connect()) as db:
            rows = db.execute(
                "SELECT tenant_id,project_id,admission_id,kind,reason,occurred_at,prev_event_sha256,event_sha256 FROM skill_admission_events WHERE tenant_id=? ORDER BY sequence",
                (tenant_id,),
            ).fetchall()
        previous: str | None = None
        for row in rows:
            if row["prev_event_sha256"] != previous:
                raise SkillAdmissionError("skill-admission event chain predecessor mismatch")
            material = {
                "schema_version": "foundry.skill-admission-event.v1",
                "tenant_id": str(row["tenant_id"]),
                "project_id": str(row["project_id"]),
                "admission_id": str(row["admission_id"]),
                "kind": str(row["kind"]),
                "reason": str(row["reason"]),
                "occurred_at": str(row["occurred_at"]),
                "prev_event_sha256": previous,
            }
            expected = _sha256(material)
            if str(row["event_sha256"]) != expected:
                raise SkillAdmissionError("skill-admission event chain hash mismatch")
            previous = expected
        return True
