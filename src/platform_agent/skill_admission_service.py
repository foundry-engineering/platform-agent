from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from contextlib import closing
from datetime import datetime

from platform_agent.skill_admission import SQLiteSkillAdmissionStore, SkillAdmissionRecord
from platform_agent.tenant_control import (
    SQLiteTenantControlStore,
    TenantContext,
    TenantControlError,
    TenantNotActiveError,
)


class GovernedSkillAdmissionService:
    """Trust-boundary service that derives tenant context from live control-plane state."""

    def __init__(
        self,
        *,
        tenant_store: SQLiteTenantControlStore,
        admission_store: SQLiteSkillAdmissionStore,
    ) -> None:
        self._tenant_store = tenant_store
        self._admission_store = admission_store

    def _current_context(self, tenant_id: str, project_id: str) -> TenantContext:
        with closing(sqlite3.connect(self._tenant_store.path)) as db:
            db.row_factory = sqlite3.Row
            tenant = db.execute(
                "SELECT status,authority_epoch,keyset_id FROM tenants WHERE tenant_id=?",
                (tenant_id,),
            ).fetchone()
            project = db.execute(
                "SELECT tenant_id,status,cell_id FROM projects WHERE project_id=?",
                (project_id,),
            ).fetchone()
        if tenant is None or project is None or str(project["tenant_id"]) != tenant_id:
            raise TenantControlError("unknown tenant/project binding")
        if str(tenant["status"]) != "active" or str(project["status"]) != "active":
            raise TenantNotActiveError("tenant/project is not active")
        return TenantContext(
            tenant_id=tenant_id,
            project_id=project_id,
            cell_id=str(project["cell_id"]),
            authority_epoch=int(tenant["authority_epoch"]),
            keyset_id=str(tenant["keyset_id"]),
        )

    def current_context(self, tenant_id: str, project_id: str) -> TenantContext:
        """Return current live tenant/project context or fail closed if inactive."""
        return self._current_context(tenant_id, project_id)

    def admit(
        self,
        *,
        tenant_id: str,
        project_id: str,
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
        max_verification_age_seconds: int = 30 * 24 * 60 * 60,
        replace_active: bool = False,
    ) -> SkillAdmissionRecord:
        context = self._current_context(tenant_id, project_id)
        return self._admission_store.admit(
            context=context,
            role_id=role_id,
            package=package,
            skill_contract=skill_contract,
            trusted_signing_keys=trusted_signing_keys,
            artifact_bytes=artifact_bytes,
            sbom_bytes=sbom_bytes,
            provenance_bytes=provenance_bytes,
            verification_evidence=verification_evidence,
            reason=reason,
            now=now,
            max_verification_age_seconds=max_verification_age_seconds,
            replace_active=replace_active,
        )

    def resolve(
        self,
        *,
        tenant_id: str,
        project_id: str,
        role_id: str,
        skill_id: str,
        package_id: str | None = None,
    ) -> SkillAdmissionRecord:
        context = self._current_context(tenant_id, project_id)
        return self._admission_store.resolve(
            context=context,
            role_id=role_id,
            skill_id=skill_id,
            package_id=package_id,
        )

    def revoke(self, admission_id: str, *, reason: str, now: datetime | None = None) -> None:
        self._admission_store.revoke(admission_id, reason=reason, now=now)

    def verify_event_chain(self, tenant_id: str) -> bool:
        return self._admission_store.verify_event_chain(tenant_id)
