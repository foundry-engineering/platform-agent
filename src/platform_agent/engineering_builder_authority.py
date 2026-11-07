"""Bind Engineering Builder writes to an existing signed tenant admission.

This adapter issues short-lived workspace leases and online witnesses only.
It cannot approve a plan, create a tenant, widen a grant or reserve a new run.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from typing import Any
import re
from pathlib import PurePosixPath

from agent_protocol.execution_grant import verify_execution_grant_signatures
from engineering_agent.builder import BuilderBoundaryError, BuilderTask, SignedAdmission
from engineering_agent.execution_gate import authorize_dop
from engineering_agent.source_context import source_path

from .runtime_authority import (
    AuthorityStateProvider, AuthorityWitnessSignerSet, issue_authority_witness,
    validate_admission_runtime_state,
)
from .tenant_authority import (
    TenantSandboxAdmission, WorkspaceBindingSigner, issue_workspace_binding,
)
from .tenant_control import TenantContext


class TenantBuilderAuthority:
    """Concrete Builder issuer over the existing Platform authority boundary."""

    def __init__(
        self, *, task: BuilderTask, admission: TenantSandboxAdmission,
        authority_state: AuthorityStateProvider, trusted_grant_keys: Mapping[str, bytes],
        workspace_signers: Sequence[WorkspaceBindingSigner],
        witness_signers: AuthorityWitnessSignerSet,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        lifetime_seconds: int = 60,
        execution_checkpoint: Callable[[], None] | None = None,
    ) -> None:
        if re.fullmatch(r"wsp_[a-f0-9]{32}", task.workspace_id) is None:
            raise BuilderBoundaryError("canonical signed Builder workspace identity required")
        if type(lifetime_seconds) is not int or not 5 <= lifetime_seconds <= 60:
            raise ValueError("builder authority lifetime must be within 5..60 seconds")
        if not trusted_grant_keys or any(
            not isinstance(kid, str) or not kid or not isinstance(key, bytes) or len(key) != 32
            for kid, key in trusted_grant_keys.items()
        ):
            raise ValueError("trusted Execution Grant keys required")
        workspace = tuple(workspace_signers)
        if not workspace or len({signer.kid for signer in workspace}) != len(workspace):
            raise ValueError("unique trusted workspace signers required")
        if (not witness_signers.signers
                or len({signer.kid for signer in witness_signers.signers}) != len(witness_signers.signers)
                or witness_signers.keyset_id != admission.tenant_context.keyset_id):
            raise ValueError("current, unique authority-witness signers required")
        # Frozen dataclasses may still contain mutable caller-owned grant mappings.
        self._admission = deepcopy(admission)
        self._task, self._state = task, authority_state
        self._grant_keys = dict(trusted_grant_keys)
        self._workspace_signers, self._witness_signers = workspace, witness_signers
        self._clock, self._lifetime = clock, lifetime_seconds
        self._execution_checkpoint = execution_checkpoint
        context = self._admission.tenant_context
        if (task.tenant_id != context.tenant_id or task.project_id != context.project_id
                or task.cell_id != context.cell_id):
            raise BuilderBoundaryError("Builder task differs from admitted tenant scope")
        matches = [grant for grant in self._admission.signed_grants
                   if grant.get("task_id") == task.task_id and grant.get("repo") == task.repository_id]
        if len(matches) != 1:
            raise BuilderBoundaryError("one exact admitted Builder task grant required")
        self._grant = deepcopy(dict(matches[0]))
        self.checkpoint()

    @property
    def task(self) -> BuilderTask:
        return self._task

    @property
    def context(self) -> TenantContext:
        return self._admission.tenant_context

    @property
    def grant_id(self) -> str:
        value = self._grant.get("grant_id")
        if not isinstance(value, str):
            raise BuilderBoundaryError("admitted Builder grant identity unavailable")
        return value

    @property
    def agent_id(self) -> str:
        value = self._grant.get("agent_id")
        if not isinstance(value, str):
            raise BuilderBoundaryError("admitted Builder agent identity unavailable")
        return value

    def checkpoint(self) -> None:
        if self._execution_checkpoint is not None:
            self._execution_checkpoint()
        verify_execution_grant_signatures(self._grant, self._grant_keys)
        snapshot = validate_admission_runtime_state(
            self._admission, authority_state=self._state,
            target_repository_id=self._task.repository_id,
        )
        if snapshot.context != self.context:
            raise BuilderBoundaryError("Builder tenant authority changed")

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None or value.utcoffset() is None:
            raise BuilderBoundaryError("trusted Builder clock must be timezone-aware")
        return value.astimezone(UTC)

    def require_source_paths(self, paths: tuple[str, ...]) -> None:
        self.checkpoint()
        for key in ("read_paths", "write_paths"):
            roots = self._grant.get(key)
            if not isinstance(roots, list) or not all(isinstance(root, str) for root in roots):
                raise BuilderBoundaryError("signed Builder file scope unavailable")
            for value in paths:
                path = PurePosixPath(source_path(value))
                if not any(PurePosixPath(root) == PurePosixPath(".") or path == PurePosixPath(root)
                           or path.is_relative_to(PurePosixPath(root)) for root in roots):
                    raise BuilderBoundaryError("configured Builder source exceeds signed " + key)

    def issue(self, task: BuilderTask, plan: Mapping[str, Any]) -> SignedAdmission:
        if task != self._task:
            raise BuilderBoundaryError("Builder task changed after authority binding")
        self.checkpoint()
        issued = self._now().replace(microsecond=0)
        expires = issued + timedelta(seconds=self._lifetime)
        snapshot = self._state.snapshot(task.tenant_id, task.project_id, task.repository_id)
        binding = issue_workspace_binding(
            snapshot, workspace_id=task.workspace_id,
            base_commit_sha=task.workspace_base_commit_sha,
            issued_at=issued, expires_at=expires, keyset_id=self.context.keyset_id,
            signers=self._workspace_signers,
        )
        witness = issue_authority_witness(
            self._admission, grant=self._grant, workspace_binding=binding,
            repository_id=task.repository_id, authority_state=self._state,
            signer_set=self._witness_signers, issued_at=issued, expires_at=expires,
        )
        # Recheck after external signing callbacks: rotation/revocation while
        # signing must not produce an executable Builder admission.
        self.checkpoint()
        now = self._now()
        result = SignedAdmission(
            grant=deepcopy(self._grant), workspace_binding=binding, authority_witness=witness,
            trusted_grant_keys=dict(self._grant_keys),
            trusted_workspace_keys={signer.kid: signer.public_key for signer in self._workspace_signers},
            trusted_witness_keys={signer.kid: signer.public_key for signer in self._witness_signers.signers},
            trusted_now=now, repository_id=task.repository_id,
            workspace_base_commit_sha=task.workspace_base_commit_sha,
        )
        # Preflight the actual DOP before returning any authority to the caller.
        # The canonical executor performs the same checks again before mutation.
        authorize_dop(
            plan, result.grant, result.workspace_binding, result.authority_witness,
            repository_id=result.repository_id,
            workspace_base_commit_sha=result.workspace_base_commit_sha,
            trusted_grant_keys=result.trusted_grant_keys,
            trusted_workspace_keys=result.trusted_workspace_keys,
            trusted_witness_keys=result.trusted_witness_keys, trusted_now=now,
        )
        return result
