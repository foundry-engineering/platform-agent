"""Compose admitted planning, witnessed DOP execution, checks and private output.

Requires an already approved tenant admission, a trusted metered Runner port,
and a separately configured independent verifier. No raw model API is called.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import stat
import zipfile
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from engineering_agent.builder import (
    BuilderBoundaryError, BuilderResult, BuilderTask, IndependentVerifier,
    PlanProposal, Verification, run_builder,
)
from engineering_agent.builder_runner import AdmittedRunnerModel, RunnerBudgetedPlanner
from engineering_agent.source_context import ScopedSourceContext, SourceSnapshot

from .artifact_store import ArtifactRecord, ContentAddressedArtifactStore
from .engineering_builder_authority import TenantBuilderAuthority


def _json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _private_directory(path: Path, workspace: Path) -> Path:
    if not path.is_absolute() or any(item.is_symlink() for item in (path, *path.parents)):
        raise BuilderBoundaryError("absolute private Builder state directory required")
    root = path.resolve(strict=True)
    info = root.stat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) & 0o077
            or root == workspace or root.is_relative_to(workspace)):
        raise BuilderBoundaryError("Builder state must be private and outside its workspace")
    return root


def _append(root: Path, name: str, body: Mapping[str, Any]) -> None:
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=directory)
        with os.fdopen(fd, "wb") as stream:
            stream.write(_json(body))
            stream.flush()
            os.fsync(stream.fileno())
        os.fsync(directory)
    finally:
        os.close(directory)


class _LivePlanner:
    def __init__(self, runner: AdmittedRunnerModel, context: ScopedSourceContext,
                 authority: TenantBuilderAuthority, paths: tuple[str, ...]) -> None:
        self._planner = RunnerBudgetedPlanner(runner, context=context)
        self._authority, self._paths = authority, frozenset(paths)

    def propose(self, task: BuilderTask, feedback: tuple[str, ...],
                *, remaining_budget_microusd: int) -> PlanProposal:
        self._authority.checkpoint()
        proposal = self._planner.propose(task, feedback,
            remaining_budget_microusd=remaining_budget_microusd)
        self._authority.checkpoint()
        operations = proposal.plan.get("operations")
        if not isinstance(operations, list) or not operations:
            raise BuilderBoundaryError("Builder proposal requires explicit source writes")
        if any(not isinstance(item, Mapping) or item.get("action") != "write"
               or item.get("path") not in self._paths for item in operations):
            raise BuilderBoundaryError("Builder proposal exceeds the configured source files")
        return proposal


class _LiveVerifier:
    def __init__(self, verifier: IndependentVerifier, authority: TenantBuilderAuthority) -> None:
        self._verifier, self._authority = verifier, authority

    def verify(self, task: BuilderTask, *, round_number: int) -> Verification:
        self._authority.checkpoint()
        result = self._verifier.verify(task, round_number=round_number)
        self._authority.checkpoint()
        return result


@dataclass(frozen=True, slots=True)
class BuilderDeliveryResult:
    run_id: str
    execution: BuilderResult
    artifact: ArtifactRecord | None


class TenantBuilderRuntime:
    """One admitted Builder attempt, with no automatic replay after a crash.

    Each verified Execution Grant is claimed once in private durable state.
    Failure leaves that claim consumed. Recovery needs fresh approved authority;
    it never silently restores model spend, repeats a write or delivers a failure.
    """

    def __init__(
        self, *, authority: TenantBuilderAuthority, workspace: Path,
        source_paths: tuple[str, ...], runner: AdmittedRunnerModel,
        verifier: IndependentVerifier, artifacts: ContentAddressedArtifactStore,
        state_directory: Path,
    ) -> None:
        if not workspace.is_absolute() or workspace.is_symlink() or not workspace.is_dir():
            raise BuilderBoundaryError("absolute real Builder workspace required")
        root = workspace.resolve(strict=True)
        if root != workspace:
            raise BuilderBoundaryError("Builder workspace cannot traverse symlink ancestors")
        if authority.task.model_budget_microusd < 1:
            raise BuilderBoundaryError("Builder requires a positive admitted model budget")
        if artifacts.root == root or artifacts.root.is_relative_to(root):
            raise BuilderBoundaryError("private Builder artifacts must be outside the workspace")
        context = ScopedSourceContext(root, source_paths)
        authority.require_source_paths(source_paths)
        self._state = _private_directory(state_directory, root)
        self._authority, self._workspace = authority, root
        self._context, self._artifacts = context, artifacts
        self._planner = _LivePlanner(runner, context, authority, source_paths)
        self._verifier = _LiveVerifier(verifier, authority)
        self._key = hashlib.sha256(_json([authority.grant_id])).hexdigest()

    def _bundle(
        self, result: BuilderResult, source: tuple[SourceSnapshot, ...], seal: Verification,
    ) -> bytes:
        task = self._authority.task
        manifest = {
            "schema_version": "foundry.builder-delivery.v1",
            "run_id": "run_" + self._key[:32], "task_id": task.task_id,
            "tenant_id": task.tenant_id, "project_id": task.project_id,
            "cell_id": task.cell_id, "workspace_id": task.workspace_id,
            "repository_id": task.repository_id,
            "base_commit_sha": task.workspace_base_commit_sha,
            "execution_grant_id": self._authority.grant_id,
            "status": "verified", "actual_model_microusd": result.used_model_microusd,
            "steps": [asdict(step) for step in result.steps], "delivery_verification": asdict(seal),
            "files": [{"path": item.path, "sha256": item.sha256} for item in source],
        }
        target = io.BytesIO()
        with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            entries = [(item.path, item.content.encode("utf-8"))
                       for item in source if item.content is not None]
            entries.append(("builder-result.json", _json(manifest)))
            for path, data in sorted(entries):
                item = zipfile.ZipInfo(path, date_time=(1980, 1, 1, 0, 0, 0))
                item.create_system = 3
                item.external_attr = (stat.S_IFREG | 0o644) << 16
                item.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(item, data)
        data = target.getvalue()
        if len(data) > 256 * 1024:
            raise BuilderBoundaryError("Builder delivery exceeds its bounded package size")
        return data

    def run(self) -> BuilderDeliveryResult:
        authority, task = self._authority, self._authority.task
        authority.checkpoint()
        # Validate the private output namespace before any consumed model call.
        self._artifacts.list_project(authority.context, repository_id=task.repository_id)
        try:
            _append(self._state, self._key + ".attempt.json", {
                "schema_version": "foundry.builder-attempt.v1",
                "execution_grant_id": authority.grant_id,
                "task_sha256": hashlib.sha256(_json(asdict(task))).hexdigest(),
            })
        except FileExistsError:
            raise BuilderBoundaryError("Builder grant already attempted; explicit recovery required") from None
        result = run_builder(task, workspace=self._workspace, planner=self._planner,
            authority=authority, verifier=self._verifier)
        artifact: ArtifactRecord | None = None
        if result.status == "verified":
            before = self._context.snapshot()
            if not before or any(item.content is None for item in before):
                raise BuilderBoundaryError("verified Builder delivery has missing configured source")
            # Seal the exact bytes collected for delivery with a fresh independent
            # check. Source changes before/after that check never enter the bundle.
            seal = self._verifier.verify(task, round_number=len(result.steps) + 1)
            if (type(seal.passed) is not bool or not seal.passed or not seal.check_ids
                    or not seal.evidence_refs
                    or any(not isinstance(item, str) or not 0 < len(item) <= 2048
                           for item in (*seal.check_ids, *seal.evidence_refs))
                    or not isinstance(seal.feedback, str) or len(seal.feedback) > 2000
                    or self._context.snapshot() != before):
                raise BuilderBoundaryError("Builder delivery source failed independent sealing")
            data = self._bundle(result, before, seal)
            authority.checkpoint()
            artifact = self._artifacts.put_bytes(authority.context,
                repository_id=task.repository_id, data=data,
                name="engineering-" + task.task_id + ".zip", media_type="application/zip",
                source_run_id="run_" + self._key[:32], execution_grant_id=authority.grant_id)
        _append(self._state, self._key + ".outcome.json", {
            "schema_version": "foundry.builder-outcome.v1", "status": result.status,
            "actual_model_microusd": result.used_model_microusd,
            "artifact_id": artifact.artifact_id if artifact is not None else None,
        })
        return BuilderDeliveryResult("run_" + self._key[:32], result, artifact)
