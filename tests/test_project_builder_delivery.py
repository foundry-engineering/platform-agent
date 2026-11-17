"""Project-file acceptance over actual signed writes and private sealed delivery.

Only model/economic counterparties are fixtures. The Docker case executes the
module and migration in the existing isolated, immutable verifier image.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import zipfile
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from agent_protocol.execution_grant import derive_execution_grant_id
from engineering_agent.builder import BuilderBoundaryError, BuilderTask, Verification
from engineering_agent.builder_runner import RunnerModelArtifact, RunnerModelRequest
from engineering_agent.sandbox_verifier import DockerSandboxVerifier, TrustedCheck, TrustedSandboxProfile
from engineering_agent.selfhosted_model import _files_to_dop

from platform_agent.grant_signing import ExecutionGrantSigner, sign_execution_grant
from builder_runtime_fixture import Harness, IMAGE


FILES = {
    "pyproject.toml": '[project]\nname = "tenant-store"\nversion = "0.1.0"\n',
    "app/store.py": (
        "def values(db, tenant):\n"
        "    return [r[0] for r in db.execute(\n"
        "        'SELECT value FROM records WHERE tenant=?', (tenant,))]\n"
    ),
    "migrations/001.sql": "CREATE TABLE records(tenant TEXT NOT NULL, value TEXT NOT NULL);\n",
    "public/index.html": "<!doctype html><title>Tenant store</title>\n",
}
PATHS = tuple(FILES)


class ProjectModelFixture:
    def __init__(self) -> None:
        self.requests: list[RunnerModelRequest] = []

    def produce(self, request: RunnerModelRequest) -> RunnerModelArtifact:
        self.requests.append(request)
        plan = _files_to_dop(
            {"files": [{"path": path, "content": content} for path, content in FILES.items()]},
            task_id=request.task_id, policy_sha256="f" * 64,
            source_context=request.source_context,
        )
        body = json.dumps(plan, sort_keys=True, separators=(",", ":")).encode()
        return RunnerModelArtifact(
            task_id=request.task_id, tenant_id=request.tenant_id,
            workspace_id=request.workspace_id, project_id=request.project_id,
            cell_id=request.cell_id, repository_id=request.repository_id,
            base_commit_sha=request.base_commit_sha, content_bytes=body,
            content_sha256=hashlib.sha256(body).hexdigest(), actual_usage_microusd=1,
            model_usage_evidence_ref="fixture:usage", signed_admission_ref="fixture:admission",
            reservation_ref="fixture:reservation", settlement_ref="fixture:settlement",
            independent_scan_ref="fixture:scan",
        )


class ProjectBytesVerifier:
    """Nonexecuting ordinary check; executable behavior is checked by Docker."""
    def __init__(self, workspace: Path) -> None:
        self.workspace = workspace

    def verify(self, task: BuilderTask, *, round_number: int) -> Verification:
        actual = {path: (self.workspace / path).read_bytes() for path in PATHS}
        passed = all(actual[path] == content.encode() for path, content in FILES.items())
        evidence = tuple("sha256:" + hashlib.sha256(actual[path]).hexdigest() for path in PATHS)
        return Verification(passed, ("explicit-project-bytes",), evidence, "")


def admit_project_paths(h: Any) -> None:
    grant = {key: value for key, value in h.grant.items() if key != "signatures"}
    grant["read_paths"], grant["write_paths"] = sorted(PATHS), sorted(PATHS)
    grant["grant_id"] = derive_execution_grant_id(grant)
    h.grant = sign_execution_grant(grant, signers=(ExecutionGrantSigner(
        "kid_builder-grant.v1", h.grant_key.public_key().public_bytes_raw(), h.grant_key.sign),))
    h.admission = replace(h.admission, signed_grants=(h.grant,))


@pytest.mark.parametrize("docker", [False, True], ids=["sealed-bytes", "docker-migration"])
def test_explicit_project_files_cross_signed_execution_and_private_delivery(
    tmp_path: Path, docker: bool,
) -> None:
    if docker and os.environ.get("FOUNDRY_BUILDER_REAL_DOCKER") != "1":
        pytest.skip("requires the reviewed immutable image and actual Docker daemon")
    h = Harness(tmp_path)
    admit_project_paths(h)
    model = ProjectModelFixture()
    verifier: Any = ProjectBytesVerifier(h.workspace)
    checks = (
        TrustedCheck("project-manifest", ("/usr/local/bin/python", "-B", "-c",
            "from pathlib import Path; import tomllib; p=Path('/workspace'); "
            "assert tomllib.loads((p/'pyproject.toml').read_text())['project']['name']=='tenant-store'; "
            "assert (p/'public/index.html').read_text().startswith('<!doctype html>')")),
        TrustedCheck("migration-tenant-isolation", ("/usr/local/bin/python", "-B", "-c",
            "import sqlite3,runpy; from pathlib import Path; p=Path('/workspace'); "
            "db=sqlite3.connect(':memory:'); db.executescript((p/'migrations/001.sql').read_text()); "
            "db.executemany('INSERT INTO records VALUES(?,?)',[('a','private-a'),('b','private-b')]); "
            "v=runpy.run_path(str(p/'app/store.py'))['values']; "
            "assert v(db,'a')==['private-a']; assert v(db,'b')==['private-b']; "
            "assert v(db,\"a' OR 1=1 --\")==[]")),
    )
    if docker:
        evidence = tmp_path / "independent-project-evidence"
        evidence.mkdir(mode=0o700)
        verifier = DockerSandboxVerifier(workspace=h.workspace, evidence_dir=evidence,
            profile=TrustedSandboxProfile(image=IMAGE, checks=checks))
    result = h.runtime(source_paths=PATHS, runner=model, verifier=verifier).run()
    assert result.execution.status == "verified" and result.artifact is not None
    assert len(model.requests) == 1 and result.execution.used_model_microusd == 1
    assert tuple(item.path for item in model.requests[0].source_context) == PATHS
    assert all(item.content is None for item in model.requests[0].source_context)
    content = h.artifacts.read_bytes(h.admission.tenant_context,
        repository_id=h.repo, artifact_id=result.artifact.artifact_id)
    assert hashlib.sha256(content).hexdigest() == result.artifact.sha256
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        assert archive.namelist() == sorted([*PATHS, "builder-result.json"])
        assert {path: archive.read(path) for path in PATHS} == {
            path: value.encode() for path, value in FILES.items()}
        manifest = json.loads(archive.read("builder-result.json"))
    assert manifest["files"] == [
        {"path": path, "sha256": hashlib.sha256(value.encode()).hexdigest()}
        for path, value in FILES.items()]
    assert manifest["execution_grant_id"] == h.grant["grant_id"]
    assert manifest["delivery_verification"]["passed"] is True
    if docker:
        assert len(list(evidence.glob("*.json"))) == 2


def test_project_extension_cannot_widen_an_existing_src_only_grant(tmp_path: Path) -> None:
    h = Harness(tmp_path)
    model = ProjectModelFixture()
    with pytest.raises(BuilderBoundaryError, match="signed read_paths"):
        h.runtime(source_paths=PATHS, runner=model, verifier=ProjectBytesVerifier(h.workspace))
    assert model.requests == [] and list(h.state.iterdir()) == []
    assert h.artifacts.list_project(h.admission.tenant_context, repository_id=h.repo) == ()
