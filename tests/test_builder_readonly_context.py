"""Signed read-only context remains readable, immutable and outside output authority."""
from __future__ import annotations

import hashlib
import io
import json
import zipfile
from dataclasses import replace

import pytest
from agent_protocol.execution_grant import derive_execution_grant_id
from engineering_agent.builder import BuilderBoundaryError
from engineering_agent.selfhosted_model import _files_to_dop

from platform_agent.builder_work_units import BuilderWorkUnit
from platform_agent.grant_signing import ExecutionGrantSigner, sign_execution_grant
from builder_runtime_fixture import Harness

PATHS = ("src/app.py", "src/reference.py")


def scoped_context(tmp_path, *, readable=True):
    h = Harness(tmp_path)
    (h.workspace / "src").mkdir()
    (h.workspace / PATHS[1]).write_bytes(b"REFERENCE = 7\n")
    grant = {key: value for key, value in h.grant.items() if key != "signatures"}
    grant["read_paths"] = list(PATHS if readable else PATHS[:1])
    grant["write_paths"] = [PATHS[0]]
    grant["grant_id"] = derive_execution_grant_id(grant)
    h.grant = sign_execution_grant(grant, signers=(ExecutionGrantSigner(
        "kid_builder-grant.v1", h.grant_key.public_key().public_bytes_raw(), h.grant_key.sign),))
    h.admission = replace(h.admission, signed_grants=(h.grant,))
    unit = BuilderWorkUnit("reference-adapter", h.task.goal, PATHS, PATHS[:1], (),
        h.task.max_rounds, ("independent-value",))
    return h, unit


def runtime(h, unit):
    return h.runtime(source_paths=PATHS, work_units=(unit,),
        unit_verifiers={unit.unit_id: h.verifier})


def test_read_only_context_reaches_model_and_private_delivery_without_write_permission(tmp_path):
    h, unit = scoped_context(tmp_path)
    reference = (h.workspace / PATHS[1]).read_bytes()
    result = runtime(h, unit).run()
    assert result.execution.status == "verified" and result.artifact is not None
    assert len(h.runner.requests) == 2
    assert all(request.source_context[1].content.encode() == reference
        for request in h.runner.requests)
    assert (h.workspace / PATHS[1]).read_bytes() == reference
    body = h.artifacts.read_bytes(h.admission.tenant_context,
        repository_id=h.repo, artifact_id=result.artifact.artifact_id)
    with zipfile.ZipFile(io.BytesIO(body)) as archive:
        assert archive.read(PATHS[1]) == reference
        assert b"return 42" in archive.read(PATHS[0])


def test_missing_read_grant_stops_context_before_model_or_attempt(tmp_path):
    h, unit = scoped_context(tmp_path, readable=False)
    with pytest.raises(BuilderBoundaryError, match="signed read_paths"):
        runtime(h, unit)
    assert not h.runner.requests and not list(h.state.iterdir())


def test_read_only_source_cannot_be_named_as_work_unit_output(tmp_path):
    h, unit = scoped_context(tmp_path)
    with pytest.raises(BuilderBoundaryError, match="signed write_paths"):
        runtime(h, replace(unit, output_paths=PATHS))
    assert not h.runner.requests and not list(h.state.iterdir())


def test_read_only_context_cannot_widen_legacy_write_scope(tmp_path):
    h, _ = scoped_context(tmp_path)
    with pytest.raises(BuilderBoundaryError, match="signed write_paths"):
        h.runtime(source_paths=PATHS)
    assert not h.runner.requests and not list(h.state.iterdir())


def test_model_proposal_cannot_write_a_read_only_context_file(tmp_path):
    h, unit = scoped_context(tmp_path)
    reference = (h.workspace / PATHS[1]).read_bytes()
    original = h.runner.produce

    def malicious(request):
        artifact = original(request)
        plan = _files_to_dop({"files": [{"path": PATHS[1], "content": "REFERENCE = 0\n"}]},
            task_id=request.task_id, policy_sha256="f" * 64,
            source_context=request.source_context)
        body = json.dumps(plan, sort_keys=True, separators=(",", ":")).encode()
        return replace(artifact, content_bytes=body, content_sha256=hashlib.sha256(body).hexdigest())

    h.runner.produce = malicious
    with pytest.raises(BuilderBoundaryError, match="configured source files"):
        runtime(h, unit).run()
    assert len(h.runner.requests) == 1
    assert not (h.workspace / PATHS[0]).exists()
    assert (h.workspace / PATHS[1]).read_bytes() == reference
    assert h.artifacts.list_project(h.admission.tenant_context, repository_id=h.repo) == ()
