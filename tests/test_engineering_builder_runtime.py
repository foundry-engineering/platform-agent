"""Signed Builder, repair, private packaging and fail-closed replay acceptance.

Model/economic counterparties remain explicit fixtures. Actual signatures,
tenant state, authorization, DOP writes and artifact reads are never replaced.
The dedicated Docker case also executes the produced code in actual containers.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import zipfile
from dataclasses import replace

import pytest
from engineering_agent.builder import BuilderBoundaryError
from engineering_agent.sandbox_verifier import DockerSandboxVerifier, TrustedCheck, TrustedSandboxProfile

from platform_agent.artifact_store import ArtifactStoreError
from builder_runtime_fixture import Harness, IMAGE, ModelPortFixture


def unpack(h, completed):
    record = completed.artifact
    assert record is not None
    body = h.artifacts.read_bytes(h.admission.tenant_context,
        repository_id=h.repo, artifact_id=record.artifact_id)
    assert hashlib.sha256(body).hexdigest() == record.sha256
    archive = zipfile.ZipFile(io.BytesIO(body))
    return archive, json.loads(archive.read("builder-result.json"))


def test_signed_repair_is_sealed_and_delivered_to_exact_tenant(tmp_path):
    h = Harness(tmp_path)
    outcome = h.runtime().run()
    assert outcome.execution.status == "verified" and outcome.artifact is not None
    assert outcome.execution.used_model_microusd == 2
    assert len(h.runner.requests) == 2 and h.verifier.calls == [1, 2, 3]
    assert h.runner.requests[0].source_context[0].content is None
    assert "return 0" in h.runner.requests[1].source_context[0].content
    assert h.runner.requests[1].verification_feedback
    assert h.runner.requests[1].maximum_spend_microusd == 4
    archive, manifest = unpack(h, outcome)
    assert archive.namelist() == ["builder-result.json", "src/app.py"]
    assert b"return 42" in archive.read("src/app.py")
    assert manifest["actual_model_microusd"] == 2
    assert manifest["delivery_verification"]["passed"] is True
    assert manifest["execution_grant_id"] == h.grant["grant_id"]
    assert manifest["files"] == [{"path": "src/app.py",
        "sha256": hashlib.sha256(archive.read("src/app.py")).hexdigest()}]
    assert len(list(h.state.glob("*.attempt.json"))) == len(list(h.state.glob("*.outcome.json"))) == 1
    assert all(path.stat().st_mode & 0o077 == 0 for path in h.state.iterdir())
    assert outcome.artifact.tenant_id == h.task.tenant_id
    assert outcome.artifact.project_id == h.task.project_id
    assert outcome.artifact.repository_id == h.repo


def test_completed_grant_cannot_repeat_model_calls_or_delivery_after_restart(tmp_path):
    h = Harness(tmp_path)
    first = h.runtime().run()
    with pytest.raises(BuilderBoundaryError, match="already attempted"):
        h.runtime().run()
    assert len(h.runner.requests) == 2
    assert h.artifacts.list_project(h.admission.tenant_context, repository_id=h.repo) == (first.artifact,)


def test_uncertain_model_failure_is_consumed_and_never_automatically_retried(tmp_path):
    h = Harness(tmp_path)
    class FailedModel:
        calls = 0
        def produce(self, request):
            self.calls += 1
            raise RuntimeError("explicit uncertain test failure")
    model = FailedModel()
    with pytest.raises(RuntimeError, match="uncertain"):
        h.runtime(runner=model).run()
    with pytest.raises(BuilderBoundaryError, match="already attempted"):
        h.runtime(runner=model).run()
    assert model.calls == 1
    assert h.artifacts.list_project(h.admission.tenant_context, repository_id=h.repo) == ()


def test_repeated_failed_plan_blocks_without_customer_artifact(tmp_path):
    h = Harness(tmp_path)
    h.runner = ModelPortFixture(h, always_fail=True)
    result = h.runtime().run()
    # Two distinct preconditions may be proposed; the repeated third candidate
    # stops before another mutation or independent check.
    assert result.execution.status == "blocked" and result.artifact is None
    assert h.artifacts.list_project(h.admission.tenant_context, repository_id=h.repo) == ()


def test_exhausted_repair_rounds_do_not_deliver_failed_code(tmp_path):
    h = Harness(tmp_path)
    h.task = replace(h.task, max_rounds=1)
    result = h.runtime().run()
    assert result.execution.status == "needs_revision" and result.artifact is None
    assert len(h.runner.requests) == 1
    assert h.artifacts.list_project(h.admission.tenant_context, repository_id=h.repo) == ()


def test_source_changed_during_delivery_seal_is_not_published(tmp_path):
    h = Harness(tmp_path)
    class ChangedVerifier:
        def verify(self, task, *, round_number):
            checked = h.verifier.verify(task, round_number=round_number)
            if round_number == 3:
                (h.workspace / "src/app.py").write_text("untested replacement\n")
            return checked
    with pytest.raises(BuilderBoundaryError, match="sealing"):
        h.runtime(verifier=ChangedVerifier()).run()
    assert h.artifacts.list_project(h.admission.tenant_context, repository_id=h.repo) == ()


def test_failed_delivery_seal_is_not_published(tmp_path):
    h = Harness(tmp_path)
    class FailedVerifier:
        def verify(self, task, *, round_number):
            checked = h.verifier.verify(task, round_number=round_number)
            return replace(checked, passed=False) if round_number == 3 else checked
    with pytest.raises(BuilderBoundaryError, match="sealing"):
        h.runtime(verifier=FailedVerifier()).run()
    assert h.artifacts.list_project(h.admission.tenant_context, repository_id=h.repo) == ()


def test_revocation_inside_independent_check_prevents_further_model_or_delivery(tmp_path):
    h = Harness(tmp_path)
    class RevokingVerifier:
        def verify(self, task, *, round_number):
            checked = h.verifier.verify(task, round_number=round_number)
            h.tenants.bump_authority_epoch(h.task.tenant_id, reason="test operator abort")
            return checked
    with pytest.raises(RuntimeError):
        h.runtime(verifier=RevokingVerifier()).run()
    assert len(h.runner.requests) == 1
    assert list(h.artifacts.root.rglob("*.zip")) == []
    assert len(list(h.state.glob("*.attempt.json"))) == 1
    assert not list(h.state.glob("*.outcome.json"))


def test_revocation_before_model_dispatch_consumes_no_model_call(tmp_path):
    h = Harness(tmp_path)
    runtime = h.runtime()
    h.tenants.release_run(h.reservation.reservation_id)
    with pytest.raises(RuntimeError):
        runtime.run()
    assert h.runner.requests == []
    assert list(h.state.iterdir()) == []


def test_successful_private_output_cannot_be_read_from_foreign_project(tmp_path):
    h = Harness(tmp_path)
    result = h.runtime().run()
    h.tenants.create_project(h.task.tenant_id, "prj_foreign0001")
    h.tenants.bind_repository(h.task.tenant_id, "prj_foreign0001", "foundry-engineering/foreign")
    foreign = h.tenants.snapshot(h.task.tenant_id, "prj_foreign0001", "foundry-engineering/foreign").context
    with pytest.raises(ArtifactStoreError):
        h.artifacts.read_bytes(foreign, repository_id="foundry-engineering/foreign",
            artifact_id=result.artifact.artifact_id)


@pytest.mark.parametrize("kind", ["public", "inside_workspace", "symlink"])
def test_runtime_state_directory_cannot_be_public_or_model_writable(tmp_path, kind):
    h = Harness(tmp_path)
    path = h.state
    if kind == "public":
        path.chmod(0o755)
    elif kind == "inside_workspace":
        path = h.workspace / "state"
        path.mkdir(mode=0o700)
    else:
        path = tmp_path / "state-link"
        path.symlink_to(h.state, target_is_directory=True)
    with pytest.raises(BuilderBoundaryError):
        h.runtime(state_directory=path)
    assert h.runner.requests == []


def test_model_cannot_expand_configured_source_paths(tmp_path):
    h = Harness(tmp_path)
    original = h.runner.produce
    def foreign(request):
        result = original(request)
        body = json.dumps(h.plan(path="src/foreign.py"), sort_keys=True, separators=(",", ":")).encode()
        return replace(result, content_bytes=body, content_sha256=hashlib.sha256(body).hexdigest())
    h.runner.produce = foreign
    with pytest.raises(BuilderBoundaryError, match="configured source"):
        h.runtime().run()
    assert not (h.workspace / "src/foreign.py").exists()


def test_model_result_cannot_exceed_admitted_budget(tmp_path):
    h = Harness(tmp_path)
    original = h.runner.produce
    def excessive(request):
        return replace(original(request), actual_usage_microusd=6)
    h.runner.produce = excessive
    with pytest.raises(BuilderBoundaryError, match="reserved spend"):
        h.runtime().run()
    assert not (h.workspace / "src/app.py").exists()
    assert h.artifacts.list_project(h.admission.tenant_context, repository_id=h.repo) == ()


def test_missing_configured_source_prevents_delivery(tmp_path):
    h = Harness(tmp_path)
    with pytest.raises(BuilderBoundaryError, match="missing configured source"):
        h.runtime(source_paths=("src/app.py", "src/missing.py")).run()
    assert h.artifacts.list_project(h.admission.tenant_context, repository_id=h.repo) == ()


def test_actual_docker_repair_uses_real_signed_authority_and_private_artifact_store(tmp_path):
    if os.environ.get("FOUNDRY_BUILDER_REAL_DOCKER") != "1":
        pytest.skip("requires the reviewed immutable image and actual Docker daemon")
    h = Harness(tmp_path)
    tests = h.workspace / "tests"
    tests.mkdir(mode=0o755)
    (tests / "test_app.py").write_text(
        "import sys, unittest\nsys.path.insert(0, '/workspace/src')\nfrom app import main\n"
        "class TestApp(unittest.TestCase):\n    def test_value(self):\n        self.assertEqual(main(), 42)\n")
    evidence = tmp_path / "docker-evidence"
    evidence.mkdir(mode=0o700)
    verifier = DockerSandboxVerifier(workspace=h.workspace, evidence_dir=evidence,
        profile=TrustedSandboxProfile(image=IMAGE, checks=(TrustedCheck("python-unittest",
            ("/usr/local/bin/python", "-B", "-m", "unittest", "discover", "-s", "/workspace/tests")),)))
    result = h.runtime(verifier=verifier).run()
    assert result.execution.status == "verified"
    assert len(result.execution.steps) == 2
    assert result.execution.steps[0].verification.passed is False
    assert result.execution.steps[1].verification.passed is True
    archive, manifest = unpack(h, result)
    assert b"return 42" in archive.read("src/app.py")
    assert len(list(evidence.glob("*.json"))) == 3
    assert manifest["delivery_verification"]["check_ids"] == ["python-unittest"]
