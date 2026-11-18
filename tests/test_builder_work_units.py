"""One real signed job spans 24 files through bounded, dependent work units."""
from __future__ import annotations

import hashlib
import io
import json
import os
import zipfile
from dataclasses import replace

import pytest
from engineering_agent.builder import BuilderBoundaryError
from platform_agent.builder_work_units import BuilderWorkUnit

from builder_runtime_fixture import Harness
from work_unit_fixture import FILES, PARTS, PATHS, UNITS, UnitModelFixture, admit_units, assigned_unit, verifiers


def setup_project(tmp_path, *, docker=False):
    h = Harness(tmp_path)
    admit_units(h)
    evidence = tmp_path / "unit-evidence"
    evidence.mkdir(mode=0o700)
    full, checks = verifiers(h.workspace, evidence, docker=docker)
    model = UnitModelFixture()
    return h, model, full, checks, evidence


@pytest.mark.parametrize("docker", [False, True], ids=["sealed-project", "docker-project"])
def test_dependent_work_units_deliver_24_files_with_one_total_budget(tmp_path, docker):
    if docker and os.environ.get("FOUNDRY_BUILDER_REAL_DOCKER") != "1":
        pytest.skip("requires the existing immutable image and actual Docker daemon")
    h, model, full, checks, evidence = setup_project(tmp_path, docker=docker)
    runtime = h.runtime(source_paths=PATHS, work_units=UNITS,
        runner=model, verifier=full, unit_verifiers=checks)
    result = runtime.run()
    assert result.execution.status == "verified" and result.execution.used_model_microusd == 3
    assert [assigned_unit(r.verification_feedback) for r in model.requests] == ["foundation", "service", "application"]
    assert [r.maximum_spend_microusd for r in model.requests] == [5, 4, 3]
    assert all(r.goal == h.task.goal and len(r.source_context) <= 16 for r in model.requests)
    assert sum(len(part) for part in PARTS.values()) == len(FILES) == 24
    observed = {item.path: item for item in model.requests[1].source_context}
    assert observed["migrations/001.sql"].content == FILES["migrations/001.sql"]
    assert [step.round_number for step in result.execution.steps] == [1, 2, 3]
    content = h.artifacts.read_bytes(h.admission.tenant_context,
        repository_id=h.repo, artifact_id=result.artifact.artifact_id)
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        assert set(archive.namelist()) == {*FILES, "builder-result.json"}
        assert all(archive.read(path) == value.encode() for path, value in FILES.items())
        manifest = json.loads(archive.read("builder-result.json"))
    assert manifest["schema_version"] == "foundry.builder-delivery.v2"
    assert manifest["actual_model_microusd"] == 3
    assert [item["unit_id"] for item in manifest["work_unit_results"]] == ["foundation", "service", "application"]
    assert manifest["files"] == [{"path": path, "sha256": hashlib.sha256(FILES[path].encode()).hexdigest()} for path in PATHS]
    if docker:
        records = [json.loads(path.read_bytes()) for path in evidence.glob("*.json")]
        assert {(item["round"], item["check_id"]) for item in records} == {
            (1, "foundation-check"), (2, "service-check"), (3, "application-check"),
            (4, "foundation-check"), (4, "service-check"), (4, "application-check")}
        assert len(records) == 6 and all(item["passed"] for item in records)
    with pytest.raises(BuilderBoundaryError, match="already attempted"):
        runtime.run()
    assert len(model.requests) == 3


def test_failed_unit_blocks_its_dependents_and_private_delivery(tmp_path):
    h, model, full, checks, _ = setup_project(tmp_path)
    original = checks["service"].verify
    def failed(task, *, round_number):
        return replace(original(task, round_number=round_number), passed=False, feedback="Service check failed")
    checks["service"].verify = failed
    result = h.runtime(source_paths=PATHS, work_units=UNITS,
        runner=model, verifier=full, unit_verifiers=checks).run()
    assert result.execution.status == "needs_revision" and result.artifact is None
    assert len(model.requests) == 2 and not (h.workspace / "src/main.py").exists()
    assert h.artifacts.list_project(h.admission.tenant_context, repository_id=h.repo) == ()


def test_full_project_verification_must_pass_after_all_units(tmp_path):
    h, model, full, checks, _ = setup_project(tmp_path)
    original = full.verify
    def failed(task, *, round_number):
        return replace(original(task, round_number=round_number), passed=False, feedback="Integration failed")
    full.verify = failed
    with pytest.raises(BuilderBoundaryError, match="sealing"):
        h.runtime(source_paths=PATHS, work_units=UNITS,
            runner=model, verifier=full, unit_verifiers=checks).run()
    assert len(model.requests) == 3
    assert h.artifacts.list_project(h.admission.tenant_context, repository_id=h.repo) == ()


def test_later_units_cannot_spend_the_original_budget_again(tmp_path):
    h, model, full, checks, _ = setup_project(tmp_path)
    original = model.produce
    def costly(request):
        return replace(original(request), actual_usage_microusd=3)
    model.produce = costly
    with pytest.raises(BuilderBoundaryError, match="reserved spend"):
        h.runtime(source_paths=PATHS, work_units=UNITS,
            runner=model, verifier=full, unit_verifiers=checks).run()
    assert [r.maximum_spend_microusd for r in model.requests] == [5, 2]
    assert not (h.workspace / "app/store.py").exists()
    assert h.artifacts.list_project(h.admission.tenant_context, repository_id=h.repo) == ()


@pytest.mark.parametrize("change", ["cycle", "missing-producer", "duplicate-output", "rounds", "source-list"])
def test_invalid_work_unit_graph_never_dispatches(tmp_path, change):
    h, model, full, checks, _ = setup_project(tmp_path)
    units, paths = UNITS, PATHS
    if change == "cycle":
        units = tuple(replace(u, dependencies=("application",)) if u.unit_id == "foundation" else u for u in units)
    elif change == "missing-producer":
        units = tuple(replace(u, dependencies=()) if u.unit_id == "service" else u for u in units)
    elif change == "duplicate-output":
        units = (*units, replace(units[1], unit_id="other", max_rounds=1))
        h.task = replace(h.task, max_rounds=4)
        checks["other"] = checks["foundation"]
    elif change == "rounds":
        units = tuple(replace(u, max_rounds=2) for u in units)
    else:
        paths = paths[:-1]
    with pytest.raises((ValueError, BuilderBoundaryError)):
        h.runtime(source_paths=paths, work_units=units,
            runner=model, verifier=full, unit_verifiers=checks)
    assert model.requests == [] and list(h.state.iterdir()) == []


def test_revocation_between_work_units_stops_further_inference(tmp_path):
    h, model, full, checks, _ = setup_project(tmp_path)
    original = checks["foundation"].verify
    def revoked(task, *, round_number):
        result = original(task, round_number=round_number)
        h.tenants.bump_authority_epoch(h.task.tenant_id, reason="stop project")
        return result
    checks["foundation"].verify = revoked
    with pytest.raises(RuntimeError):
        h.runtime(source_paths=PATHS, work_units=UNITS,
            runner=model, verifier=full, unit_verifiers=checks).run()
    assert len(model.requests) == 1 and not (h.workspace / "app/store.py").exists()


def test_unknown_unit_profile_fields_and_missing_checks_are_denied(tmp_path):
    h, model, full, _, _ = setup_project(tmp_path)
    with pytest.raises(BuilderBoundaryError, match="exact"):
        BuilderWorkUnit.from_payload({"unitId": "unit_a", "authority": "invented"})
    with pytest.raises(BuilderBoundaryError, match="exact independent verifier"):
        h.runtime(source_paths=PATHS, work_units=UNITS, runner=model,
            verifier=full, unit_verifiers={})


def test_a_unit_repairs_fresh_bytes_before_its_dependents_start(tmp_path):
    h, _, full, checks, _ = setup_project(tmp_path)
    h.task = replace(h.task, max_rounds=4)
    units = tuple(replace(unit, max_rounds=2) if unit.unit_id == "foundation" else unit for unit in UNITS)
    model = UnitModelFixture(fail_first=True)
    result = h.runtime(source_paths=PATHS, work_units=units, runner=model,
        verifier=full, unit_verifiers=checks).run()
    assert result.execution.status == "verified" and result.execution.used_model_microusd == 4
    assert [assigned_unit(r.verification_feedback) for r in model.requests] == [
        "foundation", "foundation", "service", "application"]
    assert [r.maximum_spend_microusd for r in model.requests] == [5, 4, 3, 2]
    observed = next(item for item in model.requests[1].source_context if item.path == "pyproject.toml")
    assert "wrong-name" in observed.content
    assert observed.sha256 == hashlib.sha256(observed.content.encode()).hexdigest()
    assert len(model.requests[1].verification_feedback) == 2
    assert [step.round_number for step in result.execution.steps] == [1, 2, 3, 4]


def test_a_unit_cannot_overwrite_a_read_only_dependency(tmp_path):
    from engineering_agent.selfhosted_model import _files_to_dop

    h, model, full, checks, _ = setup_project(tmp_path)
    original = model.produce
    def malicious(request):
        artifact = original(request)
        if assigned_unit(request.verification_feedback) != "service":
            return artifact
        before = next(item for item in request.source_context if item.path == "migrations/001.sql")
        entries = [{"path": path, "content": content} for path, content in PARTS["service"].items()]
        entries[0] = {"path": before.path, "content": "DROP TABLE records;\n", "expectedSha256": before.sha256}
        plan = _files_to_dop({"files": entries}, task_id=request.task_id,
            policy_sha256="f" * 64, source_context=request.source_context)
        body = json.dumps(plan, sort_keys=True, separators=(",", ":")).encode()
        return replace(artifact, content_bytes=body, content_sha256=hashlib.sha256(body).hexdigest())
    model.produce = malicious
    with pytest.raises(BuilderBoundaryError, match="configured source files"):
        h.runtime(source_paths=PATHS, work_units=UNITS, runner=model,
            verifier=full, unit_verifiers=checks).run()
    assert len(model.requests) == 2
    assert (h.workspace / "migrations/001.sql").read_text() == FILES["migrations/001.sql"]
    assert not (h.workspace / "app/store.py").exists()
