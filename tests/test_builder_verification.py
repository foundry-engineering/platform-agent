"""Operational compiler selection is trusted data and cannot manufacture authority."""

from __future__ import annotations

import io
import json
import zipfile

import pytest
from engineering_agent.builder import BuilderBoundaryError

from builder_runtime_fixture import Harness, IMAGE
from platform_agent.builder_verification import verification_ports
from platform_agent.core_worker_service import WorkerConfigurationError


def profile(check="python-check"):
    return {
        "image": IMAGE,
        "checks": [{"check_id": check, "argv": ["/usr/local/bin/python", "-V"]}],
        "diagnostic_bytes": 1200,
    }


@pytest.mark.parametrize(
    "change",
    [
        {"schemaVersion": "model-selected"},
        {"diagnoseFirst": "true"},
        {"profiles": []},
        {"profiles": [profile(), profile()]},
        {"profiles": [{**profile(), "image": "python:latest"}]},
        {"profiles": [{**profile(), "diagnostic_bytes": 99999}]},
        {"profiles": [{**profile(), "compiled_execution": "true"}]},
        {"profiles": [{**profile(), "checks": [{"check_id": "python-check", "argv": ["python"]}]}]},
        {"extra": "model command"},
    ],
)
def test_untrusted_matrix_shapes_never_construct_worker_or_run_commands(tmp_path, change):
    h = Harness(tmp_path)
    evidence = tmp_path / "evidence"
    evidence.mkdir(mode=0o700)
    matrix = {
        "schemaVersion": "foundry.builder-sandbox-matrix.v1",
        "profiles": [profile()],
        "diagnoseFirst": True,
    }
    with pytest.raises((ValueError, BuilderBoundaryError, WorkerConfigurationError)):
        verification_ports(
            value={**matrix, **change}, workspace=h.workspace, evidence_dir=evidence, work_units=()
        )
    assert not h.runner.requests and not list(evidence.glob("*.json"))


def test_signed_runtime_retains_initial_diagnosis_in_sealed_private_manifest(tmp_path):
    h = Harness(tmp_path)
    source = h.workspace / "src/app.py"
    source.parent.mkdir()
    source.write_text("def main():\n    return 0\n")
    result = h.runtime(diagnose_first=True).run()
    assert result.execution.status == "verified"
    assert (
        result.execution.initial_verification and not result.execution.initial_verification.passed
    )
    assert h.verifier.calls == [5, 1, 2, 3]
    assert h.runner.requests[0].verification_feedback
    data = h.artifacts.read_bytes(
        h.authority().context, repository_id=h.repo, artifact_id=result.artifact.artifact_id
    )
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        manifest = json.loads(archive.read("builder-result.json"))
    assert manifest["initial_verification"]["passed"] is False
    assert manifest["initial_verification"]["evidence_refs"]
    assert manifest["delivery_verification"]["passed"] is True
    assert len(manifest["steps"]) == 2


def test_private_host_oracle_is_loaded_before_model_work(tmp_path):
    h = Harness(tmp_path)
    evidence = tmp_path / "evidence"
    evidence.mkdir(mode=0o700)
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    oracle = private / "oracle.json"
    oracle.touch(mode=0o600)
    oracle.write_text(json.dumps({"schemaVersion":"foundry.functional-oracle.v1",
        "expectedResults":[42], "nilEqualsEmpty":False}))
    config = profile()
    config["checks"][0]["oracleFile"] = str(oracle)
    verifier, units, diagnose = verification_ports(value=config, workspace=h.workspace,
        evidence_dir=evidence, work_units=())
    assert verifier is not None and units is None and not diagnose
    assert not h.runner.requests and not list(evidence.glob("*.json"))


@pytest.mark.parametrize("unsafe", ["workspace", "symlink", "public", "extra", "duplicate", "missing"])
def test_host_oracle_never_comes_from_candidate_or_ambiguous_config(tmp_path, unsafe):
    h = Harness(tmp_path)
    evidence = tmp_path / "evidence"
    evidence.mkdir(mode=0o700)
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    oracle = private / "oracle.json"
    oracle.touch(mode=0o600)
    value = {"schemaVersion":"foundry.functional-oracle.v1", "expectedResults":[42], "nilEqualsEmpty":False}
    if unsafe == "extra":
        value["modelMayEdit"] = True
    oracle.write_text(json.dumps(value))
    if unsafe == "workspace":
        moved = h.workspace / "oracle.json"
        oracle.rename(moved)
        oracle = moved
    if unsafe == "symlink":
        link = private / "link.json"
        link.symlink_to(oracle)
        oracle = link
    if unsafe == "public":
        oracle.chmod(0o644)
    if unsafe == "duplicate":
        oracle.write_text('{"schemaVersion":"foundry.functional-oracle.v1","expectedResults":[42],"expectedResults":[0],"nilEqualsEmpty":false}')
    if unsafe == "missing":
        oracle.unlink()
    config = profile()
    config["checks"][0]["oracleFile"] = str(oracle)
    with pytest.raises((WorkerConfigurationError, ValueError, OSError)):
        verification_ports(value=config, workspace=h.workspace, evidence_dir=evidence, work_units=())
    assert not h.runner.requests and not list(evidence.glob("*.json"))


@pytest.mark.parametrize("version,inputs,accepted",[
    ("foundry.functional-oracle.v2",[[2]],True),
    ("foundry.functional-oracle.v1",[[2]],False),
    ("foundry.functional-oracle.v2",None,False),
    ("foundry.functional-oracle.v2","model-selected",False),
    ("foundry.functional-oracle.v2",[],False),
])
def test_public_counterexample_inputs_require_exact_private_v2_profile(tmp_path,version,inputs,accepted):
    h=Harness(tmp_path)
    evidence = tmp_path / "evidence"
    evidence.mkdir(mode=0o700)
    private = tmp_path / "oracle"
    private.mkdir(mode=0o700)
    oracle = private / "expected.json"
    oracle.touch(mode=0o600)
    value={"schemaVersion":version,"expectedResults":[4],"nilEqualsEmpty":False}
    if inputs is not None:
        value["publicInputs"]=inputs
    oracle.write_text(json.dumps(value))
    config=profile()
    config["checks"][0]["oracleFile"]=str(oracle)
    if accepted:
        verification_ports(value=config,workspace=h.workspace,evidence_dir=evidence,work_units=())
    else:
        with pytest.raises((ValueError,WorkerConfigurationError)):
            verification_ports(value=config,workspace=h.workspace,evidence_dir=evidence,work_units=())
    assert not h.runner.requests and not list(evidence.glob("*.json"))
