"""Repair actual recorded model errors with original immutable requirements."""
from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import zipfile

from engineering_agent.builder import BuilderBoundaryError
from engineering_agent.functional_oracle import FunctionalOracleCommand
from engineering_agent.model_host import RUNTIME
from platform_agent.repair_evaluation import RepairReceipt, repair_report
from public_quality import CASES, configure

RAW = (Path(__file__).parent / "quality/generated-7b-failures-v1.json").read_bytes()
SEEDS_SHA256 = "7a3978d470242feee4bfdac4e647b839752b9e07d36d9c0c625131bfa644bc90"
if hashlib.sha256(RAW).hexdigest() != SEEDS_SHA256:
    raise RuntimeError("recorded failure selection changed")
SEEDS = json.loads(RAW)["cases"]
REPAIR_IDS = tuple("repair-" + item["case_id"] for item in SEEDS)
for seed in SEEDS:
    if hashlib.sha256(seed["source"].encode()).hexdigest() != seed["source_sha256"]:
        raise RuntimeError("recorded actual model failure changed")


def selected(sandbox):
    case_id = sandbox.removeprefix("repair-")
    return next(c for c in CASES if c["case_id"] == case_id)


def seed_for(case):
    return next(s for s in SEEDS if s["case_id"] == case["case_id"])


def goal(case):
    return (f"Repair ONLY {case['source_path']}; keep signature/package and required imports. "
        "Minimal complete code, no comments. Follow the immutable original contract:\n" + case["source_template"].rstrip())


def configure_repair(case, workspace, evidence, private, python_image):
    verifier = configure(case, workspace, evidence, private, python_image)
    (workspace / case["source_path"]).write_text(seed_for(case)["source"])
    return verifier


def observe(worker, *, case, code, peers, database, model_contexts, inference, evidence, model_profile):
    try:
        assert worker.run_once()
    except BuilderBoundaryError:
        assert worker.last_attempt is not None and worker.last_attempt.execution.status == "needs_revision"
    result = worker.last_attempt
    assert result is not None and result.execution.status in {"verified", "needs_revision"}
    steps = result.execution.steps
    rounds = len(steps)
    assert 1 <= rounds <= 3 and inference.calls == 0
    assert result.execution.initial_verification and not result.execution.initial_verification.passed
    assert len(model_contexts) == rounds
    seed = seed_for(case)
    assert model_contexts[0]["sourceContext"][0]["content"] == seed["source"]
    dops = [json.loads(obj["content"]) for obj in peers.objects.values() if obj.get("content", b"").startswith(b"{")]
    assert len(dops) == rounds
    for i, context in enumerate(model_contexts):
        assert context["verificationFeedback"]
        assert len(context["sourceContext"]) == 1
        snapshot = context["sourceContext"][0]
        expected_source = seed["source"] if i == 0 else dops[i-1]["operations"][0]["content"]["data"]
        assert snapshot["path"] == case["source_path"] and snapshot["content"] == expected_source
        assert snapshot["sha256"] == hashlib.sha256(expected_source.encode()).hexdigest()
    verified = result.execution.status == "verified"
    source = (code.workspace / case["source_path"]).read_bytes()
    source_sha = hashlib.sha256(source).hexdigest()
    oracle_sha = FunctionalOracleCommand([call["expected"] for call in case["calls"]],
        nil_equals_empty=case["language"] == "go").commitment
    records = {"sha256:" + path.stem: json.loads(path.read_bytes()) for path in evidence.glob("*.json")}
    assert records and all(record["schema_version"] == "foundry.builder.sandbox-evidence.v3" and
        record["external_oracle_sha256"] == oracle_sha for record in records.values())
    initial = result.execution.initial_verification.evidence_refs
    assert initial and all(not records[ref]["passed"] for ref in initial)
    for step in steps:
        assert step.verification.evidence_refs
        assert all(records[ref]["passed"] is step.verification.passed for ref in step.verification.evidence_refs)
    assert len([event for event in peers.events if event.get("type") == "artifact"]) == int(verified)
    assert peers.events[-1]["outcome"] == ("completed" if verified else "failed")
    assert len(peers.uploads) == rounds + int(verified)
    if verified:
        assert result.artifact is not None
        with zipfile.ZipFile(io.BytesIO(peers.objects[peers.current]["content"])) as archive:
            assert set(archive.namelist()) == {case["source_path"], "builder-result.json"}
            assert archive.read(case["source_path"]) == source
            manifest = json.loads(archive.read("builder-result.json"))
            assert manifest["files"] == [{"path":case["source_path"],"sha256":source_sha}]
            assert not manifest["initial_verification"]["passed"]
            assert manifest["delivery_verification"]["passed"]
            assert all(records[ref]["passed"] for ref in manifest["delivery_verification"]["evidence_refs"])
    else:
        assert result.artifact is None
        print("PUBLIC_REPAIR_FAILURE=" + json.dumps({"caseId":case["case_id"],
            "feedback":steps[-1].verification.feedback,"source":source.decode()[:8192]},sort_keys=True))
    with database() as db:
        rows = db.execute("SELECT provider_id,model_or_tool_id,actual_total_microusd,input_tokens,output_tokens FROM foundry_spend_settlement").fetchall()
        assert len(rows) == rounds
        assert db.execute("SELECT count(*) FROM foundry_waw_invocation_claim").fetchone() == (rounds,)
        assert db.execute("SELECT reserved_paid_invocations FROM foundry_budget_scope WHERE scope_type='task'").fetchone() == (rounds,)
    assert all(row[0] == "foundry-selfhosted" and row[1] == model_profile.model_id and min(row[2:]) > 0 for row in rows)
    cost = sum(row[2] for row in rows)
    assert cost == result.execution.used_model_microusd == sum(step.usage_microusd for step in steps)
    return RepairReceipt(case["case_id"],case["language"],model_profile.model_id,model_profile.identity()["profile_sha256"],
        RUNTIME.sha256,seed["source_sha256"],source_sha,oracle_sha,result.execution.status,
        sum(row[3] for row in rows),sum(row[4] for row in rows),cost,rounds,
        tuple(step.verification.passed for step in steps),tuple(step.usage_microusd for step in steps),
        tuple(sorted(records)))


def report(receipts):
    return repair_report(seeds_sha256=SEEDS_SHA256,
        expected_cases=tuple((seed["case_id"],next(c["language"] for c in CASES if c["case_id"]==seed["case_id"])) for seed in SEEDS),
        receipts=tuple(receipts))
