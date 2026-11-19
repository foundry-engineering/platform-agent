"""Fixed licensed public tasks, real isolated runtimes and host-owned results."""
from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import zipfile

from engineering_agent.builder import BuilderBoundaryError
from engineering_agent.functional_oracle import FunctionalOracleCommand
from engineering_agent.model_host import RUNTIME
from platform_agent.builder_verification import verification_ports
from platform_agent.quality_evaluation import QualityReceipt, quality_report
from polyglot_acceptance import NODE, GO

SUITE_SHA256 = "c9d19b6d0542872477639cc34adc3102d486b7eb1300edabb08bbbba9661d085"
RAW = (Path(__file__).parent / "quality/multiple-smoke-v1.json").read_bytes()
if hashlib.sha256(RAW).hexdigest() != SUITE_SHA256:
    raise RuntimeError("predeclared quality suite changed")
CASES = json.loads(RAW)["cases"]
CASE_IDS = tuple(case["case_id"] for case in CASES)


def goal(case):
    return (f"Implement {case['entry_point']} in {case['source_path']} according to its supplied specification. "
            "Return exactly that complete source file. Preserve its function signature and package. "
            "Use minimal code without comments or documentation. No test code, execution or test claims.")


def _runner(case):
    entry = case["entry_point"]
    if case["language"] == "py":
        return "runner.py", (
            "import json,sys\nsys.path.insert(0,'/workspace/src')\n"
            f"from candidate import {entry}\n"
            "with open('/workspace/tests/inputs.json') as f: inputs=json.load(f)\n"
            f"print(json.dumps([{entry}(*args) for args in inputs],allow_nan=False,separators=(',',':')))\n"
        ), ["/usr/local/bin/python", "-B", "/workspace/tests/runner.py"]
    if case["language"] == "js":
        return "runner.cjs", (
            "const fs=require('node:fs'),vm=require('node:vm');\n"
            "vm.runInThisContext(fs.readFileSync('/workspace/src/candidate.js','utf8'));\n"
            f"const fn=vm.runInThisContext({json.dumps(entry)});\n"
            "const inputs=JSON.parse(fs.readFileSync('/workspace/tests/inputs.json','utf8'));\n"
            "process.stdout.write(JSON.stringify(inputs.map(args=>fn(...args))));\n"
        ), ["/usr/local/bin/node", "/workspace/tests/runner.cjs"]
    signatures = {"has_close_elements": ("[]float64", "float64"), "make_palindrome": ("string",), "get_positive": ("[]int",)}
    def literal(value, kind):
        if kind.startswith("[]"):
            return kind + "{" + ",".join(json.dumps(item, allow_nan=False) for item in value) + "}"
        return json.dumps(value, ensure_ascii=False, allow_nan=False)
    calls = [entry + "(" + ",".join(literal(value, kind) for value, kind in
        zip(call["arguments"], signatures[entry], strict=True)) + ")" for call in case["calls"]]
    # Public input literals avoid a cold encoding/json dependency exhausting the
    # unchanged 64 MiB compiler tmpfs. No expected value enters this source.
    result_type = {"has_close_elements": "bool", "make_palindrome": "string", "get_positive": "[]int"}[entry]
    emit = "print(value)"
    helper = ""
    if result_type == "string":
        helper = r'''func emitString(s string){print("\"");for _,r:=range s{switch r{case '"':print("\\\"");case '\\':print("\\\\");default:if r<32{const hex="0123456789abcdef";print("\\u00",string(hex[r>>4]),string(hex[r&15]))}else{print(string(r))}}};print("\"")}
'''
        emit = "emitString(value)"
    elif result_type == "[]int":
        emit = 'print("[");for j,n:=range value{if j>0{print(",")};print(n)};print("]")'
    return "runner.go", (
        "package main\n" + helper + "func main(){values:=[]" + result_type + "{" + ",".join(calls) +
        '};print("[");for i,value:=range values{if i>0{print(",")};' + emit + '};print("]")}\n'
    ), ["/usr/bin/env", "GOCACHE=/tmp/go-cache", "GOPATH=/tmp/go", "GOPROXY=off", "GOSUMDB=off",
        "GOTOOLCHAIN=local", "GOMAXPROCS=1", "/bin/sh", "-eu", "-c",
        "cp /workspace/src/candidate.go /workspace/tests/runner.go /tmp/; /usr/local/go/bin/go run -p=1 /tmp/candidate.go /tmp/runner.go"]


def configure(case, workspace, evidence, private, python_image, *, diagnostic_inputs=False):
    for path in (workspace / "src/app.py", workspace / "tests/test_app.py"):
        path.unlink(missing_ok=True)
    source = workspace / case["source_path"]
    source.parent.mkdir(exist_ok=True)
    source.write_text(case["source_template"])
    tests = workspace / "tests"
    tests.mkdir(exist_ok=True)
    (tests / "inputs.json").write_text(json.dumps([call["arguments"] for call in case["calls"]]))
    filename, runner, argv = _runner(case)
    (tests / filename).write_text(runner)
    private.mkdir(mode=0o700)
    oracle = private / "oracle.json"
    oracle.touch(mode=0o600, exist_ok=False)
    oracle_data = {"schemaVersion": "foundry.functional-oracle.v2" if diagnostic_inputs else "foundry.functional-oracle.v1",
        "expectedResults": [call["expected"] for call in case["calls"]], "nilEqualsEmpty": case["language"] == "go"}
    if diagnostic_inputs:
        oracle_data["publicInputs"] = [call["arguments"] for call in case["calls"]]
    oracle.write_text(json.dumps(oracle_data))
    profile = {"image": {"py": python_image, "js": NODE, "go": GO}[case["language"]],
        "checks": [{"check_id": "external-results", "argv": argv, "oracleFile": str(oracle)}],
        "timeout_seconds": 60, "memory_mb": 1024, "pids_limit": 128, "diagnostic_bytes": 1024,
        "compiled_execution": case["language"] == "go"}
    verifier, units, diagnose = verification_ports(value=profile, workspace=workspace, evidence_dir=evidence, work_units=())
    assert units is None and not diagnose
    return verifier


def observe(worker, *, case, code, peers, database, model_contexts, inference, evidence, model_profile):
    try:
        assert worker.run_once()
    except BuilderBoundaryError:
        assert worker.last_attempt is not None and worker.last_attempt.execution.status == "needs_revision"
    result = worker.last_attempt
    assert result is not None and len(result.execution.steps) == 1 and inference.calls == 0
    assert result.execution.status in {"verified", "needs_revision"}
    verified = result.execution.status == "verified"
    step = result.execution.steps[0]
    assert step.verification.passed is verified
    if not verified:
        print("PUBLIC_QUALITY_FAILURE=" + json.dumps({"caseId": case["case_id"],
            "feedback": step.verification.feedback, "source": (code.workspace / case["source_path"]).read_text()[:8192]}, sort_keys=True))
    assert len(model_contexts) == 1 and not model_contexts[0]["verificationFeedback"]
    context = model_contexts[0]["sourceContext"]
    assert len(context) == 1 and context[0]["path"] == case["source_path"]
    assert context[0]["content"] == case["source_template"]
    source = (code.workspace / case["source_path"]).read_bytes()
    digest = hashlib.sha256(source).hexdigest()
    oracle_sha = FunctionalOracleCommand([call["expected"] for call in case["calls"]],
        nil_equals_empty=case["language"] == "go").commitment
    # Inspect the actual immutable host evidence, never a model assertion.
    records = [json.loads(path.read_text()) for path in evidence.glob("*.json")]
    assert records and all(r["schema_version"] == "foundry.builder.sandbox-evidence.v3" and
        r["external_oracle_sha256"] == oracle_sha for r in records)
    assert all(r["passed"] is verified for r in records)
    assert len([e for e in peers.events if e.get("type") == "artifact"]) == int(verified)
    assert peers.events[-1]["outcome"] == ("completed" if verified else "failed")
    assert len(peers.uploads) == (2 if verified else 1)
    if verified:
        assert result.artifact is not None
        with zipfile.ZipFile(io.BytesIO(peers.objects[peers.current]["content"])) as archive:
            assert set(archive.namelist()) == {case["source_path"], "builder-result.json"}
            assert archive.read(case["source_path"]) == source
            manifest = json.loads(archive.read("builder-result.json"))
            assert manifest["files"] == [{"path": case["source_path"], "sha256": digest}]
            assert manifest["delivery_verification"]["passed"] is True
    else:
        assert result.artifact is None
    with database() as db:
        rows = db.execute("SELECT provider_id,model_or_tool_id,actual_total_microusd,input_tokens,output_tokens FROM foundry_spend_settlement").fetchall()
        assert len(rows) == 1
        assert db.execute("SELECT count(*) FROM foundry_waw_invocation_claim").fetchone() == (1,)
        assert db.execute("SELECT reserved_paid_invocations FROM foundry_budget_scope WHERE scope_type='task'").fetchone() == (1,)
    provider, model, cost, inputs, outputs = rows[0]
    assert provider == "foundry-selfhosted" and model == model_profile.model_id
    assert cost == result.execution.used_model_microusd == step.usage_microusd
    identity = model_profile.identity()
    return QualityReceipt(case["case_id"], case["language"], model, identity["profile_sha256"], RUNTIME.sha256,
        digest, oracle_sha, result.execution.status, inputs, outputs, cost, 1, step.verification.evidence_refs)


def report(receipts):
    return quality_report(suite_sha256=SUITE_SHA256,
        expected_cases=tuple((case["case_id"], case["language"]) for case in CASES), receipts=tuple(receipts))
