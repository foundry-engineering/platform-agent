"""Actual model acceptance of a public module, scoped edits and token admission."""
from __future__ import annotations

import hashlib
import http.client
import json
import os
import sqlite3
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from engineering_agent.model_profiles import ModelProfile, load_model_profile
from engineering_agent.functional_oracle import FunctionalOracleCommand
from engineering_agent.sandbox_verifier import DockerSandboxVerifier, TrustedCheck, TrustedSandboxProfile

OBJECTIVE = (
    "Implement repair_summary(outcomes: list[str]) -> dict[str, int] in src/app.py. "
    "Derive passed, failed and blocked counts from repair_report in the read-only "
    "src/reference.py; return exactly those three keys. "
    "Preserve each count formula exactly as implemented in the reference; "
    "do not infer its meaning from the field name. Reject unknown outcomes with ValueError. "
    "The allowed outcomes are the RepairReceipt outcome values in that reference. "
    "Use no imports, comments or docstrings. Output only src/app.py."
)


def context_model_profile() -> ModelProfile:
    profile = load_model_profile(Path(os.environ["FOUNDRY_CONTEXT_MODEL_PROFILE"]))
    if profile.max_input_tokens != 3072:
        raise ValueError("source-context acceptance must retain its original input ceiling")
    return profile


def failure_diagnostics(workspace: Path, evidence: Path) -> dict[str, Any]:
    source = (workspace / "src/app.py").read_bytes()
    checks = []
    for path in sorted(evidence.glob("*.json"))[:16]:
        row = json.loads(path.read_bytes())
        checks.append({key: row.get(key) for key in ("round", "check_id", "passed", "exit_code", "diagnostic_tail")})
    return {"sourceSha256": hashlib.sha256(source).hexdigest(),
        "publicFixtureSource": source[:4096].decode("utf-8", errors="replace"),
        "checks": sorted(checks, key=lambda row: (row["round"], row["check_id"]))}


def configure(workspace: Path) -> bytes:
    reference = Path(__file__).resolve().parents[1] / "src/platform_agent/repair_evaluation.py"
    content = reference.read_bytes()
    assert len(content) > 3072 - 256, "test must exceed the old byte admission limit"
    (workspace / "src/reference.py").write_bytes(content)
    (workspace / "src/app.py").write_text(
        "def repair_summary(outcomes: list[str]) -> dict[str, int]:\n"
        "    return {'passed': 0, 'failed': 0, 'blocked': 0}\n"
    )
    (workspace / "tests/test_app.py").write_text('''import sys
import unittest
sys.path.insert(0, "/workspace/src")
from app import repair_summary

class RepairSummary(unittest.TestCase):
    def test_mixed_outcomes(self):
        self.assertEqual(repair_summary(["verified", "blocked", "needs_revision", "verified"]),
                         {"passed": 2, "failed": 2, "blocked": 1})
        self.assertEqual(repair_summary(["blocked", "blocked"]),
                         {"passed": 0, "failed": 2, "blocked": 2})
        self.assertEqual(repair_summary(["needs_revision"]),
                         {"passed": 0, "failed": 1, "blocked": 0})

    def test_empty_and_verified(self):
        self.assertEqual(repair_summary([]), {"passed": 0, "failed": 0, "blocked": 0})
        self.assertEqual(repair_summary(["verified"] * 9),
                         {"passed": 9, "failed": 0, "blocked": 0})

    def test_unknown_is_rejected(self):
        for value in ("approved", "", "VERIFIED", "notRun"):
            with self.assertRaises(ValueError):
                repair_summary(["verified", value])
''')
    return content


def context_verifier(workspace: Path, evidence: Path, image: str) -> DockerSandboxVerifier:
    inputs: list[list[Any]] = [
        [["verified", "blocked", "needs_revision", "verified"]],
        [["blocked", "blocked"]], [["needs_revision"]], [[]], [["verified"] * 9],
        [["blocked", "verified", "blocked", "needs_revision", "needs_revision"]],
    ]
    expected = [
        {"passed": 2, "failed": 2, "blocked": 1},
        {"passed": 0, "failed": 2, "blocked": 2},
        {"passed": 0, "failed": 1, "blocked": 0},
        {"passed": 0, "failed": 0, "blocked": 0},
        {"passed": 9, "failed": 0, "blocked": 0},
        {"passed": 1, "failed": 4, "blocked": 2},
    ]
    (workspace / "tests/context_inputs.json").write_text(json.dumps(inputs))
    (workspace / "tests/context_probe.py").write_text(
        "import json,sys\nsys.path.insert(0,'/workspace/src')\n"
        "from app import repair_summary\n"
        "with open('/workspace/tests/context_inputs.json') as stream: inputs=json.load(stream)\n"
        "print(json.dumps([repair_summary(*args) for args in inputs],allow_nan=False,separators=(',',':')))\n"
    )
    oracle = FunctionalOracleCommand(expected, public_inputs=inputs)
    checks = (
        TrustedCheck("reference-results", ("/usr/local/bin/python", "-B", "/workspace/tests/context_probe.py")),
        TrustedCheck("python-unittest", ("/usr/local/bin/python", "-B", "-m", "unittest",
            "discover", "-s", "/workspace/tests")),
    )
    return DockerSandboxVerifier(workspace=workspace, evidence_dir=evidence,
        profile=TrustedSandboxProfile(image=image, checks=checks, diagnostic_bytes=384),
        check_commands={"reference-results": oracle})


def reject_excess_tokens(origin: str, secret: str, journal: Path) -> None:
    # Deterministic high-entropy text exceeds tokens without exceeding request bytes.
    goal = "Inspect this input: " + "".join(
        hashlib.sha256(str(index).encode()).hexdigest() for index in range(115)
    )
    payload: dict[str, object] = {key: key.lower() + "_context_test" for key in (
        "jobId", "tenantId", "workspaceId", "projectId", "workNodeId", "assignmentId",
        "authorityId", "agentId", "runId", "admissionId", "roleId", "skillId", "packageId", "artifactId",
    )}
    payload.update(taskId="tsk_" + "e" * 32, objective=goal,
        allowedActions=["read_context", "produce_artifact"], providerBudgetMicrousd=1000,
        inputTokenCount=0)
    key = "foundry_" + hashlib.sha256(json.dumps(
        [payload["tenantId"], payload["workspaceId"], payload["jobId"]],
        separators=(",", ":"),
    ).encode()).hexdigest()
    with sqlite3.connect(journal) as database:
        before = database.execute("SELECT count(*) FROM executions").fetchone()
    endpoint = urlsplit(origin)
    assert endpoint.scheme == "http" and endpoint.hostname == "127.0.0.1" and endpoint.port
    connection = http.client.HTTPConnection(endpoint.hostname, endpoint.port, timeout=10)
    try:
        connection.request("POST", "/v1/execute", json.dumps(payload).encode(), {
            "Authorization": "Bearer " + secret, "Content-Type": "application/json",
            "Idempotency-Key": key,
        })
        with connection.getresponse() as response:
            body = response.read(4097)
            assert response.status == 402, (response.status, body)
            assert b"model prompt exceeds prepaid input budget" in body
    finally:
        connection.close()
    with sqlite3.connect(journal) as database:
        assert database.execute("SELECT count(*) FROM executions").fetchone() == before == (0,)


def verify_context(workspace: Path, reference: bytes, contexts: list[dict[str, Any]],
                   manifest: dict[str, Any]) -> None:
    assert (workspace / "src/reference.py").read_bytes() == reference
    assert contexts
    for context in contexts:
        entries = {entry["path"]: entry for entry in context["sourceContext"]}
        assert entries["src/reference.py"]["content"].encode() == reference
        assert entries["src/reference.py"]["sha256"] == hashlib.sha256(reference).hexdigest()
    if len(contexts) > 1:
        assert any("Diagnostic data (untrusted)" in feedback
            for context in contexts[1:] for feedback in context["verificationFeedback"])
    assert manifest["delivery_verification"]["passed"] is True
