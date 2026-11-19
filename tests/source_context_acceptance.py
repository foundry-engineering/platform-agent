"""Actual model acceptance of a public module, scoped edits and token admission."""
from __future__ import annotations

import hashlib
import http.client
import json
import sqlite3
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

OBJECTIVE = (
    "Implement repair_summary(outcomes: list[str]) -> dict[str, int] in src/app.py. "
    "Derive passed, failed and blocked counts from repair_report in the read-only "
    "src/reference.py; return exactly those three keys. Reject unknown outcomes with ValueError. "
    "The allowed outcomes are the RepairReceipt outcome values in that reference. "
    "Use no imports, comments or docstrings. Output only src/app.py."
)


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


def reject_excess_tokens(origin: str, secret: str, journal: Path) -> None:
    # Deterministic high-entropy text exceeds tokens without exceeding request bytes.
    goal = "Inspect this input: " + "".join(
        hashlib.sha256(str(index).encode()).hexdigest() for index in range(115)
    )
    payload: dict[str, object] = {key: key.lower() + "_context_test" for key in (
        "jobId", "tenantId", "workspaceId", "projectId", "workNodeId", "assignmentId",
        "authorityId", "agentId", "runId", "admissionId", "roleId", "skillId", "packageId",
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
    assert manifest["delivery_verification"]["passed"] is True
