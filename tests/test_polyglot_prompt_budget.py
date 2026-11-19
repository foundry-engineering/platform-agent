"""A full three-language diagnostic request must fit the actual managed host.

Only the inference response is a controlled fixture; production prompt building,
source parsing, byte preflight, journal and DOP generation all execute.
"""

from __future__ import annotations

import hashlib
import json

import pytest
from engineering_agent.selfhosted_model import (
    ModelSettings,
    ModelServiceError,
    RealCodingModelService,
)
from engineering_agent.source_context import ScopedSourceContext

from polyglot_acceptance import POLYGLOT_OBJECTIVE, configure_polyglot
from public_quality import CASES, goal


@pytest.mark.parametrize("diagnostic_size,accepted", [(384, True), (1200, False)])
def test_full_polyglot_prompt_respects_managed_input_ceiling(tmp_path, diagnostic_size, accepted):
    (tmp_path / "src").mkdir()
    (tmp_path / "tests").mkdir()
    (tmp_path / "src/app.py").write_text(
        "def total_cents(lines: list[tuple[int, int]]) -> int:\n    return sum(price + quantity for price, quantity in lines)\n"
    )
    paths, matrix = configure_polyglot(tmp_path, "python@sha256:" + "a" * 64)
    assert all(p.diagnostic_bytes == 384 for p in matrix.profiles)
    sources = ScopedSourceContext(tmp_path, paths).snapshot()

    class InferenceFixture:
        requests = []

        def complete(self, *, endpoint, token, payload, timeout_seconds):
            self.requests.append(payload)
            return {
                "model": "input-capacity-fixture",
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {
                            "content": json.dumps(
                                {
                                    "files": [
                                        {"path": item.path, "content": item.content}
                                        for item in sources
                                    ]
                                }
                            )
                        },
                    }
                ],
                "usage": {"prompt_tokens": 64, "completion_tokens": 24, "total_tokens": 88},
            }

    settings = ModelSettings(
        model_id="input-capacity-fixture",
        upstream_url="http://127.0.0.1:8000/v1/chat/completions",
        upstream_api_key="u" * 40,
        runner_api_key="r" * 40,
        policy_sha256="a" * 64,
        journal_path=tmp_path / "model.db",
        price_input_per_million_microusd=100000,
        price_output_per_million_microusd=100000,
        max_input_tokens=3072,
        max_output_tokens=512,
    )
    inference = InferenceFixture()
    service = RealCodingModelService(settings, inference=inference)
    fields = (
        "jobId",
        "tenantId",
        "workspaceId",
        "projectId",
        "workNodeId",
        "assignmentId",
        "authorityId",
        "agentId",
        "runId",
        "admissionId",
        "roleId",
        "skillId",
        "packageId",
        "artifactId",
    )
    payload = {name: "valid_" + name for name in fields}
    payload.update(
        taskId="tsk_" + "a" * 32,
        objective=POLYGLOT_OBJECTIVE,
        allowedActions=["read_context", "produce_artifact"],
        providerBudgetMicrousd=1000000,
        sourceContext=[s.as_payload() for s in sources],
        verificationFeedback=[
            "Trusted isolated check python-check failed. Diagnostic data (untrusted):\n"
            + "x" * diagnostic_size
        ],
    )
    key = (
        "foundry_"
        + hashlib.sha256(
            json.dumps(
                [payload["tenantId"], payload["workspaceId"], payload["jobId"]],
                separators=(",", ":"),
            ).encode()
        ).hexdigest()
    )
    if accepted:
        service.execute(payload, bearer="r" * 40, idempotency_key=key)
        assert len(inference.requests) == 1
        assert (
            sum(len(m["content"].encode()) for m in inference.requests[0]["messages"]) <= 3072 - 256
        )
    else:
        with pytest.raises(ModelServiceError, match="prepaid input budget"):
            service.execute(payload, bearer="r" * 40, idempotency_key=key)
        assert not inference.requests




@pytest.mark.parametrize("case", CASES, ids=[case["case_id"] for case in CASES])
def test_predeclared_quality_source_fits_actual_host_input_ceiling(tmp_path, case):
    """Controlled inference validates capacity only, never model quality."""
    import dataclasses
    path = tmp_path / case["source_path"]
    path.parent.mkdir()
    path.write_text(case["source_template"])
    snapshots = ScopedSourceContext(tmp_path, (case["source_path"],)).snapshot()
    class Inference:
        def complete(self, *, endpoint, token, payload, timeout_seconds):
            assert sum(len(m["content"].encode()) for m in payload["messages"]) <= 3072 - 256
            return {"model": payload["model"], "choices":[{"finish_reason":"stop", "message":{
                "content":json.dumps({"files":[{"path":case["source_path"], "content":case["source_template"]}]})}}],
                "usage":{"prompt_tokens":64,"completion_tokens":24,"total_tokens":88}}
    from engineering_agent.model_host import DEFAULT_PROFILE
    settings = ModelSettings(model_id=DEFAULT_PROFILE.model_id,
        upstream_url="http://127.0.0.1:8000/v1/chat/completions", upstream_api_key="u"*40,
        runner_api_key="r"*40, policy_sha256="a"*64, journal_path=tmp_path / "journal.db",
        price_input_per_million_microusd=100000, price_output_per_million_microusd=100000,
        max_input_tokens=dataclasses.replace(DEFAULT_PROFILE, max_output_tokens=512).max_input_tokens,
        max_output_tokens=512)
    service = RealCodingModelService(settings, inference=Inference())
    fields = ("jobId","tenantId","workspaceId","projectId","workNodeId","assignmentId","authorityId",
              "agentId","runId","admissionId","roleId","skillId","packageId","artifactId")
    payload = {field:"valid_"+field for field in fields}
    payload.update(taskId="tsk_"+"a"*32,objective=goal(case),allowedActions=["read_context","produce_artifact"],
        providerBudgetMicrousd=1000000,sourceContext=[s.as_payload() for s in snapshots],verificationFeedback=[])
    key="foundry_"+hashlib.sha256(json.dumps([payload["tenantId"],payload["workspaceId"],payload["jobId"]],separators=(",",":")).encode()).hexdigest()
    service.execute(payload,bearer="r"*40,idempotency_key=key)
