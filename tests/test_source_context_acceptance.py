"""The live overflow probe must reach actual token admission before generation."""
from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from threading import Thread
from typing import Any

from engineering_agent.model_http_server import ModelHttpServer
from engineering_agent.model_token_counter import ChatMessages
from engineering_agent.selfhosted_model import (
    ModelSettings,
    RealCodingModelService,
    model_http_handler,
)

from source_context_acceptance import reject_excess_tokens


class OverBudgetCounter:
    def __init__(self) -> None:
        self.calls: list[ChatMessages] = []

    def count(self, messages: ChatMessages) -> int:
        self.calls.append(messages)
        return 3072


class ForbiddenInference:
    def complete(
        self, *, endpoint: str, token: str, payload: Mapping[str, object],
        timeout_seconds: int,
    ) -> Mapping[str, Any]:
        raise AssertionError("over-budget probe must never generate")


def test_live_overflow_probe_reaches_token_admission_without_claim(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    settings = ModelSettings(
        model_id="overflow-probe-regression",
        upstream_url="http://127.0.0.1:8000/v1/chat/completions",
        upstream_api_key="u" * 40,
        runner_api_key="r" * 40,
        policy_sha256="a" * 64,
        journal_path=tmp_path / "inference.sqlite3",
        price_input_per_million_microusd=100000,
        price_output_per_million_microusd=100000,
        max_input_tokens=3072,
        max_output_tokens=192,
    )
    counter = OverBudgetCounter()
    service = RealCodingModelService(
        settings, inference=ForbiddenInference(), token_counter=counter,
    )
    server = ModelHttpServer(("127.0.0.1", 0), model_http_handler(service))
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        reject_excess_tokens(
            f"http://127.0.0.1:{server.server_port}", settings.runner_api_key,
            settings.journal_path,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
        assert not thread.is_alive()
    assert len(counter.calls) == 1
    assert "Inspect this input:" in counter.calls[0][1][1]
