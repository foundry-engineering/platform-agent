"""Start the checksum-pinned coding model used by the signed-worker acceptance."""
from __future__ import annotations

import os
import secrets
import subprocess
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from engineering_agent.live_model_probe import (
    _available_memory_bytes, _pinned_file, _port, _wait_ready,
)

MODEL_ID = "Qwen/Qwen2.5-Coder-7B-Instruct"
WEIGHTS_SHA256 = "509287f78cb4d4cf6b3843734733b914b2c158e43e22a7f4bf5e963800894d3c"
SERVER_SHA256 = "afbe5310f53ea1b1f280aaa2952f4377c65d678af46e7d14ffc830ef98291ea6"


@contextmanager
def live_model(directory: Path, assets: Path) -> Iterator[tuple[str, str]]:
    """Yield the private inference endpoint and its temporary credential."""
    weights = _pinned_file(assets / "qwen2.5-coder-7b-instruct-q4_k_m.gguf", WEIGHTS_SHA256)
    binary = _pinned_file(assets / "llama-b12244" / "llama-server", SERVER_SHA256)
    if _available_memory_bytes() < weights.stat().st_size + 1536 * 1024**2:
        raise RuntimeError("insufficient free memory for live coding acceptance")
    directory.mkdir(mode=0o700)
    port = _port()
    token = secrets.token_urlsafe(40)
    secret = directory / "upstream.key"
    with secret.open("x") as stream:
        secret.chmod(0o600)
        stream.write(token + "\n")
    argv = [
        str(binary), "--model", str(weights), "--alias", MODEL_ID,
        "--ctx-size", "2048", "--parallel", "1", "--threads",
        str(min(os.cpu_count() or 1, 4)), "--gpu-layers", "0", "--device", "none",
        "--batch-size", "256", "--ubatch-size", "128",
        "--host", "127.0.0.1", "--port", str(port), "--api-key-file", str(secret),
        "--no-webui", "--no-slots", "--no-agent", "--offline", "--no-warmup",
    ]
    try:
        with (directory / "server.log").open("wb") as log, subprocess.Popen(
            argv, stdin=subprocess.DEVNULL, stdout=log, stderr=log,
            cwd=directory, env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
        ) as server:
            try:
                _wait_ready(server, port, token)
                yield f"http://127.0.0.1:{port}/v1/chat/completions", token
            finally:
                server.terminate()
                try:
                    server.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait(timeout=5)
    finally:
        secret.unlink(missing_ok=True)
