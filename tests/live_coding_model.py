"""Start the deployable model server for the signed-worker acceptance."""
from __future__ import annotations

import http.client
import json
from dataclasses import replace
import secrets
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from engineering_agent.model_host import MODEL_ID as MODEL_ID, DEFAULT_PROFILE, RUNTIME
from engineering_agent.model_profiles import ModelProfile


def _port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _wait_ready(server: subprocess.Popen[bytes], port: int, identity: dict[str, str]) -> None:
    deadline = time.monotonic() + 85
    while time.monotonic() < deadline:
        if server.poll() is not None:
            raise RuntimeError("managed model host exited before readiness")
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
        try:
            conn.request("GET", "/readyz")
            with conn.getresponse() as response:
                if response.status == 200:
                    body = json.loads(response.read(16385))
                    if any(body.get(key) != value for key, value in identity.items()):
                        raise RuntimeError("managed host identity differs from its approved model profile")
                    return
        except (OSError, http.client.HTTPException):
            pass
        finally:
            conn.close()
        time.sleep(0.2)
    raise TimeoutError("managed model host did not become ready")


@contextmanager
def live_model(directory: Path, assets: Path, *, max_output_tokens: int = 192,
               approved_profile: ModelProfile = DEFAULT_PROFILE) -> Iterator[tuple[str, str]]:
    """Yield the managed Runner endpoint and its temporary test credential."""
    if type(max_output_tokens) is not int or not 128 <= max_output_tokens <= 512:
        raise ValueError("explicit bounded test-model output allowance required")
    directory.mkdir(mode=0o700)
    state = directory / "state"
    runtime = directory / "runtime"
    state.mkdir(mode=0o700)
    runtime.mkdir(mode=0o700)
    token = secrets.token_urlsafe(40)
    secret = directory / "runner-token"
    secret.touch(mode=0o600, exist_ok=False)
    secret.write_text(token + "\n", encoding="ascii")
    profile = replace(approved_profile, max_output_tokens=max_output_tokens)
    profile_path = directory / "approved-model.json"
    profile_path.touch(mode=0o600, exist_ok=False)
    profile_path.write_text(json.dumps(profile.as_payload()), encoding="utf-8")
    port, engine_port = _port(), _port()
    while engine_port == port:
        engine_port = _port()
    argv = [
        sys.executable, "-m", "engineering_agent.model_host", "serve",
        "--assets", str(assets), "--state-dir", str(state), "--runtime-dir", str(runtime),
        "--runner-token-file", str(secret), "--policy-sha256", "a" * 64,
        "--input-tariff", "100000", "--output-tariff", "100000",
        "--port", str(port), "--engine-port", str(engine_port), "--profile", str(profile_path),
    ]
    try:
        with subprocess.Popen(argv, stdin=subprocess.DEVNULL) as server:
            try:
                _wait_ready(server, port, {**profile.identity(), "runtime_sha256": RUNTIME.sha256})
                yield f"http://127.0.0.1:{port}", token
            finally:
                if server.poll() is None:
                    server.terminate()
                try:
                    status = server.wait(timeout=135)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait(timeout=5)
                    raise
                if status != 0:
                    raise RuntimeError(f"managed model host exited with code {status}")
    finally:
        secret.unlink(missing_ok=True)
