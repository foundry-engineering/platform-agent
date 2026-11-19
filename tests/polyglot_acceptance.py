"""Actual fixed Python, JavaScript and Go verification of model-produced files."""

from __future__ import annotations

from pathlib import Path

from engineering_agent.sandbox_matrix import TrustedSandboxMatrix
from engineering_agent.sandbox_verifier import TrustedCheck, TrustedSandboxProfile

POLYGLOT_OBJECTIVE = (
    "Repair weighted totals in src/app.py, src/total.mjs and src/total.go: sum unit price TIMES quantity. "
    "Keep Python total_cents(lines) for integer pairs, JavaScript export function totalCents(lines), "
    "and Go package main func totalCents(lines [][2]int64) int64. Preserve exact integer arithmetic. "
    "Output exactly these three complete minimal files, no comments or docstrings."
)


NODE = (
    "docker.io/library/node@sha256:9d266751ca3d7fdbe651c878ffd5ad0a42fed49a18c283509267c97f025b7496"
)
GO = "docker.io/library/golang@sha256:4fa7c968ba93f1635670522dbb01a2c78150443e1385746924566079f36570ea"


def configure_polyglot(
    workspace: Path, python_image: str
) -> tuple[tuple[str, ...], TrustedSandboxMatrix]:
    (workspace / "src/total.mjs").write_text(
        "export function totalCents(lines){return lines.reduce((s,[p,q])=>s+p+q,0)}\n"
    )
    (workspace / "src/total.go").write_text(
        "package main\nfunc totalCents(lines [][2]int64) int64 { var total int64; for _, line := range lines { total += line[0]+line[1] }; return total }\n"
    )
    (workspace / "tests/check.mjs").write_text(
        "import {totalCents} from '../src/total.mjs';import assert from 'node:assert/strict';\n"
        "assert.equal(totalCents([[145,3],[80,2],[500,0]]),595);assert.equal(totalCents([]),0);\n"
        "assert.equal(totalCents([[2**40,13]]),13*2**40);assert.equal(totalCents([[-8,3],[10,2]]),-4);\n"
    )
    (workspace / "tests/check.go").write_text(
        'package main\nfunc main(){ if totalCents([][2]int64{{145,3},{80,2},{500,0}})!=595 { panic("quantity weighted total") }; '
        'if totalCents(nil)!=0 { panic("empty") }; if totalCents([][2]int64{{1<<40,13}})!=13*(1<<40) { panic("exact integer") }; '
        'if totalCents([][2]int64{{-8,3},{10,2}})!=-4 { panic("negative line") } }\n'
    )
    matrix = TrustedSandboxMatrix(
        (
            TrustedSandboxProfile(
                image=python_image,
                diagnostic_bytes=384,
                timeout_seconds=60,
                checks=(
                    TrustedCheck(
                        "python-check",
                        (
                            "/usr/local/bin/python",
                            "-B",
                            "-m",
                            "unittest",
                            "discover",
                            "-s",
                            "/workspace/tests",
                        ),
                    ),
                ),
            ),
            TrustedSandboxProfile(
                image=NODE,
                diagnostic_bytes=384,
                timeout_seconds=60,
                checks=(
                    TrustedCheck(
                        "javascript-check", ("/usr/local/bin/node", "/workspace/tests/check.mjs")
                    ),
                ),
            ),
            TrustedSandboxProfile(
                image=GO,
                compiled_execution=True,
                diagnostic_bytes=384,
                timeout_seconds=60,
                memory_mb=1024,
                pids_limit=128,
                checks=(
                    TrustedCheck(
                        "go-check",
                        (
                            "/usr/bin/env",
                            "GOCACHE=/tmp/go-cache",
                            "GOPATH=/tmp/go",
                            "GOPROXY=off",
                            "GOSUMDB=off",
                            "GOTOOLCHAIN=local",
                            "GOMAXPROCS=1",
                            "/bin/sh",
                            "-eu",
                            "-c",
                            "cp /workspace/src/total.go /workspace/tests/check.go /tmp/; /usr/local/go/bin/go run -p=1 /tmp/total.go /tmp/check.go",
                        ),
                    ),
                ),
            ),
        )
    )
    return ("src/app.py", "src/total.go", "src/total.mjs"), matrix


def report_model_errors(monkeypatch) -> None:
    """Expose only the isolated test server's bounded public error response."""
    import http.client

    original = http.client.HTTPConnection.getresponse

    def response(connection):
        result = original(connection)
        if not 200 <= result.status < 300:
            body = result.read(4096).decode("utf-8", errors="replace")
            raise AssertionError(f"isolated model response HTTP {result.status}: {body}")
        return result

    monkeypatch.setattr(http.client.HTTPConnection, "getresponse", response)
