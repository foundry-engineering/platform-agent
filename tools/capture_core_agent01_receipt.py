"""Publish only bounded fixture metrics and immutable source IDs, never Core logs."""
from __future__ import annotations

import argparse
import json
import re
import subprocess
from dataclasses import replace
from pathlib import Path

from engineering_agent.model_host import RUNTIME
from engineering_agent.model_profiles import load_model_profile

CORE_OBJECTS = (
    "platform-ui", "src", "db", "pyproject.toml", "uv.lock",
    "scripts/agent01_live_acceptance.py", "scripts/verify_agent01_delivery_bundle.py",
)


def git_id(root: Path, reference: str) -> str:
    value = subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", "--verify", reference], text=True,
        timeout=10, stderr=subprocess.DEVNULL,
    ).strip()
    if re.fullmatch(r"[a-f0-9]{40}", value) is None:
        raise ValueError("immutable source object ID required")
    return value


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("core", "platform", "profile", "log", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--core-commit", required=True)
    parser.add_argument("--platform-commit", required=True)
    parser.add_argument("--run-url", required=True)
    args = parser.parse_args()
    if git_id(args.core, "HEAD") != args.core_commit or git_id(args.platform, "HEAD") != args.platform_commit:
        raise ValueError("acceptance source differs from its frozen commits")
    if re.fullmatch(r"https://github.com/foundry-engineering/platform-agent/actions/runs/[0-9]+", args.run_url) is None:
        raise ValueError("actual workflow provenance required")
    profile = replace(load_model_profile(args.profile), max_output_tokens=192)
    text = args.log.read_text(encoding="utf-8")
    prefix = "Actual browser-authorized Agent 01 run through private delivery:"
    lines = [line.split(prefix, 1)[1].strip() for line in text.splitlines() if prefix in line]
    if len(lines) != 1 or "Agent 01 cold recovery passed:" not in text:
        raise ValueError("actual delivery and cold recovery evidence required")
    result = json.loads(lines[0])
    if result.get("model") != profile.model_id or result.get("profile") != profile.identity() or result.get("runtimeSha256") != RUNTIME.sha256:
        raise ValueError("actual model/runtime identity differs from the selected profile")
    metrics = {}
    for name in ("rounds", "inputTokens", "outputTokens"):
        value = result.get(name)
        if type(value) is not int or not 0 < value <= 100_000:
            raise ValueError("bounded actual inference metrics required")
        metrics[name] = value
    digest = result.get("zipSha256")
    if not isinstance(digest, str) or re.fullmatch(r"[a-f0-9]{64}", digest) is None:
        raise ValueError("sealed delivered bytes required")
    receipt = {
        "schemaVersion": "foundry.core-agent01-qualified-runtime.v1",
        "acceptanceWorkflowCommit": git_id(Path(__file__).resolve().parents[1], "HEAD"),
        "runUrl": args.run_url, "coreCommit": args.core_commit,
        "platformCommit": args.platform_commit,
        "coreRuntimeObjectIds": {path: git_id(args.core, "HEAD:" + path) for path in CORE_OBJECTS},
        "platformRuntimeObjectIds": {path: git_id(args.platform, "HEAD:" + path)
            for path in ("src", "tests", "pyproject.toml", "uv.lock")},
        "modelId": profile.model_id, "profile": profile.identity(),
        "runtimeSha256": RUNTIME.sha256, "zipSha256": digest, **metrics,
        "coldRecoveryPassed": True, "realMalwareScanRequired": True,
        "enterpriseReleaseApproved": False,
    }
    args.output.write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n")
    print(json.dumps(receipt, sort_keys=True))


if __name__ == "__main__":
    main()
