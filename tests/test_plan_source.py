from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from platform_agent.plan_source import PlanSourceError, inspect_plan_source


def test_fingerprint_is_content_deterministic(tmp_path: Path) -> None:
    payload = b"deterministic-xlsx-placeholder"

    first = tmp_path / "first.xlsx"
    second = tmp_path / "second.xlsx"

    first.write_bytes(payload)
    second.write_bytes(payload)

    first_result = inspect_plan_source(first)
    second_result = inspect_plan_source(second)

    assert first_result == second_result
    assert first_result.sha256 == hashlib.sha256(payload).hexdigest()
    assert first_result.size_bytes == len(payload)
    assert json.loads(first_result.to_canonical_json()) == first_result.as_dict()


def test_rejects_unsupported_plan_format(tmp_path: Path) -> None:
    source = tmp_path / "plan.csv"
    source.write_text("task,status", encoding="utf-8")

    with pytest.raises(PlanSourceError, match="unsupported plan format"):
        inspect_plan_source(source)


def test_rejects_empty_source(tmp_path: Path) -> None:
    source = tmp_path / "plan.xlsx"
    source.touch()

    with pytest.raises(PlanSourceError, match="must not be empty"):
        inspect_plan_source(source)


def test_rejects_oversized_source_before_hashing(tmp_path: Path) -> None:
    source = tmp_path / "plan.xlsx"
    source.write_bytes(b"12345")

    with pytest.raises(PlanSourceError, match="exceeds 4 byte limit"):
        inspect_plan_source(source, max_bytes=4)


def test_rejects_symbolic_link(tmp_path: Path) -> None:
    target = tmp_path / "target.xlsx"
    target.write_bytes(b"workbook")

    source = tmp_path / "plan.xlsx"

    try:
        source.symlink_to(target)
    except OSError:
        pytest.skip("symbolic links are not available on this platform")

    with pytest.raises(PlanSourceError, match="must not be a symbolic link"):
        inspect_plan_source(source)
