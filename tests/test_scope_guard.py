from __future__ import annotations

from dataclasses import dataclass

import pytest

from platform_agent.scope_guard import ScopeGuardError, validate_execution_request_scopes


@dataclass(frozen=True)
class Request:
    task_id: str
    read_paths: tuple[str, ...]
    write_paths: tuple[str, ...]


def test_whole_workspace_scope_is_rejected() -> None:
    with pytest.raises(ScopeGuardError, match="whole workspace"):
        validate_execution_request_scopes(
            [Request("task", (".",), ())]
        )


def test_runtime_and_vcs_metadata_are_rejected() -> None:
    for value in (".eng/evidence", ".git/config"):
        with pytest.raises(ScopeGuardError, match="reserved runtime/VCS"):
            validate_execution_request_scopes(
                [Request("task", (value,), ())]
            )


def test_write_scope_requires_explicit_read_coverage() -> None:
    with pytest.raises(ScopeGuardError, match="not covered"):
        validate_execution_request_scopes(
            [Request("task", ("tests",), ("src",))]
        )


def test_explicit_file_and_directory_scopes_are_allowed() -> None:
    validate_execution_request_scopes(
        [
            Request(
                "task",
                ("pyproject.toml", "src"),
                ("pyproject.toml", "src/api"),
            )
        ]
    )
