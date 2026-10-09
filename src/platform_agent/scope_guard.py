from __future__ import annotations

from collections.abc import Iterable
from pathlib import PurePosixPath
from typing import Protocol

_RESERVED_SCOPE_ROOTS = frozenset({".eng", ".git"})


class ScopeGuardError(ValueError):
    """Raised when a platform execution request delegates unsafe filesystem scope."""


class FilesystemScopeRequest(Protocol):
    task_id: str
    read_paths: tuple[str, ...]
    write_paths: tuple[str, ...]


def normalize_authority_path(value: str, *, field: str) -> PurePosixPath:
    if not isinstance(value, str) or not value:
        raise ScopeGuardError(f"{field} must be a non-empty path")
    if "\\" in value or value.startswith("/") or value.endswith("/"):
        raise ScopeGuardError(f"{field} must be canonical relative POSIX form")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".."} for part in path.parts):
        raise ScopeGuardError(f"{field} contains traversal or ambiguity")
    if path.as_posix() != value:
        raise ScopeGuardError(f"{field} must be canonical relative POSIX form")
    if path == PurePosixPath("."):
        raise ScopeGuardError(
            f"{field} cannot delegate the whole workspace; explicit paths are required"
        )
    if path.parts and path.parts[0] in _RESERVED_SCOPE_ROOTS:
        raise ScopeGuardError(f"{field} cannot target reserved runtime/VCS metadata")
    return path


def path_is_covered(path: PurePosixPath, roots: tuple[PurePosixPath, ...]) -> bool:
    return any(path == root or path.is_relative_to(root) for root in roots)


def validate_execution_request_scopes(requests: Iterable[FilesystemScopeRequest]) -> None:
    """Validate every requested filesystem authority before admission begins."""
    for request in requests:
        reads = tuple(
            normalize_authority_path(value, field=f"{request.task_id}.read_paths")
            for value in request.read_paths
        )
        writes = tuple(
            normalize_authority_path(value, field=f"{request.task_id}.write_paths")
            for value in request.write_paths
        )
        if len(reads) != len(set(reads)):
            raise ScopeGuardError(f"{request.task_id}.read_paths contains duplicates")
        if len(writes) != len(set(writes)):
            raise ScopeGuardError(f"{request.task_id}.write_paths contains duplicates")
        for write in writes:
            if not path_is_covered(write, reads):
                raise ScopeGuardError(
                    f"{request.task_id} write path is not covered by explicit read scope"
                )
