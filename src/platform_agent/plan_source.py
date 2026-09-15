from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Final

PLAN_SOURCE_SCHEMA: Final[str] = "foundry.plan-source.v1"
DEFAULT_MAX_PLAN_BYTES: Final[int] = 64 * 1024 * 1024

_SUPPORTED_FORMATS: Final[dict[str, str]] = {
    ".xlsx": "xlsx",
}


class PlanSourceError(ValueError):
    """Raised when a plan source cannot be accepted deterministically."""


@dataclass(frozen=True, slots=True)
class PlanSourceFingerprint:
    schema: str
    format: str
    sha256: str
    size_bytes: int

    def as_dict(self) -> dict[str, str | int]:
        return {
            "schema": self.schema,
            "format": self.format,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
        }

    def to_canonical_json(self) -> str:
        return json.dumps(
            self.as_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )


def _detect_format(path: Path) -> str:
    suffix = path.suffix.lower()

    try:
        return _SUPPORTED_FORMATS[suffix]
    except KeyError as exc:
        supported = ", ".join(sorted(_SUPPORTED_FORMATS))
        raise PlanSourceError(
            f"unsupported plan format {suffix or '<none>'}; supported: {supported}"
        ) from exc


def inspect_plan_source(
    source: str | Path,
    *,
    max_bytes: int = DEFAULT_MAX_PLAN_BYTES,
) -> PlanSourceFingerprint:
    """Validate and fingerprint an immutable view of a plan source.

    Host-specific path and timestamp metadata are deliberately excluded from
    the returned fingerprint. Identical workbook bytes therefore produce the
    same canonical identity on every machine.
    """
    if max_bytes <= 0:
        raise ValueError("max_bytes must be greater than zero")

    path = Path(source)
    plan_format = _detect_format(path)

    try:
        path_before = path.lstat()
    except OSError as exc:
        raise PlanSourceError("unable to stat plan source") from exc

    if stat.S_ISLNK(path_before.st_mode):
        raise PlanSourceError("plan source must not be a symbolic link")

    if not stat.S_ISREG(path_before.st_mode):
        raise PlanSourceError("plan source must be a regular file")

    if path_before.st_size == 0:
        raise PlanSourceError("plan source must not be empty")

    if path_before.st_size > max_bytes:
        raise PlanSourceError(
            f"plan source exceeds {max_bytes} byte limit: {path_before.st_size}"
        )

    digest = hashlib.sha256()
    size = 0

    try:
        with path.open("rb") as handle:
            opened_before = os.fstat(handle.fileno())

            if (
                opened_before.st_dev != path_before.st_dev
                or opened_before.st_ino != path_before.st_ino
            ):
                raise PlanSourceError("plan source changed before reading")

            while chunk := handle.read(1024 * 1024):
                size += len(chunk)

                if size > max_bytes:
                    raise PlanSourceError(
                        f"plan source exceeds {max_bytes} byte limit while reading"
                    )

                digest.update(chunk)

            opened_after = os.fstat(handle.fileno())

    except PlanSourceError:
        raise
    except OSError as exc:
        raise PlanSourceError("unable to read plan source") from exc

    if (
        opened_before.st_size != opened_after.st_size
        or opened_before.st_mtime_ns != opened_after.st_mtime_ns
        or size != opened_after.st_size
    ):
        raise PlanSourceError("plan source changed while being fingerprinted")

    try:
        path_after = path.lstat()
    except OSError as exc:
        raise PlanSourceError("unable to re-stat plan source") from exc

    if (
        path_after.st_dev != opened_after.st_dev
        or path_after.st_ino != opened_after.st_ino
        or path_after.st_size != opened_after.st_size
        or path_after.st_mtime_ns != opened_after.st_mtime_ns
    ):
        raise PlanSourceError("plan source changed while being fingerprinted")

    return PlanSourceFingerprint(
        schema=PLAN_SOURCE_SCHEMA,
        format=plan_format,
        sha256=digest.hexdigest(),
        size_bytes=size,
    )
