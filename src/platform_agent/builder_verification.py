"""Strict owner-configured single-runtime or polyglot Builder verification."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

from engineering_agent.builder import IndependentVerifier
from engineering_agent.sandbox_matrix import DockerSandboxMatrixVerifier, TrustedSandboxMatrix
from engineering_agent.sandbox_verifier import (
    DockerSandboxVerifier,
    TrustedCheck,
    TrustedSandboxProfile,
)

from .builder_work_units import BuilderWorkUnit
from .core_worker_service import WorkerConfigurationError


def _profile(value: object) -> TrustedSandboxProfile:
    allowed = {
        "image",
        "checks",
        "timeout_seconds",
        "memory_mb",
        "cpu_count",
        "pids_limit",
        "diagnostic_bytes",
        "compiled_execution",
    }
    if (
        not isinstance(value, dict)
        or not {"image", "checks"} <= set(value)
        or not set(value) <= allowed
        or not isinstance(value["checks"], list)
    ):
        raise WorkerConfigurationError("exact trusted sandbox profile required")
    checks: list[TrustedCheck] = []
    for check in value["checks"]:
        if (
            not isinstance(check, dict)
            or set(check) != {"check_id", "argv"}
            or not isinstance(check["argv"], list)
        ):
            raise WorkerConfigurationError("fixed trusted checker argv required")
        checks.append(TrustedCheck(check["check_id"], tuple(check["argv"])))
    data: dict[str, Any] = {**value, "checks": tuple(checks)}
    return TrustedSandboxProfile(**data)


def verification_ports(
    *, value: object, workspace: Path, evidence_dir: Path, work_units: tuple[BuilderWorkUnit, ...]
) -> tuple[IndependentVerifier, dict[str, IndependentVerifier] | None, bool]:
    diagnose_first = False
    configuration: TrustedSandboxMatrix | TrustedSandboxProfile
    if isinstance(value, dict) and "schemaVersion" in value:
        if (
            set(value) != {"schemaVersion", "profiles", "diagnoseFirst"}
            or value["schemaVersion"] != "foundry.builder-sandbox-matrix.v1"
            or not isinstance(value["profiles"], list)
            or not 1 <= len(value["profiles"]) <= 6
            or type(value["diagnoseFirst"]) is not bool
        ):
            raise WorkerConfigurationError("exact trusted sandbox matrix profile required")
        configuration = TrustedSandboxMatrix(tuple(_profile(item) for item in value["profiles"]))
        diagnose_first = value["diagnoseFirst"]
    else:
        configuration = _profile(value)

    def port(check_ids: tuple[str, ...] | None = None) -> IndependentVerifier:
        if isinstance(configuration, TrustedSandboxMatrix):
            matrix = configuration if check_ids is None else configuration.subset(check_ids)
            return DockerSandboxMatrixVerifier(
                workspace=workspace, evidence_dir=evidence_dir, matrix=matrix
            )
        selected = configuration
        if check_ids is not None:
            checks = {check.check_id: check for check in selected.checks}
            if any(check_id not in checks for check_id in check_ids):
                raise WorkerConfigurationError(
                    "work-unit checks must exist in trusted sandbox profiles"
                )
            selected = replace(selected, checks=tuple(checks[key] for key in check_ids))
        return DockerSandboxVerifier(
            workspace=workspace, evidence_dir=evidence_dir, profile=selected
        )

    return (
        port(),
        ({unit.unit_id: port(unit.check_ids) for unit in work_units} if work_units else None),
        diagnose_first,
    )
