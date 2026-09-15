from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from types import SimpleNamespace

import pytest

import platform_agent.sandbox_admission as sandbox
from platform_agent.capability_router import CapabilityRegistry
from platform_agent.plan_admission import PlanAdmission, PlanAdmissionError, candidate_sha256
from platform_agent.sandbox_admission import (
    ApprovalGrant,
    ConstraintGrant,
    ExecutionRequest,
    ResourceRequest,
    SandboxAdmissionError,
    admit_dispatch_to_sandbox,
    verify_sandbox_admission,
)

TASK = "tsk_AAAAAAAAAAAAAAAAAAAA"
SOURCE_SHA = "a" * 64
PLAN_GRAPH_ID = "https://foundry.engineering/schemas/plangraph/v1/plan_graph.json"
POLICY_SCHEMA_ID = "https://foundry.engineering/schemas/policy/v1/execution_policy.json"
GRANT_SCHEMA_ID = "https://foundry.engineering/schemas/execution/v1/execution_grant.json"
APPROVAL_EVIDENCE = "sha256:" + "e" * 64
CONSTRAINT_EVIDENCE = "sha256:" + "c" * 64


def _canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _hash(value: object) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _derive_grant_id(value: object) -> str:
    assert isinstance(value, dict)
    material = {key: item for key, item in value.items() if key != "grant_id"}
    return "sgr_" + _hash(material)[:32]


def _validate_grant(value: object) -> None:
    assert isinstance(value, dict)
    if value.get("schema_version") != "execution-grant.v1":
        raise ValueError("wrong grant schema")
    if value.get("grant_id") != _derive_grant_id(value):
        raise ValueError("wrong grant identity")


def _policy() -> dict[str, object]:
    return {
        "schema_version": "execution-policy.v1",
        "policy_id": "pol_foundry_default",
        "version": "1.0.0",
        "classification": {
            "level": "internal",
            "pii": "none",
            "secret_handling": "forbidden",
        },
        "retention": {"max_days": 30, "delete_on_completion": False},
        "redaction": {"json_pointers": [], "replacement": "[REDACTED]"},
        "approvals": [
            {
                "approval_id": "approval_operator",
                "kind": "operator",
                "min_count": 1,
                "evidence_required": True,
            }
        ],
        "sandbox": {
            "filesystem": {
                "read_roots": ["src", "tests"],
                "write_roots": ["src"],
                "allow_delete": False,
                "max_file_bytes": 1048576,
            },
            "tools": {"allowed_tool_ids": ["tool_pytest", "tool_file.write"]},
            "network": {"mode": "deny", "allowed_hosts": [], "allowed_ports": []},
            "environment": {
                "allowed_keys": ["HOME", "LANG"],
                "denied_keys": ["GITHUB_TOKEN"],
            },
            "resources": {
                "wall_time_seconds": 300,
                "cpu_time_seconds": 200,
                "memory_mb": 2048,
                "max_processes": 32,
                "max_output_bytes": 1048576,
            },
        },
    }


def _payload(*capabilities: str) -> dict[str, object]:
    return {
        "type": "capability.advertise",
        "capabilities": [
            {
                "capability_id": capability,
                "version": "1.0.0",
                "input_schema": f"schema://{capability}/input",
                "output_schema": f"schema://{capability}/output",
            }
            for capability in capabilities
        ],
    }


def _registry() -> CapabilityRegistry:
    return CapabilityRegistry.from_apv1_payloads(
        {"backend-agent": _payload("cap_backend.service")}
    )


def _plan(policy: dict[str, object], *, path_scope: list[str] | None = None) -> dict[str, object]:
    if path_scope is None:
        path_scope = ["src", "tests"]
    return {
        "plan_id": "pln_ABCDEFGHIJKLMNOPQRSTUVWXYZ12",
        "source": {"sha256": SOURCE_SHA},
        "policy_ref": {
            "policy_id": "pol_foundry_default",
            "policy_sha256": _hash(policy),
            "jurisdiction": "global",
            "constraints": ["change-ticket"],
        },
        "tasks": [
            {
                "task_id": TASK,
                "dependencies": [],
                "preconditions": [],
                "acceptance_gates": [{"gate_id": "gate_ok"}],
                "routing": {
                    "owner": "backend-agent",
                    "required_capabilities": [],
                },
                "target": {
                    "repo": "foundry-engineering/example",
                    "path_scope": path_scope,
                },
            }
        ],
    }


def _admission(plan: object) -> PlanAdmission:
    candidate = candidate_sha256(plan)
    material = {
        "schema_version": "foundry.plan-admission.v1",
        "plan_id": "pln_ABCDEFGHIJKLMNOPQRSTUVWXYZ12",
        "source_sha256": SOURCE_SHA,
        "candidate_sha256": candidate,
        "approval_evidence_ref": APPROVAL_EVIDENCE,
        "protocol_schema_id": PLAN_GRAPH_ID,
        "dependencies_reviewed": True,
        "routing_reviewed": True,
    }
    return PlanAdmission(admission_id="adm_" + _hash(material)[:32], **material)


def _request(**overrides: object) -> ExecutionRequest:
    values: dict[str, object] = {
        "task_id": TASK,
        "repo": "foundry-engineering/example",
        "read_paths": ("src", "tests"),
        "write_paths": ("src/generated.txt",),
        "allow_delete": False,
        "max_file_bytes": 524288,
        "tool_ids": ("tool_file.write", "tool_pytest"),
        "network_hosts": (),
        "network_ports": (),
        "environment_keys": ("HOME",),
        "resources": ResourceRequest(
            wall_time_seconds=120,
            cpu_time_seconds=100,
            memory_mb=1024,
            max_processes=8,
            max_output_bytes=262144,
        ),
        "approvals": (
            ApprovalGrant(
                approval_id="approval_operator",
                approver_ids=("operator-1",),
                evidence_refs=(APPROVAL_EVIDENCE,),
            ),
        ),
        "constraints": (
            ConstraintGrant(
                constraint="change-ticket",
                evidence_ref=CONSTRAINT_EVIDENCE,
            ),
        ),
    }
    values.update(overrides)
    return ExecutionRequest(**values)  # type: ignore[arg-type]


def _install_protocol_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    def load(name: str):
        if name == "agent_protocol.execution_policy":
            return SimpleNamespace(
                EXECUTION_POLICY_ID=POLICY_SCHEMA_ID,
                validate_execution_policy=lambda value: None,
                execution_policy_sha256=_hash,
            )
        if name == "agent_protocol.execution_grant":
            return SimpleNamespace(
                EXECUTION_GRANT_ID=GRANT_SCHEMA_ID,
                validate_execution_grant=_validate_grant,
                derive_execution_grant_id=_derive_grant_id,
            )
        raise ModuleNotFoundError(name)

    monkeypatch.setattr(sandbox.importlib, "import_module", load)


def _admit(
    monkeypatch: pytest.MonkeyPatch,
    *,
    policy: dict[str, object] | None = None,
    plan: dict[str, object] | None = None,
    request: ExecutionRequest | None = None,
):
    _install_protocol_runtime(monkeypatch)
    active_policy = policy or _policy()
    active_plan = plan or _plan(active_policy)
    active_request = request or _request()
    return admit_dispatch_to_sandbox(
        active_plan,
        admission=_admission(active_plan),
        registry=_registry(),
        requests=(active_request,),
        policies={"pol_foundry_default": active_policy},
    )


def test_valid_admission_emits_canonical_execution_grant(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admitted = _admit(monkeypatch)

    assert admitted.sandbox_admission_id.startswith("sad_")
    assert len(admitted.grants) == 1
    grant = admitted.grants[0]
    assert grant.schema_version == "execution-grant.v1"
    assert grant.grant_id == _derive_grant_id(grant.as_dict())
    assert grant.authority.dispatch_id == admitted.dispatch_id
    assert grant.authority.plan_admission_id == admitted.plan_admission_id
    assert grant.policy_ref.policy_sha256 == _hash(_policy())
    assert grant.approvals[0].evidence_refs == (APPROVAL_EVIDENCE,)
    assert grant.constraint_evidence[0].evidence_ref == CONSTRAINT_EVIDENCE


def test_admission_is_deterministic_and_recomputable(monkeypatch: pytest.MonkeyPatch) -> None:
    policy = _policy()
    plan = _plan(policy)
    request = _request()
    _install_protocol_runtime(monkeypatch)
    kwargs = {
        "admission": _admission(plan),
        "registry": _registry(),
        "requests": (request,),
        "policies": {"pol_foundry_default": policy},
    }
    admitted = admit_dispatch_to_sandbox(plan, **kwargs)  # type: ignore[arg-type]
    repeated = admit_dispatch_to_sandbox(plan, **kwargs)  # type: ignore[arg-type]

    assert admitted.as_dict() == repeated.as_dict()
    verify_sandbox_admission(admitted, plan, **kwargs)  # type: ignore[arg-type]


def test_tampered_grant_fails_recomputation(monkeypatch: pytest.MonkeyPatch) -> None:
    policy = _policy()
    plan = _plan(policy)
    request = _request()
    _install_protocol_runtime(monkeypatch)
    admitted = admit_dispatch_to_sandbox(
        plan,
        admission=_admission(plan),
        registry=_registry(),
        requests=(request,),
        policies={"pol_foundry_default": policy},
    )
    tampered_grant = replace(admitted.grants[0], max_file_bytes=999999)
    tampered = replace(admitted, grants=(tampered_grant,))

    with pytest.raises(SandboxAdmissionError, match="recomputed authority"):
        verify_sandbox_admission(
            tampered,
            plan,
            admission=_admission(plan),
            registry=_registry(),
            requests=(request,),
            policies={"pol_foundry_default": policy},
        )


def test_protocol_contracts_unavailable_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        sandbox.importlib,
        "import_module",
        lambda name: (_ for _ in ()).throw(ModuleNotFoundError(name)),
    )
    policy = _policy()
    plan = _plan(policy)

    with pytest.raises(SandboxAdmissionError, match="contracts are unavailable"):
        admit_dispatch_to_sandbox(
            plan,
            admission=_admission(plan),
            registry=_registry(),
            requests=(_request(),),
            policies={"pol_foundry_default": policy},
        )


def test_wrong_execution_contract_version_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    def load(name: str):
        if name == "agent_protocol.execution_policy":
            return SimpleNamespace(
                EXECUTION_POLICY_ID=POLICY_SCHEMA_ID,
                validate_execution_policy=lambda value: None,
                execution_policy_sha256=_hash,
            )
        return SimpleNamespace(
            EXECUTION_GRANT_ID="https://foundry.engineering/schemas/execution/v2/execution_grant.json",
            validate_execution_grant=_validate_grant,
            derive_execution_grant_id=_derive_grant_id,
        )

    monkeypatch.setattr(sandbox.importlib, "import_module", load)
    policy = _policy()
    plan = _plan(policy)

    with pytest.raises(SandboxAdmissionError, match="required execution contracts"):
        admit_dispatch_to_sandbox(
            plan,
            admission=_admission(plan),
            registry=_registry(),
            requests=(_request(),),
            policies={"pol_foundry_default": policy},
        )


def test_policy_hash_mismatch_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_protocol_runtime(monkeypatch)
    policy = _policy()
    plan = _plan(policy)
    policy_ref = plan["policy_ref"]
    assert isinstance(policy_ref, dict)
    policy_ref["policy_sha256"] = "f" * 64

    with pytest.raises(SandboxAdmissionError, match="hash does not match"):
        admit_dispatch_to_sandbox(
            plan,
            admission=_admission(plan),
            registry=_registry(),
            requests=(_request(),),
            policies={"pol_foundry_default": policy},
        )


def test_requests_must_exactly_match_ready_assignments(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_protocol_runtime(monkeypatch)
    policy = _policy()
    plan = _plan(policy)

    with pytest.raises(SandboxAdmissionError, match="exactly match"):
        admit_dispatch_to_sandbox(
            plan,
            admission=_admission(plan),
            registry=_registry(),
            requests=(),
            policies={"pol_foundry_default": policy},
        )


def test_empty_target_scope_denies_filesystem_execution(monkeypatch: pytest.MonkeyPatch) -> None:
    policy = _policy()
    plan = _plan(policy, path_scope=[])

    with pytest.raises(SandboxAdmissionError, match="path_scope is empty"):
        _admit(monkeypatch, policy=policy, plan=plan)


@pytest.mark.parametrize(
    ("request", "message"),
    [
        (_request(repo="foundry-engineering/other"), "repo does not match"),
        (_request(write_paths=("docs/out.txt",)), "not covered by requested read scope"),
        (_request(write_paths=("src/../escape.txt",)), "path traversal"),
        (_request(write_paths=(".eng/owned.txt",)), "runtime metadata"),
        (_request(max_file_bytes=2097152), "max_file_bytes exceeds policy"),
        (_request(allow_delete=True), "delete is denied"),
        (_request(tool_ids=("tool_shell",)), "tools denied by policy"),
        (
            _request(network_hosts=("api.github.com",), network_ports=(443,)),
            "network access is denied",
        ),
        (_request(environment_keys=("GITHUB_TOKEN",)), "environment request is denied"),
        (
            _request(
                resources=ResourceRequest(
                    wall_time_seconds=301,
                    cpu_time_seconds=100,
                    memory_mb=1024,
                    max_processes=8,
                    max_output_bytes=262144,
                )
            ),
            "resource request exceeds policy",
        ),
        (_request(approvals=()), "approval grants do not exactly match"),
        (
            _request(
                approvals=(
                    ApprovalGrant(
                        approval_id="approval_operator",
                        approver_ids=("operator-1",),
                        evidence_refs=(),
                    ),
                )
            ),
            "approval evidence is required",
        ),
        (_request(constraints=()), "constraint evidence does not exactly match"),
    ],
)
def test_policy_and_scope_violations_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
    request: ExecutionRequest,
    message: str,
) -> None:
    with pytest.raises(SandboxAdmissionError, match=message):
        _admit(monkeypatch, request=request)


def test_stale_plan_admission_stops_before_sandbox(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_protocol_runtime(monkeypatch)
    policy = _policy()
    plan = _plan(policy)
    admitted_plan = _admission(plan)
    plan["source"] = {"sha256": "9" * 64}

    with pytest.raises(PlanAdmissionError, match="source hash mismatch"):
        admit_dispatch_to_sandbox(
            plan,
            admission=admitted_plan,
            registry=_registry(),
            requests=(_request(),),
            policies={"pol_foundry_default": policy},
        )
