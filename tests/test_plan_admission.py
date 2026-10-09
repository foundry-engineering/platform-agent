from __future__ import annotations

from types import SimpleNamespace

import pytest

import platform_agent.plan_admission as admission
from platform_agent.plan_admission import (
    PlanAdmissionError,
    PlanApproval,
    admit_plan_candidate,
    candidate_sha256,
    verify_plan_admission,
)

SOURCE_SHA = "a" * 64
EVIDENCE_REF = "sha256:" + "e" * 64
PLAN_GRAPH_ID = "https://foundry.engineering/schemas/plangraph/v1/plan_graph.json"


def _plan() -> dict[str, object]:
    return {
        "schema_version": "plangraph.v1",
        "plan_id": "pln_ABCDEFGHIJKLMNOPQRSTUVWXYZ12",
        "title": "Foundry admission test",
        "source": {"kind": "xlsx", "sha256": SOURCE_SHA, "ref": "roadmap.xlsx"},
        "policy_ref": {
            "policy_id": "pol_foundry_default",
            "policy_sha256": "b" * 64,
            "jurisdiction": "global",
            "constraints": [],
        },
        "tasks": [],
    }


def _report(plan: object, *, dependencies_column_present: bool = False) -> dict[str, object]:
    return {
        "source_sha256": SOURCE_SHA,
        "candidate_sha256": candidate_sha256(plan),
        "dependencies_column_present": dependencies_column_present,
    }


def _approval(plan: object, *, dependencies_reviewed: bool = True, routing_reviewed: bool = True) -> PlanApproval:
    return PlanApproval(
        approved_source_sha256=SOURCE_SHA,
        approved_candidate_sha256=candidate_sha256(plan),
        approval_evidence_ref=EVIDENCE_REF,
        dependencies_reviewed=dependencies_reviewed,
        routing_reviewed=routing_reviewed,
    )


def _install_validator(monkeypatch: pytest.MonkeyPatch) -> list[object]:
    seen: list[object] = []

    def validate(value: object) -> None:
        seen.append(value)

    monkeypatch.setattr(
        admission.importlib,
        "import_module",
        lambda name: SimpleNamespace(PLAN_GRAPH_ID=PLAN_GRAPH_ID, validate_plan_graph=validate),
    )
    return seen


def test_admission_binds_exact_candidate_source_and_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen = _install_validator(monkeypatch)
    plan = _plan()
    admitted = admit_plan_candidate(
        plan=plan,
        report=_report(plan),
        approval=_approval(plan),
    )

    assert seen == [plan]
    assert admitted.plan_id == plan["plan_id"]
    assert admitted.source_sha256 == SOURCE_SHA
    assert admitted.candidate_sha256 == candidate_sha256(plan)
    assert admitted.approval_evidence_ref == EVIDENCE_REF
    verify_plan_admission(plan, admitted)


def test_missing_dependency_review_fails_closed_when_column_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_validator(monkeypatch)
    plan = _plan()

    with pytest.raises(PlanAdmissionError, match="dependency review"):
        admit_plan_candidate(
            plan=plan,
            report=_report(plan, dependencies_column_present=False),
            approval=_approval(plan, dependencies_reviewed=False),
        )


def test_routing_review_is_always_required(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_validator(monkeypatch)
    plan = _plan()

    with pytest.raises(PlanAdmissionError, match="routing review"):
        admit_plan_candidate(
            plan=plan,
            report=_report(plan, dependencies_column_present=True),
            approval=_approval(plan, routing_reviewed=False),
        )


def test_tampered_candidate_is_not_covered_by_old_approval(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_validator(monkeypatch)
    plan = _plan()
    report = _report(plan)
    approval = _approval(plan)
    plan["title"] = "Tampered after approval"

    with pytest.raises(PlanAdmissionError, match="candidate hash"):
        admit_plan_candidate(plan=plan, report=report, approval=approval)


def test_protocol_validator_unavailable_blocks_admission(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = _plan()

    def unavailable(name: str):
        raise ModuleNotFoundError(name)

    monkeypatch.setattr(admission.importlib, "import_module", unavailable)

    with pytest.raises(PlanAdmissionError, match="validator is unavailable"):
        admit_plan_candidate(plan=plan, report=_report(plan), approval=_approval(plan))


def test_wrong_protocol_contract_version_blocks_admission(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = _plan()
    monkeypatch.setattr(
        admission.importlib,
        "import_module",
        lambda name: SimpleNamespace(
            PLAN_GRAPH_ID="https://foundry.engineering/schemas/plangraph/v2/plan_graph.json",
            validate_plan_graph=lambda value: None,
        ),
    )

    with pytest.raises(PlanAdmissionError, match="required PlanGraph v1"):
        admit_plan_candidate(plan=plan, report=_report(plan), approval=_approval(plan))


def test_stale_admission_rejected_after_plan_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_validator(monkeypatch)
    plan = _plan()
    admitted = admit_plan_candidate(plan=plan, report=_report(plan), approval=_approval(plan))
    plan["title"] = "Changed after admission"

    with pytest.raises(PlanAdmissionError, match="candidate hash mismatch"):
        verify_plan_admission(plan, admitted)
