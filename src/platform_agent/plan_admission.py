from __future__ import annotations

import hashlib
import importlib
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping, cast

_PLAN_GRAPH_ID = "https://foundry.engineering/schemas/plangraph/v1/plan_graph.json"
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_EVIDENCE_RE = re.compile(r"^sha256:[a-f0-9]{64}$")


class PlanAdmissionError(ValueError):
    """Raised when a parsed plan cannot be admitted for execution."""


@dataclass(frozen=True, slots=True)
class PlanApproval:
    approved_source_sha256: str
    approved_candidate_sha256: str
    approval_evidence_ref: str
    dependencies_reviewed: bool
    routing_reviewed: bool

    def __post_init__(self) -> None:
        if _SHA256_RE.fullmatch(self.approved_source_sha256) is None:
            raise PlanAdmissionError("approved_source_sha256 must be lowercase sha256")
        if _SHA256_RE.fullmatch(self.approved_candidate_sha256) is None:
            raise PlanAdmissionError("approved_candidate_sha256 must be lowercase sha256")
        if _EVIDENCE_RE.fullmatch(self.approval_evidence_ref) is None:
            raise PlanAdmissionError("approval_evidence_ref must be sha256:<64 lowercase hex>")


@dataclass(frozen=True, slots=True)
class PlanAdmission:
    schema_version: str
    admission_id: str
    plan_id: str
    source_sha256: str
    candidate_sha256: str
    approval_evidence_ref: str
    protocol_schema_id: str
    dependencies_reviewed: bool
    routing_reviewed: bool

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "admission_id": self.admission_id,
            "plan_id": self.plan_id,
            "source_sha256": self.source_sha256,
            "candidate_sha256": self.candidate_sha256,
            "approval_evidence_ref": self.approval_evidence_ref,
            "protocol_schema_id": self.protocol_schema_id,
            "dependencies_reviewed": self.dependencies_reviewed,
            "routing_reviewed": self.routing_reviewed,
        }

    def to_canonical_json(self) -> str:
        return canonical_json(self.as_dict())


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def candidate_sha256(plan: object) -> str:
    return hashlib.sha256(canonical_json(plan).encode("utf-8")).hexdigest()


def _require_mapping(value: object, *, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise PlanAdmissionError(f"{field} must be an object")
    return cast(Mapping[str, Any], value)


def _require_string(value: object, *, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise PlanAdmissionError(f"{field} must be a non-empty string")
    return value


def _validate_canonical_plangraph(plan: object) -> None:
    """Require the promoted canonical PlanGraph validator before admission.

    The import is intentionally dynamic while the protocol contract is still on
    a stacked draft branch. Once promoted/tagged, platform-agent should pin the
    released agent-protocol package rather than a mutable feature branch.
    """
    try:
        module = importlib.import_module("agent_protocol.schema")
    except ModuleNotFoundError as exc:
        raise PlanAdmissionError(
            "canonical agent-protocol PlanGraph validator is unavailable"
        ) from exc

    schema_id = getattr(module, "PLAN_GRAPH_ID", None)
    validator = getattr(module, "validate_plan_graph", None)
    if schema_id != _PLAN_GRAPH_ID or not callable(validator):
        raise PlanAdmissionError(
            "installed agent-protocol does not provide the required PlanGraph v1 contract"
        )

    try:
        validator(plan)
    except Exception as exc:
        raise PlanAdmissionError("canonical PlanGraph v1 validation failed") from exc


def _admission_id(material: Mapping[str, object]) -> str:
    digest = hashlib.sha256(canonical_json(material).encode("utf-8")).hexdigest()
    return "adm_" + digest[:32]


def admit_plan_candidate(
    *,
    plan: object,
    report: object,
    approval: PlanApproval,
) -> PlanAdmission:
    """Admit exactly one reviewed PlanGraph candidate for downstream scheduling.

    Admission binds operator approval to immutable source/candidate hashes and
    refuses to convert parser uncertainty into executable state.
    """
    plan_map = _require_mapping(plan, field="plan")
    report_map = _require_mapping(report, field="report")

    plan_id = _require_string(plan_map.get("plan_id"), field="plan.plan_id")
    source = _require_mapping(plan_map.get("source"), field="plan.source")
    source_sha256 = _require_string(source.get("sha256"), field="plan.source.sha256")
    report_source_sha256 = _require_string(
        report_map.get("source_sha256"), field="report.source_sha256"
    )
    report_candidate_sha256 = _require_string(
        report_map.get("candidate_sha256"), field="report.candidate_sha256"
    )

    actual_candidate_sha256 = candidate_sha256(plan_map)
    if source_sha256 != report_source_sha256:
        raise PlanAdmissionError("parse report source hash does not match PlanGraph source hash")
    if actual_candidate_sha256 != report_candidate_sha256:
        raise PlanAdmissionError("parse report candidate hash does not match PlanGraph candidate")
    if approval.approved_source_sha256 != source_sha256:
        raise PlanAdmissionError("operator approval does not bind the current source hash")
    if approval.approved_candidate_sha256 != actual_candidate_sha256:
        raise PlanAdmissionError("operator approval does not bind the current candidate hash")

    dependencies_column_present = report_map.get("dependencies_column_present")
    if not isinstance(dependencies_column_present, bool):
        raise PlanAdmissionError("report.dependencies_column_present must be boolean")
    if not dependencies_column_present and not approval.dependencies_reviewed:
        raise PlanAdmissionError(
            "dependencies column is absent; explicit dependency review is required"
        )
    if not approval.routing_reviewed:
        raise PlanAdmissionError(
            "Gantt Owner Repo(s) values are routing hints; explicit routing review is required"
        )

    _validate_canonical_plangraph(plan_map)

    material: dict[str, object] = {
        "schema_version": "foundry.plan-admission.v1",
        "plan_id": plan_id,
        "source_sha256": source_sha256,
        "candidate_sha256": actual_candidate_sha256,
        "approval_evidence_ref": approval.approval_evidence_ref,
        "protocol_schema_id": _PLAN_GRAPH_ID,
        "dependencies_reviewed": approval.dependencies_reviewed,
        "routing_reviewed": approval.routing_reviewed,
    }
    return PlanAdmission(
        schema_version="foundry.plan-admission.v1",
        admission_id=_admission_id(material),
        plan_id=plan_id,
        source_sha256=source_sha256,
        candidate_sha256=actual_candidate_sha256,
        approval_evidence_ref=approval.approval_evidence_ref,
        protocol_schema_id=_PLAN_GRAPH_ID,
        dependencies_reviewed=approval.dependencies_reviewed,
        routing_reviewed=approval.routing_reviewed,
    )


def verify_plan_admission(plan: object, admission: PlanAdmission) -> None:
    """Reject stale or forged admission metadata before scheduling/dispatch."""
    plan_map = _require_mapping(plan, field="plan")
    plan_id = _require_string(plan_map.get("plan_id"), field="plan.plan_id")
    source = _require_mapping(plan_map.get("source"), field="plan.source")
    source_sha256 = _require_string(source.get("sha256"), field="plan.source.sha256")
    actual_candidate_sha256 = candidate_sha256(plan_map)

    if admission.schema_version != "foundry.plan-admission.v1":
        raise PlanAdmissionError("unsupported plan admission version")
    if admission.protocol_schema_id != _PLAN_GRAPH_ID:
        raise PlanAdmissionError("plan admission references an unsupported protocol contract")
    if admission.plan_id != plan_id:
        raise PlanAdmissionError("plan admission plan_id mismatch")
    if admission.source_sha256 != source_sha256:
        raise PlanAdmissionError("plan admission source hash mismatch")
    if admission.candidate_sha256 != actual_candidate_sha256:
        raise PlanAdmissionError("plan admission candidate hash mismatch")

    material = {
        key: value
        for key, value in admission.as_dict().items()
        if key != "admission_id"
    }
    if admission.admission_id != _admission_id(material):
        raise PlanAdmissionError("plan admission identity mismatch")
