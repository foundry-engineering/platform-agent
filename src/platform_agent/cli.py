from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping, cast

import typer

from platform_agent.gantt_parser import GanttParseError, parse_gantt_workbook
from platform_agent.plan_admission import (
    PlanAdmissionError,
    PlanApproval,
    admit_plan_candidate,
)
from platform_agent.plan_source import PlanSourceError, inspect_plan_source

app = typer.Typer(add_completion=False, no_args_is_help=True)

plan_app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Plan ingestion and admission controls.",
)

app.add_typer(plan_app, name="plan")


@app.callback()
def _root() -> None:
    return


@app.command()
def health() -> None:
    typer.echo("ok")


def _load_json_object(path: Path, *, field: str) -> Mapping[str, Any]:
    raw: object = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise PlanAdmissionError(f"{field} root must be a JSON object")
    return cast(Mapping[str, Any], raw)


@plan_app.command("inspect")
def plan_inspect(
    source: Path = typer.Argument(
        ...,
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        resolve_path=False,
        help="Path to the operator-supplied plan workbook.",
    ),
) -> None:
    """Validate and emit a deterministic source fingerprint."""
    try:
        fingerprint = inspect_plan_source(source)
    except PlanSourceError as exc:
        typer.echo(f"plan rejected: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    typer.echo(fingerprint.to_canonical_json())


@plan_app.command("parse")
def plan_parse(
    source: Path = typer.Argument(
        ...,
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        resolve_path=False,
        help="Path to the operator-supplied Gantt workbook.",
    ),
    policy_id: str = typer.Option(..., "--policy-id"),
    policy_sha256: str = typer.Option(..., "--policy-sha256"),
    jurisdiction: str = typer.Option(..., "--jurisdiction"),
) -> None:
    """Parse an XLSX Gantt into a deterministic, non-admitted PlanGraph candidate."""
    try:
        parsed = parse_gantt_workbook(
            source,
            policy_id=policy_id,
            policy_sha256=policy_sha256,
            jurisdiction=jurisdiction,
        )
    except GanttParseError as exc:
        typer.echo(f"plan rejected: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    payload = {
        "admitted": False,
        "plan": parsed.plan,
        "report": parsed.report.as_dict(),
    }
    typer.echo(
        json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    )


@plan_app.command("admit")
def plan_admit(
    parsed_result: Path = typer.Argument(
        ...,
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        help="JSON output previously produced by `platform-agent plan parse`.",
    ),
    approved_source_sha256: str = typer.Option(..., "--approved-source-sha256"),
    approved_candidate_sha256: str = typer.Option(..., "--approved-candidate-sha256"),
    approval_evidence_ref: str = typer.Option(..., "--approval-evidence-ref"),
    dependencies_reviewed: bool = typer.Option(False, "--dependencies-reviewed"),
    routing_reviewed: bool = typer.Option(False, "--routing-reviewed"),
) -> None:
    """Admit exactly the reviewed PlanGraph candidate; fail closed on any mismatch."""
    try:
        payload = _load_json_object(parsed_result, field="parsed_result")
        if payload.get("admitted") is not False:
            raise PlanAdmissionError("input must be a non-admitted parser result")
        plan = payload.get("plan")
        report = payload.get("report")
        approval = PlanApproval(
            approved_source_sha256=approved_source_sha256,
            approved_candidate_sha256=approved_candidate_sha256,
            approval_evidence_ref=approval_evidence_ref,
            dependencies_reviewed=dependencies_reviewed,
            routing_reviewed=routing_reviewed,
        )
        admission = admit_plan_candidate(plan=plan, report=report, approval=approval)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, PlanAdmissionError) as exc:
        typer.echo(f"plan admission rejected: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    typer.echo(admission.to_canonical_json())
