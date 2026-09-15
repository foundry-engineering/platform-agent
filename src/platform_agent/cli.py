from __future__ import annotations

import json
from pathlib import Path

import typer

from platform_agent.gantt_parser import GanttParseError, parse_gantt_workbook
from platform_agent.plan_source import PlanSourceError, inspect_plan_source

app = typer.Typer(add_completion=False, no_args_is_help=True)

plan_app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Plan ingestion controls.",
)

app.add_typer(plan_app, name="plan")


@app.callback()
def _root() -> None:
    return


@app.command()
def health() -> None:
    typer.echo("ok")


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
    """Parse an XLSX Gantt into a deterministic PlanGraph v1 candidate."""
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
