from pathlib import Path

import typer

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
