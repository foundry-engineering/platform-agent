import subprocess
import typer

demo = typer.Typer(add_completion=False, no_args_is_help=True)

@demo.command("cross-agent")
def cross_agent() -> None:
    res = subprocess.run(
        ["engineering-agent", "health"],
        capture_output=True,
        text=True,
    )
    if res.returncode != 0:
        if res.stdout:
            typer.echo(res.stdout.rstrip())
        if res.stderr:
            typer.echo(res.stderr.rstrip(), err=True)
        raise typer.Exit(code=res.returncode)

    out = (res.stdout or "").strip()
    typer.echo(out if out else "ok")
