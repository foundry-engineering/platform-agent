import typer

app = typer.Typer(add_completion=False, no_args_is_help=True)

@app.callback()
def _root() -> None:
    return

@app.command()
def health() -> None:
    typer.echo("ok")
