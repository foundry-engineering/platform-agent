import typer

from .demo import demo as demo_app

app = typer.Typer(add_completion=False, no_args_is_help=True)
app.add_typer(demo_app, name="demo")

@app.command()
def health() -> None:
    typer.echo("ok")
