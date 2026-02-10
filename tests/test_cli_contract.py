import typer.main
from platform_agent.cli import app, health

def test_health_output(capsys) -> None:
    health()
    assert capsys.readouterr().out.strip() == "ok"

def test_cli_command_tree_contains_health() -> None:
    cmd = typer.main.get_command(app)
    commands = getattr(cmd, "commands", None)
    assert isinstance(commands, dict)
    assert "health" in commands
