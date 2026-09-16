import typer.main
from typer.testing import CliRunner

from platform_agent.cli import app, health

runner = CliRunner()


def test_health_output(capsys) -> None:
    health()
    assert capsys.readouterr().out.strip() == "ok"


def test_cli_command_tree_contains_health_and_plan_controls() -> None:
    cmd = typer.main.get_command(app)
    commands = getattr(cmd, "commands", None)

    assert isinstance(commands, dict)
    assert "health" in commands
    assert "plan" in commands

    plan = commands["plan"]
    plan_commands = getattr(plan, "commands", None)
    assert isinstance(plan_commands, dict)
    assert set(plan_commands) >= {"inspect", "parse", "admit"}


def test_plan_inspect_emits_canonical_json(tmp_path) -> None:
    source = tmp_path / "plan.xlsx"
    source.write_bytes(b"workbook-bytes")

    result = runner.invoke(
        app,
        [
            "plan",
            "inspect",
            str(source),
        ],
    )

    assert result.exit_code == 0
    assert result.stdout.strip() == (
        '{"format":"xlsx",'
        '"schema":"foundry.plan-source.v1",'
        '"sha256":"977ae00c34126a1c073815f483d1869e'
        'e09894533641771199f8803ff0967cc1",'
        '"size_bytes":14}'
    )
