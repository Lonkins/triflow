from typer.testing import CliRunner

import triflow
from triflow.cli import app

runner = CliRunner()


def test_version_attribute() -> None:
    assert triflow.__version__


def test_cli_version_command() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert triflow.__version__ in result.output
