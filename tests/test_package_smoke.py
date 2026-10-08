import pytest

from traffic_analyser import __version__
from traffic_analyser.cli import build_parser, main


def test_package_import_and_version() -> None:
    assert __version__ == "0.1.0"
    assert build_parser().prog == "traffic-analyser"


def test_cli_version(capsys: pytest.CaptureFixture[str]) -> None:
    try:
        main(["--version"])
    except SystemExit as error:
        assert error.code == 0

    output = capsys.readouterr().out
    assert "traffic-analyser 0.1.0" in output