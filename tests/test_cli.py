import argparse

import pytest

from traffic_analyser.cli import build_parser, dispatch, main
from traffic_analyser.models import ExitCode


def test_parser_supports_live_options() -> None:
    args = build_parser().parse_args(
        [
            "live",
            "--interface",
            "eth0",
            "--filter",
            "tcp or udp",
            "--list-interfaces",
            "--max-duration",
            "12",
            "--bucket-size",
            "2",
            "--max-packets",
            "20",
            "--max-bytes",
            "2000",
            "--redact",
            "--show-plots",
            "--save-plots",
            "reports",
            "--log-level",
            "INFO",
        ]
    )

    assert args.command == "live"
    assert args.interface == "eth0"
    assert args.filter == "tcp or udp"
    assert args.list_interfaces is True
    assert args.max_duration == 12.0
    assert args.bucket_size == 2.0
    assert args.max_packets == 20
    assert args.max_bytes == 2000
    assert args.redact is True
    assert args.show_plots is True
    assert args.save_plots == "reports"


def test_parser_supports_pcap_options() -> None:
    args = build_parser().parse_args(
        [
            "pcap",
            "capture.pcapng",
            "--max-file-size",
            "5000",
            "--max-packets",
            "10",
        ]
    )

    assert args.command == "pcap"
    assert args.path == "capture.pcapng"
    assert args.max_file_size == 5000
    assert args.max_packets == 10


@pytest.mark.parametrize("option", ["--bucket-size", "--max-packets", "--max-bytes"])
def test_parser_rejects_non_positive_limits(option: str) -> None:
    with pytest.raises(SystemExit) as error:
        build_parser().parse_args(["pcap", "capture.pcap", option, "0"])

    assert error.value.code == int(ExitCode.INVALID_CLI_INPUT)


def test_parser_rejects_live_only_options_on_pcap() -> None:
    with pytest.raises(SystemExit) as error:
        build_parser().parse_args(["pcap", "capture.pcap", "--interface", "eth0"])

    assert error.value.code == int(ExitCode.INVALID_CLI_INPUT)


def test_help_includes_authorised_use_notice() -> None:
    with pytest.raises(SystemExit) as error:
        build_parser().parse_args(["--help"])

    assert error.value.code == 0


def test_dispatch_calls_the_selected_handler_and_builds_limits() -> None:
    calls: list[argparse.Namespace] = []

    def handler(args: argparse.Namespace) -> int:
        calls.append(args)
        return 0

    args = build_parser().parse_args(
        ["pcap", "capture.pcap", "--max-packets", "4", "--bucket-size", "3"]
    )

    assert dispatch(args, pcap_handler=handler) == 0
    assert calls[0].limits.max_packets == 4
    assert calls[0].limits.bucket_size == 3.0


def test_missing_live_interface_is_invalid_cli_input(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["live"]) == int(ExitCode.INVALID_CLI_INPUT)
    output = capsys.readouterr().err
    assert "requires --interface" in output
    assert "Traceback" not in output


def test_expected_handler_failure_has_no_traceback(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["pcap", "missing.pcap"]) == int(ExitCode.OFFLINE_INPUT_ERROR)
    output = capsys.readouterr().err
    assert "offline input is missing or unreadable" in output
    assert "Traceback" not in output


def test_keyboard_interrupt_is_handled_at_cli_boundary(
    capsys: pytest.CaptureFixture[str],
) -> None:
    def interrupted(_args: argparse.Namespace) -> int:
        raise KeyboardInterrupt

    assert main(
        ["live", "--interface", "eth0"], live_handler=interrupted
    ) == int(ExitCode.SUCCESS)
    assert "capture interrupted" in capsys.readouterr().err