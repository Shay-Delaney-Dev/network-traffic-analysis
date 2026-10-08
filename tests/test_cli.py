import argparse

import pytest

from traffic_analyser.cli import build_parser, dispatch, main
from traffic_analyser.models import AnalysisResult, ExitCode


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


def test_live_can_list_interfaces(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    class FakeAdapter:
        def list_interfaces(self) -> tuple[str, ...]:
            return ("eth0", "lo")

    monkeypatch.setattr("traffic_analyser.cli.CaptureAdapter", FakeAdapter)

    assert main(["live", "--list-interfaces"]) == int(ExitCode.SUCCESS)
    assert capsys.readouterr().out == "eth0\nlo\n"


def test_live_handler_reports_partial_analysis_and_forwards_filter(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    calls: list[tuple[str, str | None]] = []

    def fake_live(_source, interface, _limits, *, bpf_filter):
        calls.append((interface, bpf_filter))
        return AnalysisResult()

    monkeypatch.setattr("traffic_analyser.cli.analyze_live", fake_live)

    assert main(["live", "--interface", "eth0", "--filter", "tcp"]) == 0
    assert calls == [("eth0", "tcp")]
    assert "Input: live (eth0)" in capsys.readouterr().out


def test_expected_handler_failure_has_no_traceback(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["pcap", "missing.pcap"]) == int(ExitCode.OFFLINE_INPUT_ERROR)
    output = capsys.readouterr().err
    assert "offline input is missing or unreadable" in output
    assert "Traceback" not in output


def test_pcap_handler_prints_standard_report(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        "traffic_analyser.cli.analyze_offline",
        lambda _path, _limits: AnalysisResult(),
    )

    assert main(["pcap", "capture.pcap"]) == int(ExitCode.SUCCESS)
    output = capsys.readouterr().out

    assert "Traffic analysis report" in output
    assert "Input: pcap (capture.pcap)" in output
    assert "No packets captured." in output


def test_pcap_save_plots_writes_four_files(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    monkeypatch.setattr(
        "traffic_analyser.cli.analyze_offline",
        lambda _path, _limits: AnalysisResult(),
    )

    assert main(["pcap", "capture.pcap", "--save-plots", str(tmp_path)]) == 0
    assert {path.name for path in tmp_path.iterdir()} == {
        "traffic_volume.png",
        "protocol_distribution.png",
        "top_endpoints.png",
        "packet_size_distribution.png",
    }


def test_pcap_plot_modes_are_explicit(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    monkeypatch.setattr(
        "traffic_analyser.cli.analyze_offline",
        lambda _path, _limits: AnalysisResult(),
    )
    shown: list[bool] = []
    monkeypatch.setattr(
        "traffic_analyser.cli.show_plots",
        lambda _result, *, redact: shown.append(redact),
    )

    assert main(["pcap", "capture.pcap", "--show-plots"]) == 0
    assert shown == [False]
    assert not list(tmp_path.iterdir())


def test_pcap_can_save_and_display_when_both_are_requested(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    monkeypatch.setattr(
        "traffic_analyser.cli.analyze_offline",
        lambda _path, _limits: AnalysisResult(),
    )
    calls: list[str] = []
    monkeypatch.setattr(
        "traffic_analyser.cli.save_plots",
        lambda _result, _directory, *, redact: calls.append("save"),
    )
    monkeypatch.setattr(
        "traffic_analyser.cli.show_plots",
        lambda _result, *, redact: calls.append("show"),
    )

    assert (
        main(
            [
                "pcap",
                "capture.pcap",
                "--show-plots",
                "--save-plots",
                str(tmp_path),
            ]
        )
        == 0
    )
    assert calls == ["save", "show"]


def test_pcap_plot_output_failure_is_a_clean_cli_error(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        "traffic_analyser.cli.analyze_offline",
        lambda _path, _limits: AnalysisResult(),
    )
    output_file = tmp_path / "not-a-directory"
    output_file.write_text("x")

    assert (
        main(["pcap", "capture.pcap", "--save-plots", str(output_file)])
        == int(ExitCode.INVALID_CLI_INPUT)
    )
    error = capsys.readouterr().err
    assert "plot output directory" in error
    assert "Traceback" not in error


def test_keyboard_interrupt_is_handled_at_cli_boundary(
    capsys: pytest.CaptureFixture[str],
) -> None:
    def interrupted(_args: argparse.Namespace) -> int:
        raise KeyboardInterrupt

    assert main(
        ["live", "--interface", "eth0"], live_handler=interrupted
    ) == int(ExitCode.SUCCESS)
    assert "capture interrupted" in capsys.readouterr().err