"""Command-line entry point for the traffic analyser."""

from __future__ import annotations

import argparse
import logging
import sys
from collections.abc import Callable, Sequence

from traffic_analyser import __version__
from traffic_analyser.capture import CaptureAdapter, CaptureError
from traffic_analyser.limits import (
    DEFAULT_BUCKET_SIZE,
    DEFAULT_BYTE_COUNT,
    DEFAULT_CAPTURE_DURATION,
    DEFAULT_OFFLINE_FILE_SIZE,
    DEFAULT_PACKET_COUNT,
    MAX_BYTE_COUNT,
    MAX_CAPTURE_DURATION,
    MAX_OFFLINE_FILE_SIZE,
    MAX_PACKET_COUNT,
    ResourceLimits,
    validate_positive_float,
    validate_positive_int,
)
from traffic_analyser.models import AnalysisError, ErrorCategory, ExitCode
from traffic_analyser.pcap_reader import OfflineInputError
from traffic_analyser.reporting import render_report
from traffic_analyser.visualization import (
    PlotOutputError,
    prepare_plot_backend,
    save_plots,
    show_plots,
)
from traffic_analyser.workflow import analyze_offline

CommandHandler = Callable[[argparse.Namespace], int | ExitCode | None]


class _CliFailure(Exception):
    """Carry a typed expected failure to the CLI boundary."""

    def __init__(self, error: AnalysisError) -> None:
        super().__init__(error.message)
        self.error = error


def _positive_int(value: str) -> int:
    try:
        return validate_positive_int(
            int(value), name="value", maximum=MAX_PACKET_COUNT
        )
    except (TypeError, ValueError) as error:
        raise argparse.ArgumentTypeError(str(error)) from error


def _positive_bytes(value: str) -> int:
    try:
        return validate_positive_int(int(value), name="value", maximum=MAX_BYTE_COUNT)
    except (TypeError, ValueError) as error:
        raise argparse.ArgumentTypeError(str(error)) from error


def _positive_duration(value: str) -> float:
    try:
        return validate_positive_float(
            float(value), name="value", maximum=MAX_CAPTURE_DURATION
        )
    except (TypeError, ValueError) as error:
        raise argparse.ArgumentTypeError(str(error)) from error


def _positive_file_size(value: str) -> int:
    try:
        return validate_positive_int(
            int(value), name="value", maximum=MAX_OFFLINE_FILE_SIZE
        )
    except (TypeError, ValueError) as error:
        raise argparse.ArgumentTypeError(str(error)) from error


def _log_level(value: str) -> int:
    level = getattr(logging, value.upper(), None)
    if not isinstance(level, int):
        raise argparse.ArgumentTypeError(f"unknown log level: {value}")
    return level


def _add_shared_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--bucket-size",
        type=_positive_duration,
        default=DEFAULT_BUCKET_SIZE,
        metavar="SECONDS",
        help="time-bucket duration (default: %(default)s)",
    )
    parser.add_argument(
        "--max-packets",
        type=_positive_int,
        default=DEFAULT_PACKET_COUNT,
        metavar="COUNT",
        help="maximum packets to process (default: %(default)s)",
    )
    parser.add_argument(
        "--max-bytes",
        type=_positive_bytes,
        default=DEFAULT_BYTE_COUNT,
        metavar="BYTES",
        help="maximum captured bytes to process (default: %(default)s)",
    )
    parser.add_argument(
        "--redact",
        action="store_true",
        help="redact sensitive identifiers in reports and plots",
    )
    parser.add_argument(
        "--show-plots",
        action="store_true",
        help="display plots after analysis",
    )
    parser.add_argument(
        "--save-plots",
        metavar="DIRECTORY",
        help="save plots to DIRECTORY after analysis",
    )
    parser.add_argument(
        "--log-level",
        type=_log_level,
        default=logging.WARNING,
        metavar="LEVEL",
        help="diagnostic log level (DEBUG, INFO, WARNING, ERROR, or CRITICAL)",
    )


def build_parser() -> argparse.ArgumentParser:
    """Build the public command-line parser."""
    parser = argparse.ArgumentParser(
        prog="traffic-analyser",
        description="Analyse authorised network traffic using packet metadata.",
        epilog="Only inspect traffic you are authorised to access.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    live = subparsers.add_parser(
        "live",
        help="capture and analyse traffic from a local interface",
        description="Capture authorised traffic from a local interface.",
        epilog="Only inspect traffic you are authorised to access.",
    )
    live.add_argument("--interface", help="capture interface name")
    live.add_argument("--filter", help="optional BPF capture filter")
    live.add_argument(
        "--list-interfaces",
        action="store_true",
        help="list available interfaces and exit",
    )
    live.add_argument(
        "--max-duration",
        type=_positive_duration,
        default=DEFAULT_CAPTURE_DURATION,
        metavar="SECONDS",
        help="maximum capture duration (default: %(default)s)",
    )
    _add_shared_options(live)

    pcap = subparsers.add_parser(
        "pcap",
        help="analyse a local classic pcap or pcapng file",
        description="Analyse an authorised local pcap or pcapng file.",
        epilog="Only inspect traffic you are authorised to access.",
    )
    pcap.add_argument("path", metavar="PATH", help="path to a pcap or pcapng file")
    pcap.add_argument(
        "--max-file-size",
        type=_positive_file_size,
        default=DEFAULT_OFFLINE_FILE_SIZE,
        metavar="BYTES",
        help="maximum accepted input file size (default: %(default)s)",
    )
    _add_shared_options(pcap)
    return parser


def _resource_limits(args: argparse.Namespace) -> ResourceLimits:
    """Convert parsed resource options into the shared bounded contract."""
    return ResourceLimits(
        max_duration=getattr(args, "max_duration", DEFAULT_CAPTURE_DURATION),
        max_packets=args.max_packets,
        max_bytes=args.max_bytes,
        max_file_size=getattr(args, "max_file_size", DEFAULT_OFFLINE_FILE_SIZE),
        bucket_size=args.bucket_size,
    )


def run_live(args: argparse.Namespace) -> int:
    """List interfaces now; bounded live capture is owned by Ticket 15."""
    if args.list_interfaces:
        try:
            print("\n".join(CaptureAdapter().list_interfaces()))
        except CaptureError as error:
            raise _CliFailure(
                AnalysisError(ErrorCategory.CAPTURE_BACKEND, str(error))
            ) from error
        return int(ExitCode.SUCCESS)
    raise _CliFailure(
        AnalysisError(
            ErrorCategory.CAPTURE_BACKEND,
            "live capture workflow is not available yet",
        )
    )


def run_pcap(args: argparse.Namespace) -> int:
    """Run bounded offline analysis and retain its result for reporting."""
    try:
        args.analysis_result = analyze_offline(args.path, args.limits)
    except OfflineInputError as error:
        raise _CliFailure(
            AnalysisError(ErrorCategory.OFFLINE_INPUT, str(error))
        ) from error
    print(
        render_report(
            args.analysis_result,
            input_type="pcap",
            identity=args.path,
            redact=args.redact,
        )
    )
    if args.show_plots or args.save_plots:
        prepare_plot_backend(interactive=args.show_plots)
        try:
            if args.save_plots:
                save_plots(
                    args.analysis_result,
                    args.save_plots,
                    redact=args.redact,
                )
            if args.show_plots:
                show_plots(args.analysis_result, redact=args.redact)
        except PlotOutputError as error:
            raise _CliFailure(
                AnalysisError(ErrorCategory.INVALID_CLI_INPUT, str(error))
            ) from error
    return int(ExitCode.SUCCESS)


def dispatch(
    args: argparse.Namespace,
    *,
    live_handler: CommandHandler = run_live,
    pcap_handler: CommandHandler = run_pcap,
) -> int:
    """Dispatch parsed arguments through injectable workflow boundaries."""
    args.limits = _resource_limits(args)
    if args.command == "live":
        if not args.list_interfaces and not args.interface:
            raise _CliFailure(
                AnalysisError(
                    ErrorCategory.INVALID_CLI_INPUT,
                    "live requires --interface unless --list-interfaces is used",
                )
            )
        return int(live_handler(args) or ExitCode.SUCCESS)
    if args.command == "pcap":
        return int(pcap_handler(args) or ExitCode.SUCCESS)
    raise _CliFailure(AnalysisError(ErrorCategory.INVALID_CLI_INPUT, "unknown command"))


def main(
    argv: Sequence[str] | None = None,
    *,
    live_handler: CommandHandler = run_live,
    pcap_handler: CommandHandler = run_pcap,
) -> int:
    """Run the command-line application without exposing expected tracebacks."""
    try:
        args = build_parser().parse_args(argv)
        return dispatch(
            args, live_handler=live_handler, pcap_handler=pcap_handler
        )
    except _CliFailure as failure:
        print(f"traffic-analyser: error: {failure.error.message}", file=sys.stderr)
        return int(failure.error.exit_code)
    except KeyboardInterrupt:
        print("traffic-analyser: capture interrupted", file=sys.stderr)
        return int(ExitCode.SUCCESS)