"""Command-line entry point for the traffic analyser."""

from __future__ import annotations

import argparse
from collections.abc import Sequence

from traffic_analyser import __version__


def build_parser() -> argparse.ArgumentParser:
    """Build the foundation CLI parser."""
    parser = argparse.ArgumentParser(
        prog="traffic-analyser",
        description="Analyse authorised network traffic using packet metadata.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command-line application."""
    build_parser().parse_args(argv)
    return 0