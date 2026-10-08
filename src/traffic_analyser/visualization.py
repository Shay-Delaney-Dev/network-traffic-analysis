"""Headless-safe Matplotlib charts built from aggregate analysis results."""

from __future__ import annotations

import os
from pathlib import Path

import matplotlib
import matplotlib.pyplot as plt
from matplotlib.figure import Figure

from traffic_analyser.models import AnalysisResult
from traffic_analyser.privacy import Redactor

PLOT_FILENAMES = (
    "traffic_volume.png",
    "protocol_distribution.png",
    "top_endpoints.png",
    "packet_size_distribution.png",
)


class PlotOutputError(ValueError):
    """Raised when plot output cannot be safely displayed or saved."""


def traffic_volume_chart(result: AnalysisResult) -> Figure:
    """Build the packet and byte volume chart."""
    figure, axis = plt.subplots()
    if not result.time_buckets:
        _empty(axis, "No traffic volume available")
        return figure
    labels = [bucket.start.isoformat() for bucket in result.time_buckets]
    positions = range(len(labels))
    axis.bar(positions, [bucket.bytes for bucket in result.time_buckets], label="Bytes")
    axis.set_xticks(list(positions), labels, rotation=45, ha="right")
    axis.set_ylabel("Bytes")
    axis.set_title("Traffic volume over time")
    axis.legend()
    figure.tight_layout()
    return figure


def protocol_distribution_chart(result: AnalysisResult) -> Figure:
    """Build the protocol packet-count distribution chart."""
    figure, axis = plt.subplots()
    if not result.protocol_counters:
        _empty(axis, "No protocol distribution available")
        return figure
    labels = [counter.protocol.value for counter in result.protocol_counters]
    axis.bar(labels, [counter.packets for counter in result.protocol_counters])
    axis.set_ylabel("Packets")
    axis.set_title("Protocol distribution")
    axis.tick_params(axis="x", rotation=45)
    figure.tight_layout()
    return figure


def top_endpoints_chart(result: AnalysisResult, *, redact: bool = False) -> Figure:
    """Build a horizontal chart of the top source endpoints."""
    figure, axis = plt.subplots()
    redactor = Redactor(enabled=redact)
    if not result.top_source_endpoints:
        _empty(axis, "No top endpoints available")
        return figure
    labels = [redactor.endpoint(endpoint) for endpoint, _ in result.top_source_endpoints]
    counts = [count for _, count in result.top_source_endpoints]
    axis.barh(labels, counts)
    axis.set_xlabel("Packets")
    axis.set_title("Top source endpoints")
    figure.tight_layout()
    return figure


def packet_size_distribution_chart(result: AnalysisResult) -> Figure:
    """Build a packet-size distribution chart from bounded size counters."""
    figure, axis = plt.subplots()
    if not result.packet_sizes:
        _empty(axis, "No packet-size data available")
        return figure
    sizes = [item.size for item in result.packet_sizes]
    counts = [item.packets for item in result.packet_sizes]
    axis.bar(sizes, counts, width=0.8)
    axis.set_xlabel("Packet size (bytes)")
    axis.set_ylabel("Packets")
    axis.set_title("Packet-size distribution")
    figure.tight_layout()
    return figure


def save_plots(
    result: AnalysisResult,
    directory: str | os.PathLike[str],
    *,
    redact: bool = False,
) -> tuple[Path, ...]:
    """Save all charts to an existing writable directory without overwriting."""
    output_directory = Path(directory)
    if not output_directory.is_dir():
        raise PlotOutputError("plot output directory must be an existing directory")
    if not os.access(output_directory, os.W_OK):
        raise PlotOutputError("plot output directory is not writable")

    output_paths = tuple(output_directory / name for name in PLOT_FILENAMES)
    existing = next((path for path in output_paths if path.exists()), None)
    if existing is not None:
        raise PlotOutputError(f"refusing to overwrite existing plot: {existing.name}")

    figures = _build_figures(result, redact=redact)
    try:
        for figure, output_path in zip(figures, output_paths):
            figure.savefig(output_path)
    except OSError as error:
        for output_path in output_paths:
            output_path.unlink(missing_ok=True)
        raise PlotOutputError(f"unable to save plots: {error}") from error
    finally:
        for figure in figures:
            plt.close(figure)
    return output_paths


def show_plots(result: AnalysisResult, *, redact: bool = False) -> None:
    """Display all charts only when the caller explicitly requests it."""
    figures = _build_figures(result, redact=redact)
    try:
        plt.show()
    finally:
        for figure in figures:
            plt.close(figure)


def _build_figures(result: AnalysisResult, *, redact: bool) -> tuple[Figure, ...]:
    return (
        traffic_volume_chart(result),
        protocol_distribution_chart(result),
        top_endpoints_chart(result, redact=redact),
        packet_size_distribution_chart(result),
    )


def prepare_plot_backend(*, interactive: bool) -> None:
    """Select a non-interactive backend whenever display was not requested."""
    if not interactive:
        matplotlib.use("Agg")


def _empty(axis: object, message: str) -> None:
    axis.text(0.5, 0.5, message, ha="center", va="center")  # type: ignore[attr-defined]
    axis.set_axis_off()  # type: ignore[attr-defined]


__all__ = [
    "PLOT_FILENAMES",
    "PlotOutputError",
    "packet_size_distribution_chart",
    "protocol_distribution_chart",
    "prepare_plot_backend",
    "save_plots",
    "show_plots",
    "top_endpoints_chart",
    "traffic_volume_chart",
]
