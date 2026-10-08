"""Headless-safe Matplotlib charts built from aggregate analysis results."""

from __future__ import annotations

import matplotlib.pyplot as plt
from matplotlib.figure import Figure

from traffic_analyser.models import AnalysisResult
from traffic_analyser.privacy import Redactor


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


def _empty(axis: object, message: str) -> None:
    axis.text(0.5, 0.5, message, ha="center", va="center")  # type: ignore[attr-defined]
    axis.set_axis_off()  # type: ignore[attr-defined]


__all__ = [
    "packet_size_distribution_chart",
    "protocol_distribution_chart",
    "top_endpoints_chart",
    "traffic_volume_chart",
]
