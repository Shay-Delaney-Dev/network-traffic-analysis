"""Offline acquisition and shared normalized analysis workflows."""

from __future__ import annotations

from collections.abc import Callable, Iterable

from traffic_analyser.aggregator import Aggregator
from traffic_analyser.decoder import DecodeContext, decode
from traffic_analyser.limits import ResourceLimits
from traffic_analyser.models import AnalysisResult, ProcessingWarning
from traffic_analyser.pcap_reader import OfflinePacket, OfflinePcapReader, PathInput


def process_packet_records(
    records: Iterable[OfflinePacket],
    limits: ResourceLimits,
    *,
    warnings: Iterable[ProcessingWarning]
    | Callable[[], Iterable[ProcessingWarning]] = (),
) -> AnalysisResult:
    """Process acquired records through the shared decoder and aggregator boundary."""
    aggregator = Aggregator(limits)
    for record in records:
        aggregator.add(
            decode(
                record.packet,
                DecodeContext(
                    timestamp=record.timestamp,
                    captured_length=record.captured_length,
                    original_length=record.original_length,
                    inspected_header_bytes=limits.inspected_header_bytes,
                ),
            )
        )
    warning_items = warnings() if callable(warnings) else warnings
    for warning in warning_items:
        aggregator.add_warning(warning)
    return aggregator.result()


def analyze_offline(path: PathInput, limits: ResourceLimits) -> AnalysisResult:
    """Analyze a local pcap or pcapng file with bounded partial-result handling."""
    with OfflinePcapReader(path, limits) as reader:
        records = iter(reader)
        result = process_packet_records(records, limits, warnings=lambda: reader.warnings)
    return result


__all__ = ["analyze_offline", "process_packet_records"]