"""Offline acquisition and shared normalized analysis workflows."""

from __future__ import annotations

import time
from collections.abc import Callable, Iterable
from datetime import UTC, datetime

from scapy.packet import Packet

from traffic_analyser.aggregator import Aggregator
from traffic_analyser.capture import CaptureSource
from traffic_analyser.decoder import DecodeContext, decode
from traffic_analyser.limits import LimitTracker, ResourceLimits
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


def analyze_live(
    source: CaptureSource,
    interface: str,
    limits: ResourceLimits,
    *,
    bpf_filter: str | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> AnalysisResult:
    """Capture transient packets into the same decoder and aggregator pipeline."""
    aggregator = Aggregator(limits)
    tracker = LimitTracker(limits)
    started = clock()
    stopped = False

    def elapsed() -> float:
        return max(0.0, clock() - started)

    def on_packet(packet: Packet) -> None:
        nonlocal stopped
        if stopped:
            return
        try:
            captured_length = len(packet)
            original_length = int(
                getattr(packet, "wirelen", captured_length) or captured_length
            )
            timestamp = datetime.fromtimestamp(float(packet.time), tz=UTC)
        except Exception:  # noqa: BLE001 - malformed live packets are skippable
            captured_length = 0
            original_length = 0
            timestamp = datetime.now(tz=UTC)

        if not tracker.try_accept(captured_length, elapsed()):
            stopped = True
            return
        aggregator.add(
            decode(
                packet,
                DecodeContext(
                    timestamp=timestamp,
                    captured_length=captured_length,
                    original_length=original_length,
                    inspected_header_bytes=limits.inspected_header_bytes,
                ),
            )
        )

    def stop_filter(_packet: Packet) -> bool:
        nonlocal stopped
        if stopped or elapsed() >= limits.max_duration:
            stopped = True
        return stopped

    try:
        source.capture(
            interface,
            bpf_filter=bpf_filter,
            on_packet=on_packet,
            stop_filter=stop_filter,
            timeout=limits.max_duration,
        )
    except KeyboardInterrupt:
        stopped = True
    finally:
        close = getattr(source, "close", None)
        if callable(close):
            close()
    return aggregator.result()


__all__ = ["analyze_live", "analyze_offline", "process_packet_records"]