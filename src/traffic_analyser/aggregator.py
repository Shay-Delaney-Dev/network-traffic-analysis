"""Streaming aggregation of normalized packet metadata."""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Generic, TypeAlias, TypeVar

from traffic_analyser.decoder import DecodeResult, DecodeStatus
from traffic_analyser.limits import BoundedSamples, ResourceLimits
from traffic_analyser.models import (
    AnalysisResult,
    ConversationKey,
    DnsMetadata,
    EndpointKey,
    HttpMetadata,
    PacketMetadata,
    PacketSizeCounter,
    ProcessingStatistics,
    ProcessingWarning,
    Protocol,
    ProtocolCounter,
    TimeBucket,
    TlsMetadata,
    WarningCategory,
)

AggregateInput: TypeAlias = PacketMetadata | DecodeResult
AggregateKey = TypeVar("AggregateKey", EndpointKey, ConversationKey)


class _BoundedCounter(Generic[AggregateKey]):
    def __init__(self, maximum: int) -> None:
        self.maximum = maximum
        self._counts: dict[AggregateKey, int] = {}

    def increment(self, key: AggregateKey) -> None:
        self._counts[key] = self._counts.get(key, 0) + 1
        if len(self._counts) > self.maximum:
            retained = sorted(
                self._counts.items(),
                key=lambda item: (-item[1], item[0].canonical()),
            )[: self.maximum]
            self._counts = dict(retained)

    def items(self) -> tuple[tuple[AggregateKey, int], ...]:
        return tuple(self._counts.items())


class Aggregator:
    """Accumulate bounded counters without retaining normalized packets."""

    def __init__(self, limits: ResourceLimits | None = None) -> None:
        self.limits = limits or ResourceLimits()
        self._received = 0
        self._decoded = 0
        self._unsupported = 0
        self._malformed = 0
        self._skipped = 0
        self._total_packets = 0
        self._total_bytes = 0
        self._start_time: datetime | None = None
        self._end_time: datetime | None = None
        self._buckets: defaultdict[int, list[int]] = defaultdict(lambda: [0, 0])
        self._protocols: Counter[Protocol] = Counter()
        self._protocol_bytes: Counter[Protocol] = Counter()
        self._sources = _BoundedCounter[EndpointKey](self.limits.top_n)
        self._destinations = _BoundedCounter[EndpointKey](self.limits.top_n)
        self._conversations = _BoundedCounter[ConversationKey](self.limits.top_n)
        self._packet_sizes: Counter[int] = Counter()
        self._dns = BoundedSamples[DnsMetadata](self.limits.metadata_samples)
        self._http = BoundedSamples[HttpMetadata](self.limits.metadata_samples)
        self._tls = BoundedSamples[TlsMetadata](self.limits.metadata_samples)
        self._warnings = BoundedSamples[ProcessingWarning](self.limits.metadata_samples)

    def add(self, item: AggregateInput) -> None:
        """Consume one normalized record or categorized decoder outcome."""
        if isinstance(item, DecodeResult):
            self._received += 1
            if item.status is not DecodeStatus.DECODED or item.metadata is None:
                self._count_skip(item)
                return
            self._decoded += 1
            self._add_metadata(item.metadata)
            return
        if isinstance(item, PacketMetadata):
            self._received += 1
            self._decoded += 1
            self._add_metadata(item)
            return
        raise TypeError("aggregator input must be PacketMetadata or DecodeResult")

    def add_warning(self, warning: ProcessingWarning) -> None:
        """Retain one bounded warning from an acquisition source."""
        self._warnings.add(warning)

    consume = add

    def result(self) -> AnalysisResult:
        """Finalize counters into immutable, report-ready metadata."""
        return AnalysisResult(
            total_packets=self._total_packets,
            total_bytes=self._total_bytes,
            start_time=self._start_time,
            end_time=self._end_time,
            time_buckets=tuple(
                TimeBucket(
                    start=self._bucket_start(bucket),
                    end=self._bucket_start(bucket) + timedelta(seconds=self.limits.bucket_size),
                    packets=values[0],
                    bytes=values[1],
                )
                for bucket, values in sorted(self._buckets.items())
            ),
            protocol_counters=tuple(
                ProtocolCounter(protocol, self._protocols[protocol], self._protocol_bytes[protocol])
                for protocol in sorted(self._protocols, key=lambda value: value.value)
            ),
            top_source_endpoints=self._top(self._sources),
            top_destination_endpoints=self._top(self._destinations),
            top_conversations=self._top(self._conversations),
            packet_sizes=tuple(
                PacketSizeCounter(size, count)
                for size, count in sorted(self._packet_sizes.items())
            ),
            processing=ProcessingStatistics(
                received=self._received,
                decoded=self._decoded,
                unsupported=self._unsupported,
                malformed=self._malformed,
                skipped=self._skipped,
            ),
            warnings=self._warnings.values,
            dns_summaries=self._dns.values,
            http_summaries=self._http.values,
            tls_summaries=self._tls.values,
        )

    finalize = result

    def _add_metadata(self, metadata: PacketMetadata) -> None:
        self._total_packets += 1
        self._total_bytes += metadata.captured_length
        self._start_time = metadata.timestamp if self._start_time is None else min(self._start_time, metadata.timestamp)
        self._end_time = metadata.timestamp if self._end_time is None else max(self._end_time, metadata.timestamp)
        bucket = self._bucket_index(metadata.timestamp)
        self._buckets[bucket][0] += 1
        self._buckets[bucket][1] += metadata.captured_length
        self._packet_sizes[metadata.captured_length] += 1

        for protocol in (metadata.link_protocol, metadata.network_protocol, metadata.transport_protocol):
            if protocol is not None:
                self._protocols[protocol] += 1
                self._protocol_bytes[protocol] += metadata.captured_length
        if metadata.dns is not None:
            self._protocols[Protocol.DNS] += 1
            self._protocol_bytes[Protocol.DNS] += metadata.captured_length
            self._dns.add(metadata.dns)
        if metadata.http is not None:
            self._protocols[Protocol.HTTP] += 1
            self._protocol_bytes[Protocol.HTTP] += metadata.captured_length
            self._http.add(metadata.http)
        if metadata.tls is not None:
            self._protocols[Protocol.TLS] += 1
            self._protocol_bytes[Protocol.TLS] += metadata.captured_length
            self._tls.add(metadata.tls)

        source = metadata.source_endpoint()
        destination = metadata.destination_endpoint()
        if source is not None:
            self._sources.increment(source)
        if destination is not None:
            self._destinations.increment(destination)
        conversation = metadata.conversation()
        if conversation is not None:
            self._conversations.increment(conversation)

    def _count_skip(self, outcome: DecodeResult) -> None:
        if outcome.status is DecodeStatus.UNSUPPORTED:
            self._unsupported += 1
            category = WarningCategory.UNSUPPORTED_PROTOCOL
        elif outcome.status is DecodeStatus.MALFORMED:
            self._malformed += 1
            category = WarningCategory.MALFORMED_PACKET
        else:
            self._skipped += 1
            category = WarningCategory.SKIPPED_PACKET
        self._warnings.add(ProcessingWarning(category, outcome.reason or outcome.status.value))

    def _bucket_index(self, timestamp: datetime) -> int:
        return int(timestamp.timestamp() // self.limits.bucket_size)

    def _bucket_start(self, bucket: int) -> datetime:
        if self._start_time is None:
            raise RuntimeError("cannot build a time bucket without packets")
        epoch = bucket * self.limits.bucket_size
        return datetime.fromtimestamp(epoch, tz=self._start_time.tzinfo)

    def _top(
        self, counter: _BoundedCounter[AggregateKey]
    ) -> tuple[tuple[AggregateKey, int], ...]:
        return tuple(
            sorted(
                counter.items(), key=lambda item: (-item[1], item[0].canonical())
            )[: self.limits.top_n]
        )


__all__ = ["AggregateInput", "Aggregator"]