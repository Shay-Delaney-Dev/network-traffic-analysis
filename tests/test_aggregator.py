from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv6Address

from traffic_analyser.aggregator import Aggregator
from traffic_analyser.decoder import DecodeResult, DecodeStatus
from traffic_analyser.limits import ResourceLimits
from traffic_analyser.models import (
    DnsMetadata,
    HttpMetadata,
    PacketMetadata,
    Protocol,
    TlsMetadata,
)

TIMESTAMP = datetime(2026, 1, 1, 0, 0, 1, tzinfo=UTC)


def packet(
    *,
    timestamp: datetime = TIMESTAMP,
    size: int = 60,
    source: str = "192.0.2.1",
    destination: str = "192.0.2.2",
    source_port: int = 1234,
    destination_port: int = 443,
    protocol: Protocol = Protocol.TCP,
) -> PacketMetadata:
    return PacketMetadata(
        timestamp=timestamp,
        captured_length=size,
        original_length=size,
        network_protocol=Protocol.IPV4,
        transport_protocol=protocol,
        source_address=IPv4Address(source),
        destination_address=IPv4Address(destination),
        source_port=source_port,
        destination_port=destination_port,
    )


def test_empty_aggregator_returns_typed_empty_result() -> None:
    result = Aggregator().result()

    assert result.total_packets == 0
    assert result.total_bytes == 0
    assert result.processing.received == 0
    assert result.time_buckets == ()
    assert result.protocol_counters == ()


def test_aggregator_streams_totals_buckets_protocols_and_sizes() -> None:
    aggregator = Aggregator(ResourceLimits(bucket_size=10))
    aggregator.add(packet(size=60))
    aggregator.add(packet(timestamp=TIMESTAMP.replace(second=12), size=100, protocol=Protocol.UDP))

    result = aggregator.finalize()

    assert result.total_packets == 2
    assert result.total_bytes == 160
    assert result.start_time == TIMESTAMP
    assert result.end_time == TIMESTAMP.replace(second=12)
    assert [(bucket.packets, bucket.bytes) for bucket in result.time_buckets] == [(1, 60), (1, 100)]
    assert [(counter.protocol, counter.packets, counter.bytes) for counter in result.protocol_counters] == [
        (Protocol.IPV4, 2, 160),
        (Protocol.TCP, 1, 60),
        (Protocol.UDP, 1, 100),
    ]
    assert [(item.size, item.packets) for item in result.packet_sizes] == [(60, 1), (100, 1)]


def test_bidirectional_ipv4_ipv6_conversations_and_ties_are_deterministic() -> None:
    aggregator = Aggregator(ResourceLimits(top_n=1))
    first = packet(source="192.0.2.1", destination="192.0.2.2")
    reverse = packet(source="192.0.2.2", destination="192.0.2.1", source_port=443, destination_port=1234)
    ipv6 = PacketMetadata(
        timestamp=TIMESTAMP,
        captured_length=70,
        original_length=70,
        network_protocol=Protocol.IPV6,
        source_address=IPv6Address("2001:db8::2"),
        destination_address=IPv6Address("2001:db8::1"),
    )
    aggregator.add(first)
    aggregator.add(reverse)
    aggregator.add(ipv6)

    result = aggregator.result()

    assert result.top_conversations[0][1] == 2
    assert result.top_source_endpoints[0][0].canonical() == "192.0.2.1:1234"
    assert result.top_destination_endpoints[0][0].canonical() == "192.0.2.1:1234"
    assert result.top_conversations[0][0].canonical() == "192.0.2.1:1234 <-> 192.0.2.2:443"


def test_skip_outcomes_are_counted_and_warned_without_aborting() -> None:
    aggregator = Aggregator()
    aggregator.add(DecodeResult(DecodeStatus.MALFORMED, reason="invalid lengths"))
    aggregator.add(DecodeResult(DecodeStatus.UNSUPPORTED, reason="unknown layer"))
    aggregator.add(DecodeResult(DecodeStatus.SKIPPED, reason="not observable"))
    aggregator.add(packet())

    result = aggregator.result()

    assert result.processing.received == 4
    assert result.processing.decoded == 1
    assert result.processing.malformed == 1
    assert result.processing.unsupported == 1
    assert result.processing.skipped == 1
    assert len(result.warnings) == 3
    assert result.total_packets == 1


def test_packets_without_ip_or_transport_fields_are_still_aggregated() -> None:
    aggregator = Aggregator()
    aggregator.add(
        PacketMetadata(
            timestamp=TIMESTAMP,
            captured_length=14,
            original_length=14,
            link_protocol=Protocol.ETHERNET,
        )
    )

    result = aggregator.result()

    assert result.total_packets == 1
    assert result.total_bytes == 14
    assert result.top_source_endpoints == ()
    assert result.top_destination_endpoints == ()
    assert result.top_conversations == ()
    assert len(result.protocol_counters) == 1
    assert result.protocol_counters[0].protocol is Protocol.ETHERNET


def test_metadata_summaries_are_bounded() -> None:
    aggregator = Aggregator(ResourceLimits(metadata_samples=1))
    first = PacketMetadata(
        timestamp=TIMESTAMP,
        captured_length=60,
        original_length=60,
        dns=DnsMetadata(query_name="one.example"),
    )
    second = PacketMetadata(
        timestamp=TIMESTAMP,
        captured_length=60,
        original_length=60,
        dns=DnsMetadata(query_name="two.example"),
        http=HttpMetadata(method="GET"),
        tls=TlsMetadata(version="TLS 1.3"),
    )
    aggregator.add(first)
    aggregator.add(second)

    result = aggregator.result()

    assert result.dns_summaries == (DnsMetadata(query_name="one.example"),)
    assert result.http_summaries == (HttpMetadata(method="GET"),)
    assert result.tls_summaries == (TlsMetadata(version="TLS 1.3"),)


def test_top_and_metadata_state_are_bounded() -> None:
    aggregator = Aggregator(ResourceLimits(top_n=1, metadata_samples=2))
    for index in range(5):
        aggregator.add(packet(source=f"192.0.2.{index + 1}"))

    result = aggregator.result()

    assert len(result.top_source_endpoints) == 1
    assert len(result.top_destination_endpoints) == 1
    assert len(aggregator._sources.items()) == 1
    assert len(aggregator._destinations.items()) == 1
    assert len(aggregator._conversations.items()) == 1
    assert len(aggregator._dns.values) == 0
    assert len(result.packet_sizes) == 1