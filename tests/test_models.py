from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv6Address

import pytest

from traffic_analyser.models import (
    AnalysisError,
    AnalysisResult,
    ConversationKey,
    EndpointKey,
    ErrorCategory,
    ExitCode,
    PacketMetadata,
    ProcessingStatistics,
    Protocol,
    WarningCategory,
)


def test_endpoint_and_conversation_keys_support_ipv4_and_ipv6() -> None:
    ipv4 = EndpointKey(IPv4Address("192.0.2.10"), 443)
    ipv6 = EndpointKey(IPv6Address("2001:db8::10"), 8443)

    conversation = ConversationKey.from_endpoints(ipv6, ipv4)

    assert ipv4.canonical() == "192.0.2.10:443"
    assert conversation.first == ipv4
    assert conversation.second == ipv6
    assert conversation.canonical() == "192.0.2.10:443 <-> 2001:db8::10:8443"
    assert conversation == ConversationKey.from_endpoints(ipv4, ipv6)


def test_packet_metadata_keeps_optional_protocol_fields_explicit() -> None:
    packet = PacketMetadata(
        timestamp=datetime(2026, 1, 1, tzinfo=UTC),
        captured_length=60,
        original_length=60,
        network_protocol=Protocol.IPV4,
        source_address=IPv4Address("192.0.2.1"),
        destination_address=IPv4Address("192.0.2.2"),
    )

    assert packet.source_endpoint() == EndpointKey(IPv4Address("192.0.2.1"))
    assert packet.destination_endpoint() == EndpointKey(IPv4Address("192.0.2.2"))
    assert packet.dns is None
    assert packet.http is None
    assert packet.tls is None
    assert packet.conversation() is not None


def test_empty_analysis_result_has_typed_empty_collections() -> None:
    result = AnalysisResult()

    assert result.total_packets == 0
    assert result.processing == ProcessingStatistics()
    assert result.time_buckets == ()
    assert result.warnings == ()


def test_error_categories_map_to_documented_exit_codes() -> None:
    assert AnalysisError(ErrorCategory.INVALID_CLI_INPUT, "bad option").exit_code == ExitCode.INVALID_CLI_INPUT
    assert AnalysisError(ErrorCategory.OFFLINE_INPUT, "missing file").exit_code == ExitCode.OFFLINE_INPUT_ERROR
    assert AnalysisError(ErrorCategory.CAPTURE_BACKEND, "capture unavailable").exit_code == ExitCode.CAPTURE_BACKEND_ERROR
    assert AnalysisError(ErrorCategory.PROCESSING_WARNING, "packet skipped").exit_code == ExitCode.PROCESSING_WARNING
    assert WarningCategory.MALFORMED_PACKET.value == "malformed_packet"


def test_packet_metadata_rejects_invalid_lengths_and_ports() -> None:
    timestamp = datetime(2026, 1, 1, tzinfo=UTC)

    with pytest.raises(ValueError):
        PacketMetadata(timestamp, captured_length=61, original_length=60)
    with pytest.raises(ValueError):
        PacketMetadata(timestamp, captured_length=60, original_length=60, source_port=65536)