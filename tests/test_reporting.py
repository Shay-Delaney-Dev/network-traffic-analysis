from datetime import UTC, datetime
from ipaddress import IPv4Address

from traffic_analyser.models import (
    AnalysisResult,
    ConversationKey,
    DnsMetadata,
    EndpointKey,
    HttpMetadata,
    PacketSizeCounter,
    ProcessingStatistics,
    ProcessingWarning,
    Protocol,
    ProtocolCounter,
    TimeBucket,
    TlsMetadata,
    WarningCategory,
)
from traffic_analyser.reporting import render_report


def populated_result() -> AnalysisResult:
    first = EndpointKey(IPv4Address("192.0.2.1"), 1234)
    second = EndpointKey(IPv4Address("198.51.100.2"), 443)
    return AnalysisResult(
        total_packets=2,
        total_bytes=160,
        start_time=datetime(2026, 1, 1, tzinfo=UTC),
        end_time=datetime(2026, 1, 1, 0, 0, 2, tzinfo=UTC),
        time_buckets=(
            TimeBucket(
                datetime(2026, 1, 1, tzinfo=UTC),
                datetime(2026, 1, 1, 0, 0, 10, tzinfo=UTC),
                2,
                160,
            ),
        ),
        protocol_counters=(ProtocolCounter(Protocol.TCP, 2, 160),),
        top_source_endpoints=((first, 2),),
        top_destination_endpoints=((second, 2),),
        top_conversations=((ConversationKey.from_endpoints(first, second), 2),),
        packet_sizes=(PacketSizeCounter(80, 2),),
        processing=ProcessingStatistics(received=2, decoded=2),
        warnings=(
            ProcessingWarning(WarningCategory.PROCESSING, "payload-secret", 1),
        ),
        dns_summaries=(DnsMetadata("internal.example", 0, False),),
        http_summaries=(
            HttpMetadata("GET", "service.example", "/private", 200),
        ),
        tls_summaries=(
            TlsMetadata("TLS 1.3", "client_hello", "secure.example"),
        ),
    )


def test_report_contains_all_sections_and_redacts_sensitive_values() -> None:
    report = render_report(
        populated_result(),
        input_type="pcap",
        identity="/private/capture.pcap",
        redact=True,
    )

    for section in (
        "Traffic analysis report",
        "Totals",
        "Traffic volume",
        "Protocol distribution",
        "Top source endpoints",
        "Top destination endpoints",
        "Top conversations",
        "Packet-size summary",
        "DNS metadata",
        "HTTP metadata",
        "TLS metadata",
        "Processing warnings",
    ):
        assert section in report
    for sensitive in (
        "192.0.2.1",
        "198.51.100.2",
        "internal.example",
        "payload-secret",
    ):
        assert sensitive not in report
    assert "<redacted:" in report


def test_empty_and_all_unavailable_results_render_clear_messages() -> None:
    report = render_report(AnalysisResult(), input_type="pcap", identity="empty.pcap")

    assert "No packets captured." in report
    assert "No recognised protocols." in report
    assert "No observable endpoints." in report
    assert "No observable conversations." in report
    assert "No DNS metadata available." in report
    assert "Processing warnings\n  None." in report
