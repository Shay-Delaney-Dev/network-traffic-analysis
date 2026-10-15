from datetime import UTC, datetime
from io import StringIO
from ipaddress import IPv4Address

from rich.console import Console

from traffic_analyser.models import (
    AnalysisResult,
    ConversationKey,
    DnsMetadata,
    EndpointKey,
    FlowSummary,
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
from traffic_analyser.reporting import print_report, render_report


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
        top_flows=(FlowSummary(
            conversation=ConversationKey.from_endpoints(first, second),
            packets=2,
            bytes=160,
            first_seen=datetime(2026, 1, 1, tzinfo=UTC),
            last_seen=datetime(2026, 1, 1, 0, 0, 2, tzinfo=UTC),
            duration_seconds=2.0,
            forward_packets=1,
            reverse_packets=1,
            packets_per_second=1.0,
            bytes_per_second=80.0,
        ),),
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
        "Flow analytics",
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
    assert "1 forward, 1 reverse" in report


def test_empty_and_all_unavailable_results_render_clear_messages() -> None:
    report = render_report(AnalysisResult(), input_type="pcap", identity="empty.pcap")

    assert "No packets captured." in report
    assert "No recognised protocols." in report
    assert "No observable endpoints." in report
    assert "No observable conversations." in report
    assert "No DNS metadata available." in report
    assert "Processing warnings\n  None." in report


def test_print_report_uses_rich_panel_when_enabled_but_keeps_redaction() -> None:
    buffer = StringIO()
    console = Console(file=buffer, force_terminal=True, color_system="standard")

    print_report(
        populated_result(),
        input_type="pcap",
        identity="/private/capture.pcap",
        redact=True,
        console=console,
        use_rich=True,
    )

    output = buffer.getvalue()
    assert "Traffic analysis report" in output
    assert "Top source endpoints" in output
    assert "<redacted:" in output
    assert "192.0.2.1" not in output


def test_rich_report_applies_semantic_styles_without_parsing_values_as_markup() -> None:
    from traffic_analyser.reporting import REPORT_STYLES, _rich_report_text

    styled = _rich_report_text(
        render_report(
            populated_result(),
            input_type="pcap",
            identity="capture.pcap",
        )
    )

    assert any(span.style == REPORT_STYLES["section"] for span in styled.spans)
    assert any(span.style == REPORT_STYLES["total"] for span in styled.spans)
    assert any(span.style == REPORT_STYLES["identifier"] for span in styled.spans)
    assert any(span.style == REPORT_STYLES["port"] for span in styled.spans)
    assert any(span.style == REPORT_STYLES["available"] for span in styled.spans)
    assert any(span.style == REPORT_STYLES["warning"] for span in styled.spans)
    assert "[bold red]" not in styled.plain


def test_plain_report_is_deterministic_and_has_no_terminal_markers(monkeypatch) -> None:
    monkeypatch.setenv("NO_COLOR", "1")
    first = StringIO()
    second = StringIO()

    print_report(
        populated_result(),
        input_type="pcap",
        identity="capture.pcap",
        stream=first,
    )
    print_report(
        populated_result(),
        input_type="pcap",
        identity="capture.pcap",
        stream=second,
    )

    assert first.getvalue() == second.getvalue()
    assert "\x1b[" not in first.getvalue()
