"""Metadata-only terminal reports for completed analysis results."""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any, TextIO

from traffic_analyser.models import AnalysisResult, ProcessingWarning
from traffic_analyser.privacy import Redactor

if TYPE_CHECKING:
    from rich.console import Console as ConsoleType
    from rich.text import Text as TextType

rich_console_cls: Any | None
rich_panel_cls: Any | None
rich_text_cls: type[TextType] | None

try:
    from rich.console import Console as _RichConsole
    from rich.panel import Panel as _RichPanel
    from rich.text import Text as _RichText
    rich_console_cls = _RichConsole
    rich_panel_cls = _RichPanel
    rich_text_cls = _RichText
except ImportError:  # pragma: no cover - optional runtime dependency fallback
    rich_console_cls = None
    rich_panel_cls = None
    rich_text_cls = None

REPORT_STYLES = {
    "title": "bold cyan",
    "section": "bold cyan",
    "protocol": "bold green",
    "identifier": "yellow",
    "port": "magenta",
    "total": "bold white",
    "available": "green",
    "unavailable": "dim",
    "warning": "bold yellow",
}

_SECTION_NAMES = {
    "Time range",
    "Totals",
    "Processing",
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
}
_UNAVAILABLE_MARKER = "No "
_AVAILABLE_MARKERS = ("DnsMetadata(", "HttpMetadata(", "TlsMetadata(")
_PORT_PATTERN = re.compile(r":\d+(?=\D|$)")
_IDENTIFIER_PATTERNS = (
    re.compile(r"<redacted:[^>]+>"),
    re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    re.compile(r"\b[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,}\b"),
)
_PROTOCOL_NAMES = {
    "ethernet",
    "ipv4",
    "ipv6",
    "tcp",
    "udp",
    "icmp",
    "icmpv6",
    "dns",
    "http",
    "tls",
    "unknown",
}


def print_report(
    result: AnalysisResult,
    *,
    input_type: str,
    identity: str,
    redact: bool = False,
    console: ConsoleType | None = None,
    use_rich: bool | None = None,
    stream: TextIO | None = None,
) -> None:
    """Print the report with Rich or deterministic plain text."""
    text = render_report(
        result, input_type=input_type, identity=identity, redact=redact
    )
    if use_rich is None:
        use_rich = _should_use_rich_output()
    if (
        not use_rich
        or rich_console_cls is None
        or rich_panel_cls is None
        or rich_text_cls is None
    ):
        if stream is not None:
            print(text, file=stream)
        else:
            print(text)
        return

    target = (
        console
        if console is not None
        else rich_console_cls(file=stream if stream is not None else None)
    )
    target.print(
        rich_panel_cls(
            _rich_report_text(text),
            title=rich_text_cls(
                "Traffic analysis report", style=REPORT_STYLES["title"]
            ),
            subtitle=f"[dim]{input_type}[/dim]",
            border_style="cyan",
            padding=(0, 1),
        )
    )


def _rich_report_text(report: str) -> TextType:
    """Apply semantic styles to generated report text without parsing markup."""
    styled = _new_rich_text()
    for index, line in enumerate(report.splitlines()):
        if index:
            styled.append("\n")
        styled.append(_style_report_line(line))
    return styled


def _style_report_line(line: str) -> TextType:
    styled = _new_rich_text(line)
    stripped = line.strip()
    if stripped == "Traffic analysis report":
        styled.stylize(REPORT_STYLES["title"])
    elif stripped in _SECTION_NAMES:
        styled.stylize(REPORT_STYLES["section"])
    elif stripped == "None." or stripped.startswith(
        (_UNAVAILABLE_MARKER, "No traffic captured.")
    ):
        styled.stylize(REPORT_STYLES["unavailable"])
    elif any(marker in stripped for marker in _AVAILABLE_MARKERS):
        styled.stylize(REPORT_STYLES["available"])
    elif stripped.startswith(
        (
            "malformed_packet",
            "unsupported_protocol",
            "skipped_packet",
            "processing_warning",
        )
    ):
        styled.stylize(REPORT_STYLES["warning"])

    if ": " in line and stripped.split(": ", 1)[0] in {"Packets", "Bytes"}:
        styled.stylize(REPORT_STYLES["total"])
    first_word = stripped.split(": ", 1)[0]
    if first_word in _PROTOCOL_NAMES:
        protocol_start = len(line) - len(line.lstrip())
        styled.stylize(
            REPORT_STYLES["protocol"],
            protocol_start,
            protocol_start + len(first_word),
        )
    for pattern in _IDENTIFIER_PATTERNS:
        for match in pattern.finditer(line):
            styled.stylize(REPORT_STYLES["identifier"], match.start(), match.end())
    for match in _PORT_PATTERN.finditer(line):
        styled.stylize(REPORT_STYLES["port"], match.start(), match.end())
    return styled


def _new_rich_text(value: str = "") -> TextType:
    if rich_text_cls is None:
        raise RuntimeError("Rich text support is unavailable")
    return rich_text_cls(value)


def _should_use_rich_output() -> bool:
    """Only use Rich in interactive terminals where colour output is supported."""
    if rich_console_cls is None or rich_panel_cls is None:
        return False
    if os.environ.get("NO_COLOR") is not None:
        return False
    stdout = sys.stdout
    return bool(stdout.isatty())


def render_report(
    result: AnalysisResult,
    *,
    input_type: str,
    identity: str,
    redact: bool = False,
) -> str:
    """Render a complete terminal report without exposing packet contents."""
    redactor = Redactor(enabled=redact)
    lines = [
        "Traffic analysis report",
        f"Input: {input_type} ({_input_identity(identity, redactor)})",
        "",
        "Time range",
        f"  Start: {_format_time(result.start_time)}",
        f"  End: {_format_time(result.end_time)}",
        "",
        "Totals",
        f"  Packets: {result.total_packets}",
        f"  Bytes: {result.total_bytes}",
        "",
        "Processing",
        f"  Received: {result.processing.received}",
        f"  Decoded: {result.processing.decoded}",
        f"  Malformed: {result.processing.malformed}",
        f"  Unsupported: {result.processing.unsupported}",
        f"  Skipped: {result.processing.skipped}",
        "",
        "Traffic volume",
        *_volume_lines(result),
        "",
        "Protocol distribution",
        *_protocol_lines(result),
        "",
        "Top source endpoints",
        *_endpoint_lines(result.top_source_endpoints, redactor),
        "",
        "Top destination endpoints",
        *_endpoint_lines(result.top_destination_endpoints, redactor),
        "",
        "Top conversations",
        *_conversation_lines(result, redactor),
        "",
        "Flow analytics",
        *_flow_lines(result, redactor),
        "",
        "Packet-size summary",
        *_packet_size_lines(result),
        "",
        "DNS metadata",
        *_dns_lines(result, redactor),
        "",
        "HTTP metadata",
        *_http_lines(result, redactor),
        "",
        "TLS metadata",
        *_tls_lines(result, redactor),
        "",
        "Processing warnings",
        *_warning_lines(result.warnings),
    ]
    if result.total_packets == 0:
        lines.insert(2, "No packets captured.")
    return "\n".join(lines)


def _input_identity(identity: str, redactor: Redactor) -> str:
    """Keep paths out of normal reports and redact displayed identities."""
    basename = Path(identity).name or identity
    return redactor.identifier(basename, kind="input") or "<unknown>"


def _format_time(value: object) -> str:
    return str(value) if value is not None else "unavailable"


def _volume_lines(result: AnalysisResult) -> list[str]:
    if not result.time_buckets:
        return ["  No traffic captured."]
    return [
        f"  {bucket.start.isoformat()} - {bucket.end.isoformat()}: "
        f"{bucket.packets} packets, {bucket.bytes} bytes"
        for bucket in result.time_buckets
    ]


def _protocol_lines(result: AnalysisResult) -> list[str]:
    if not result.protocol_counters:
        return ["  No recognised protocols."]
    return [
        f"  {counter.protocol.value}: {counter.packets} packets, {counter.bytes} bytes"
        for counter in result.protocol_counters
    ]


def _endpoint_lines(items: tuple[tuple[object, int], ...], redactor: Redactor) -> list[str]:
    if not items:
        return ["  No observable endpoints."]
    return [f"  {redactor.endpoint(endpoint)}: {count}" for endpoint, count in items]  # type: ignore[arg-type]


def _conversation_lines(result: AnalysisResult, redactor: Redactor) -> list[str]:
    if not result.top_conversations:
        return ["  No observable conversations."]
    return [
        f"  {redactor.conversation(conversation)}: {count}"
        for conversation, count in result.top_conversations
    ]


def _flow_lines(result: AnalysisResult, redactor: Redactor) -> list[str]:
    if not result.top_flows:
        return ["  No flow analytics available."]
    return [
        f"  {redactor.conversation(flow.conversation)}: "
        f"{flow.packets} packets, {flow.bytes} bytes, "
        f"{flow.forward_packets} forward, {flow.reverse_packets} reverse, "
        f"duration {flow.duration_seconds:.6f}s, "
        f"rates {flow.packets_per_second:.6f} packets/s, "
        f"{flow.bytes_per_second:.6f} bytes/s"
        for flow in result.top_flows
    ]


def _packet_size_lines(result: AnalysisResult) -> list[str]:
    if not result.packet_sizes:
        return ["  No packet sizes available."]
    sizes = [item.size for item in result.packet_sizes]
    return [
        f"  Observed sizes: {', '.join(str(size) for size in sizes)}",
        f"  Size range: {min(sizes)}-{max(sizes)} bytes",
    ]


def _dns_lines(result: AnalysisResult, redactor: Redactor) -> list[str]:
    if not result.dns_summaries:
        return ["  No DNS metadata available."]
    return [f"  {redactor.dns(item)}" for item in result.dns_summaries]


def _http_lines(result: AnalysisResult, redactor: Redactor) -> list[str]:
    if not result.http_summaries:
        return ["  No HTTP metadata available."]
    return [f"  {redactor.http(item)}" for item in result.http_summaries]


def _tls_lines(result: AnalysisResult, redactor: Redactor) -> list[str]:
    if not result.tls_summaries:
        return ["  No TLS metadata available."]
    return [f"  {redactor.tls(item)}" for item in result.tls_summaries]


def _warning_lines(warnings: tuple[ProcessingWarning, ...]) -> list[str]:
    if not warnings:
        return ["  None."]
    return [
        "  "
        + warning.category.value
        + (f" (packet {warning.packet_index})" if warning.packet_index is not None else "")
        for warning in warnings
    ]


__all__ = ["render_report"]