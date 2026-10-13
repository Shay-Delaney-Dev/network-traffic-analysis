"""Metadata-only terminal reports for completed analysis results."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any, TextIO

if TYPE_CHECKING:
    from rich.console import Console as ConsoleType

rich_console_cls: Any | None
rich_panel_cls: Any | None

try:
    from rich.console import Console as _RichConsole
    from rich.panel import Panel as _RichPanel
    rich_console_cls = _RichConsole
    rich_panel_cls = _RichPanel
except ImportError:  # pragma: no cover - optional runtime dependency fallback
    rich_console_cls = None
    rich_panel_cls = None

from traffic_analyser.models import AnalysisResult, ProcessingWarning
from traffic_analyser.privacy import Redactor


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
    """Print the report with a Rich panel in interactive terminals and plain text otherwise."""
    text = render_report(result, input_type=input_type, identity=identity, redact=redact)
    if use_rich is None:
        use_rich = _should_use_rich_output()
    if not use_rich or rich_console_cls is None or rich_panel_cls is None:
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
            text,
            title="[bold cyan]Traffic analysis report[/bold cyan]",
            subtitle=f"[dim]{input_type}[/dim]",
            border_style="cyan",
            padding=(0, 1),
        )
    )


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