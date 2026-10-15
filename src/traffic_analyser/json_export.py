"""Versioned, metadata-only JSON export for completed analyses."""

from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any

from traffic_analyser.models import (
    AnalysisResult,
    DnsMetadata,
    HttpMetadata,
    TlsMetadata,
)
from traffic_analyser.privacy import Redactor

JSON_SCHEMA_VERSION = "1.0"


class JsonExportError(ValueError):
    """Raised when JSON export cannot safely complete."""


def export_json(
    result: AnalysisResult,
    destination: str | os.PathLike[str],
    *,
    redact: bool = False,
) -> Path:
    """Write one deterministic analysis document without overwriting files."""
    output_path = _validate_destination(destination)
    document = serialize_analysis(result, redact=redact)
    payload = json.dumps(document, indent=2, sort_keys=True) + "\n"

    try:
        with output_path.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except FileExistsError as error:
        raise JsonExportError("JSON export destination already exists") from error
    except OSError as error:
        output_path.unlink(missing_ok=True)
        raise JsonExportError(f"unable to write JSON export: {error}") from error
    return output_path


def serialize_analysis(
    result: AnalysisResult, *, redact: bool = False
) -> dict[str, Any]:
    """Convert a bounded result into the stable public export schema."""
    redactor = Redactor(enabled=redact)
    return {
        "schema_version": JSON_SCHEMA_VERSION,
        "analysis": {
            "totals": {
                "packets": result.total_packets,
                "bytes": result.total_bytes,
            },
            "time_range": {
                "start": _timestamp(result.start_time),
                "end": _timestamp(result.end_time),
            },
            "time_buckets": [
                {
                    "start": _timestamp(bucket.start),
                    "end": _timestamp(bucket.end),
                    "packets": bucket.packets,
                    "bytes": bucket.bytes,
                }
                for bucket in result.time_buckets
            ],
            "protocols": [
                {
                    "protocol": counter.protocol.value,
                    "packets": counter.packets,
                    "bytes": counter.bytes,
                }
                for counter in result.protocol_counters
            ],
            "top_source_endpoints": _endpoint_items(
                result.top_source_endpoints, redactor
            ),
            "top_destination_endpoints": _endpoint_items(
                result.top_destination_endpoints, redactor
            ),
            "top_conversations": [
                {
                    "conversation": redactor.conversation(conversation),
                    "count": count,
                }
                for conversation, count in result.top_conversations
            ],
            "flows": [
                {
                    "conversation": redactor.conversation(flow.conversation),
                    "packets": flow.packets,
                    "bytes": flow.bytes,
                    "first_seen": _timestamp(flow.first_seen),
                    "last_seen": _timestamp(flow.last_seen),
                    "duration_seconds": flow.duration_seconds,
                    "forward_packets": flow.forward_packets,
                    "reverse_packets": flow.reverse_packets,
                    "packets_per_second": flow.packets_per_second,
                    "bytes_per_second": flow.bytes_per_second,
                }
                for flow in result.top_flows
            ],
            "packet_sizes": [
                {"size": item.size, "packets": item.packets}
                for item in result.packet_sizes
            ],
            "processing": {
                "received": result.processing.received,
                "decoded": result.processing.decoded,
                "unsupported": result.processing.unsupported,
                "malformed": result.processing.malformed,
                "skipped": result.processing.skipped,
            },
            "warnings": [
                {
                    "category": warning.category.value,
                    "packet_index": warning.packet_index,
                }
                for warning in result.warnings
            ],
            "metadata": {
                "dns": [_dns_item(item, redactor) for item in result.dns_summaries],
                "http": [
                    _http_item(item, redactor) for item in result.http_summaries
                ],
                "tls": [_tls_item(item, redactor) for item in result.tls_summaries],
            },
        },
    }


def _validate_destination(destination: str | os.PathLike[str]) -> Path:
    output_path = Path(destination)
    parent = output_path.parent
    if output_path.is_symlink() or output_path.exists():
        raise JsonExportError("JSON export destination already exists")
    if output_path.suffix.lower() != ".json":
        raise JsonExportError("JSON export destination must use the .json extension")
    if _has_symlink_component(parent) or not parent.is_dir():
        raise JsonExportError("JSON export directory must be an existing directory")
    if not os.access(parent, os.W_OK):
        raise JsonExportError("JSON export directory is not writable")
    return output_path


def _has_symlink_component(path: Path) -> bool:
    current = path
    while current != current.parent:
        if current.is_symlink():
            return True
        current = current.parent
    return current.is_symlink()


def _timestamp(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None or value.utcoffset() is None:
        raise JsonExportError("analysis timestamps must be timezone-aware")
    return value.isoformat()


def _endpoint_items(
    items: tuple[tuple[Any, int], ...], redactor: Redactor
) -> list[dict[str, Any]]:
    return [
        {"endpoint": redactor.endpoint(endpoint), "count": count}
        for endpoint, count in items
    ]


def _dns_item(metadata: DnsMetadata, redactor: Redactor) -> dict[str, Any]:
    safe = redactor.dns(metadata)
    return {
        "query_name": safe.query_name,
        "response_code": safe.response_code,
        "is_response": safe.is_response,
    }


def _http_item(metadata: HttpMetadata, redactor: Redactor) -> dict[str, Any]:
    safe = redactor.http(metadata)
    return {
        "method": safe.method,
        "host": safe.host,
        "path": safe.path,
        "status": safe.status,
    }


def _tls_item(metadata: TlsMetadata, redactor: Redactor) -> dict[str, Any]:
    safe = redactor.tls(metadata)
    return {
        "version": safe.version,
        "handshake_type": safe.handshake_type,
        "server_name": safe.server_name,
    }


__all__ = [
    "JSON_SCHEMA_VERSION",
    "JsonExportError",
    "export_json",
    "serialize_analysis",
]