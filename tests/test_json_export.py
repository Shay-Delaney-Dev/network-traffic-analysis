import json
from datetime import UTC, datetime
from ipaddress import IPv4Address

import pytest

from traffic_analyser.json_export import (
    JSON_SCHEMA_VERSION,
    JsonExportError,
    export_json,
    serialize_analysis,
)
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


def populated_result() -> AnalysisResult:
    first = EndpointKey(IPv4Address("192.0.2.1"), 1234)
    second = EndpointKey(IPv4Address("198.51.100.2"), 443)
    return AnalysisResult(
        total_packets=2,
        total_bytes=160,
        start_time=datetime(2026, 1, 1, tzinfo=UTC),
        end_time=datetime(2026, 1, 1, 0, 0, 2, tzinfo=UTC),
        time_buckets=(TimeBucket(
            datetime(2026, 1, 1, tzinfo=UTC),
            datetime(2026, 1, 1, 0, 0, 10, tzinfo=UTC),
            2,
            160,
        ),),
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
        http_summaries=(HttpMetadata("GET", "service.example", "/private", 200),),
        tls_summaries=(TlsMetadata("TLS 1.3", "client_hello", "secure.example"),),
    )


def test_serialize_analysis_has_stable_metadata_only_schema_and_redaction() -> None:
    document = serialize_analysis(populated_result(), redact=True)

    assert document["schema_version"] == JSON_SCHEMA_VERSION
    assert document["analysis"]["totals"] == {"packets": 2, "bytes": 160}
    assert document["analysis"]["time_range"]["start"].endswith("+00:00")
    assert document["analysis"]["protocols"] == [
        {"protocol": "tcp", "packets": 2, "bytes": 160}
    ]
    serialized = json.dumps(document, sort_keys=True)
    for sensitive in (
        "192.0.2.1",
        "198.51.100.2",
        "internal.example",
        "service.example",
        "secure.example",
        "payload-secret",
    ):
        assert sensitive not in serialized
    assert "<redacted:" in serialized


def test_empty_result_serializes_with_null_time_range() -> None:
    document = serialize_analysis(AnalysisResult())

    assert document["analysis"]["time_range"] == {"start": None, "end": None}
    assert document["analysis"]["metadata"] == {"dns": [], "http": [], "tls": []}
    assert json.loads(json.dumps(document)) == document


def test_naive_timestamp_is_rejected() -> None:
    with pytest.raises(JsonExportError, match="timezone-aware"):
        serialize_analysis(AnalysisResult(start_time=datetime.min))  # noqa: DTZ901


def test_export_refuses_collisions_and_unsafe_destinations(tmp_path) -> None:
    destination = tmp_path / "analysis.json"
    assert export_json(AnalysisResult(), destination) == destination
    assert json.loads(destination.read_text()) ["schema_version"] == JSON_SCHEMA_VERSION

    with pytest.raises(JsonExportError, match="already exists"):
        export_json(AnalysisResult(), destination)
    with pytest.raises(JsonExportError, match=r"\.json"):
        export_json(AnalysisResult(), tmp_path / "analysis.txt")
    with pytest.raises(JsonExportError, match="existing directory"):
        export_json(AnalysisResult(), tmp_path / "missing" / "analysis.json")


def test_cli_writes_requested_export_and_preserves_plain_report(
    monkeypatch, tmp_path, capsys
) -> None:
    monkeypatch.setattr(
        "traffic_analyser.cli.analyze_offline",
        lambda _path, _limits: AnalysisResult(),
    )
    destination = tmp_path / "analysis.json"

    from traffic_analyser.cli import main

    assert main(["pcap", "capture.pcap", "--export-json", str(destination)]) == 0
    assert json.loads(destination.read_text())["schema_version"] == JSON_SCHEMA_VERSION
    assert "Traffic analysis report" in capsys.readouterr().out