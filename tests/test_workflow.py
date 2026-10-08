from datetime import UTC, datetime
from pathlib import Path

import pytest
from scapy.all import IP, TCP, Ether, PcapNgWriter, Raw, wrpcap

from traffic_analyser.decoder import DecodeResult, DecodeStatus, decode
from traffic_analyser.limits import ResourceLimits
from traffic_analyser.pcap_reader import OfflinePacket
from traffic_analyser.workflow import analyze_offline, process_packet_records


def write_capture(path: Path, packets: list[Ether]) -> None:
    if path.suffix == ".pcapng":
        with PcapNgWriter(str(path)) as writer:
            for packet in packets:
                writer.write(packet)
    else:
        wrpcap(str(path), packets)


@pytest.fixture
def packets() -> list[Ether]:
    first = Ether() / IP(src="192.0.2.1", dst="192.0.2.2") / TCP(sport=1000, dport=443)
    second = Ether() / IP(src="192.0.2.2", dst="192.0.2.1") / TCP(sport=443, dport=1000)
    first.time = 1_700_000_000
    second.time = 1_700_000_002
    return [first, second]


@pytest.mark.parametrize("suffix", [".pcap", ".pcapng"])
def test_offline_workflow_supports_capture_formats(
    tmp_path: Path, packets: list[Ether], suffix: str
) -> None:
    path = tmp_path / f"capture{suffix}"
    write_capture(path, packets)

    result = analyze_offline(path, ResourceLimits())

    assert result.total_packets == 2
    assert result.total_bytes == sum(len(packet) for packet in packets)
    assert result.processing.received == 2
    assert result.processing.decoded == 2
    assert result.processing.malformed == 0


def test_offline_result_matches_equivalent_injected_packet_stream(
    tmp_path: Path, packets: list[Ether]
) -> None:
    path = tmp_path / "capture.pcap"
    write_capture(path, packets)
    limits = ResourceLimits()

    offline_result = analyze_offline(path, limits)
    timestamps = (
        datetime.fromtimestamp(1_700_000_000, tz=UTC),
        datetime.fromtimestamp(1_700_000_002, tz=UTC),
    )
    records = tuple(
        OfflinePacket(packet, timestamp, len(packet), len(packet))
        for packet, timestamp in zip(packets, timestamps)
    )
    injected_result = process_packet_records(records, limits)

    assert injected_result == offline_result


def test_malformed_record_generates_warning_and_later_record_is_analyzed(
    tmp_path: Path, packets: list[Ether], monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "capture.pcap"
    write_capture(path, packets)
    real_decode = decode
    calls = 0

    def decode_first_as_malformed(packet: object, context: object) -> DecodeResult:
        nonlocal calls
        calls += 1
        if calls == 1:
            return DecodeResult(DecodeStatus.MALFORMED, reason="test malformed packet")
        return real_decode(packet, context)  # type: ignore[arg-type]

    monkeypatch.setattr("traffic_analyser.workflow.decode", decode_first_as_malformed)

    result = analyze_offline(path, ResourceLimits())

    assert result.processing.received == 2
    assert result.processing.malformed == 1
    assert result.processing.decoded == 1
    assert any(warning.message == "test malformed packet" for warning in result.warnings)


def test_empty_and_all_skipped_inputs_produce_valid_results(tmp_path: Path) -> None:
    empty_path = tmp_path / "empty.pcap"
    write_capture(empty_path, [])
    empty = analyze_offline(empty_path, ResourceLimits())

    skipped_path = tmp_path / "skipped.pcap"
    write_capture(skipped_path, [Ether() / Raw(load=b"unsupported")])
    skipped = analyze_offline(skipped_path, ResourceLimits())

    assert empty.total_packets == 0
    assert empty.processing.received == 0
    assert skipped.total_packets == 0
    assert skipped.processing.unsupported == 1
    assert skipped.warnings