from pathlib import Path

import pytest
from scapy.all import IP, UDP, Ether, PcapNgWriter, wrpcap

from traffic_analyser.limits import ResourceLimits
from traffic_analyser.pcap_reader import OfflineInputError, OfflinePcapReader


@pytest.fixture
def packet() -> Ether:
    return Ether() / IP(src="192.0.2.1", dst="192.0.2.2") / UDP(sport=1, dport=2)


def write_pcap(path: Path, packets: list[Ether]) -> None:
    wrpcap(str(path), packets)


def write_pcapng(path: Path, packets: list[Ether]) -> None:
    with PcapNgWriter(str(path)) as writer:
        for packet in packets:
            writer.write(packet)


@pytest.mark.parametrize(
    "suffix, writer",
    [(".pcap", write_pcap), (".pcapng", write_pcapng)],
)
def test_reader_supports_pcap_and_pcapng(
    tmp_path: Path, packet: Ether, suffix: str, writer: object
) -> None:
    path = tmp_path / f"capture{suffix}"
    writer(path, [packet])  # type: ignore[operator]

    with OfflinePcapReader(path, ResourceLimits()) as reader:
        record = next(reader)

    assert record.packet is not None
    assert record.captured_length == len(packet)
    assert record.original_length == len(packet)
    assert record.timestamp.tzinfo is not None


def test_empty_pcap_completes_without_records(tmp_path: Path) -> None:
    path = tmp_path / "empty.pcap"
    write_pcap(path, [])

    with OfflinePcapReader(path, ResourceLimits()) as reader:
        assert list(reader) == []
        assert reader.warnings == ()


def test_truncated_pcap_becomes_a_warning(tmp_path: Path, packet: Ether) -> None:
    path = tmp_path / "truncated.pcap"
    write_pcap(path, [packet])
    path.write_bytes(path.read_bytes()[:-4])

    with OfflinePcapReader(path, ResourceLimits()) as reader:
        records = list(reader)
        warnings = reader.warnings

    assert len(records) == 1
    assert records[0].captured_length < records[0].original_length
    assert len(warnings) == 1
    assert warnings[0].category.value == "malformed_packet"


@pytest.mark.parametrize(
    "path_factory",
    [
        lambda tmp_path: tmp_path / "missing.pcap",
        lambda tmp_path: tmp_path,
        lambda tmp_path: tmp_path / "unsupported.bin",
    ],
)
def test_invalid_inputs_raise_offline_error(
    tmp_path: Path, path_factory: object
) -> None:
    path = path_factory(tmp_path)  # type: ignore[operator]
    if path.name == "unsupported.bin":
        path.write_bytes(b"not a capture")

    with pytest.raises(OfflineInputError), OfflinePcapReader(path, ResourceLimits()):
        pass


def test_symbolic_links_are_rejected(tmp_path: Path, packet: Ether) -> None:
    target = tmp_path / "capture.pcap"
    link = tmp_path / "link.pcap"
    write_pcap(target, [packet])
    link.symlink_to(target)

    with pytest.raises(OfflineInputError, match="symbolic link"), OfflinePcapReader(
        link, ResourceLimits()
    ):
        pass


def test_unreadable_input_raises_offline_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "capture.pcap"
    path.write_bytes(b"capture")

    def deny_open(*args: object, **kwargs: object) -> int:
        raise PermissionError("permission denied")

    monkeypatch.setattr("traffic_analyser.pcap_reader.os.open", deny_open)

    with pytest.raises(OfflineInputError, match="unreadable"), OfflinePcapReader(
        path, ResourceLimits()
    ):
        pass


def test_file_size_limit_is_checked_before_reading(tmp_path: Path, packet: Ether) -> None:
    path = tmp_path / "capture.pcap"
    write_pcap(path, [packet])

    with pytest.raises(OfflineInputError, match="file-size"), OfflinePcapReader(
        path, ResourceLimits(max_file_size=1)
    ):
        pass


def test_packet_and_byte_limits_stop_iteration(tmp_path: Path, packet: Ether) -> None:
    path = tmp_path / "capture.pcap"
    write_pcap(path, [packet, packet])

    with OfflinePcapReader(
        path,
        ResourceLimits(max_packets=1, max_bytes=len(packet) * 2),
    ) as reader:
        assert len(list(reader)) == 1

    with OfflinePcapReader(
        path,
        ResourceLimits(max_packets=10, max_bytes=len(packet)),
    ) as reader:
        assert len(list(reader)) == 1
