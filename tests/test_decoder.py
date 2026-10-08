from dataclasses import fields
from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv6Address

from scapy.all import ICMP, IP, TCP, UDP, Ether, ICMPv6EchoRequest, IPv6, Raw
from scapy.packet import Packet

from traffic_analyser.decoder import DecodeContext, DecodeStatus, decode
from traffic_analyser.models import Protocol

TIMESTAMP = datetime(2026, 1, 1, tzinfo=UTC)


def test_decode_ipv4_tcp_normalizes_headers_only() -> None:
    packet = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(
        src="192.0.2.1", dst="192.0.2.2"
    ) / TCP(sport=1234, dport=443, flags="SA") / Raw(load=b"secret payload")

    result = decode(packet, DecodeContext(TIMESTAMP, 100, 100))

    assert result.status is DecodeStatus.DECODED
    assert result.metadata is not None
    assert result.metadata.timestamp == TIMESTAMP
    assert result.metadata.link_protocol is Protocol.ETHERNET
    assert result.metadata.network_protocol is Protocol.IPV4
    assert result.metadata.transport_protocol is Protocol.TCP
    assert result.metadata.source_address == IPv4Address("192.0.2.1")
    assert result.metadata.destination_address == IPv4Address("192.0.2.2")
    assert result.metadata.source_port == 1234
    assert result.metadata.destination_port == 443
    assert result.metadata.tcp_flags == ("S", "A")
    assert "secret payload" not in repr(result)
    assert not any(
        isinstance(getattr(result.metadata, field.name), Packet)
        for field in fields(result.metadata)
    )


def test_decode_ipv6_udp_and_icmpv6() -> None:
    udp_result = decode(Ether() / IPv6(src="2001:db8::1", dst="2001:db8::2") / UDP(sport=53, dport=5000))
    icmp_result = decode(
        Ether() / IPv6(src="2001:db8::1", dst="2001:db8::2") / ICMPv6EchoRequest()
    )

    assert udp_result.metadata is not None
    assert udp_result.metadata.network_protocol is Protocol.IPV6
    assert udp_result.metadata.transport_protocol is Protocol.UDP
    assert udp_result.metadata.source_address == IPv6Address("2001:db8::1")
    assert udp_result.metadata.destination_port == 5000
    assert icmp_result.metadata is not None
    assert icmp_result.metadata.transport_protocol is Protocol.ICMPV6
    assert icmp_result.metadata.icmp_type == 128


def test_decode_icmp_and_missing_transport_fields() -> None:
    result = decode(Ether() / IP(src="192.0.2.1", dst="192.0.2.2") / ICMP(type=3, code=1))
    empty = decode(Ether(), DecodeContext(TIMESTAMP, 14, 14))

    assert result.metadata is not None
    assert result.metadata.transport_protocol is Protocol.ICMP
    assert result.metadata.icmp_type == 3
    assert result.metadata.icmp_code == 1
    assert empty.metadata is not None
    assert empty.metadata.network_protocol is None
    assert empty.metadata.transport_protocol is None


def test_decode_rejects_unknown_layers_and_categorizes_malformed_input() -> None:
    unsupported = decode(Ether() / Raw(load=b"not an IP packet"))
    malformed = decode(object())  # type: ignore[arg-type]
    invalid_lengths = decode(Ether(), DecodeContext(TIMESTAMP, 15, 14))
    truncated = decode(Ether(), DecodeContext(TIMESTAMP, 13, 14))

    assert unsupported.status is DecodeStatus.UNSUPPORTED
    assert malformed.status is DecodeStatus.MALFORMED
    assert invalid_lengths.status is DecodeStatus.MALFORMED
    assert truncated.status is DecodeStatus.MALFORMED
    assert unsupported.metadata is None
    assert malformed.reason is not None