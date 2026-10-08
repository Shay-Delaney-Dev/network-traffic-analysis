from dataclasses import fields
from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv6Address

from scapy.all import (
    DNS,
    DNSQR,
    ICMP,
    IP,
    TCP,
    UDP,
    Ether,
    ICMPv6EchoRequest,
    IPv6,
    Raw,
)
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
from scapy.layers.tls.handshake import TLSClientHello
from scapy.layers.tls.record import TLS
from scapy.packet import Packet

from traffic_analyser.decoder import DecodeContext, DecodeStatus, decode
from traffic_analyser.models import Protocol

TIMESTAMP = datetime(2026, 1, 1, tzinfo=UTC)


class BareTLS(TLS):
    def __init__(self) -> None:
        Packet.__init__(self)

    def __bytes__(self) -> bytes:
        return b"tls header"


class BareClientHello(TLSClientHello):
    def __init__(self, version: int, extensions: list[Packet]) -> None:
        Packet.__init__(self)
        self.version = version
        self.msgtype = "client_hello"
        self.ext = extensions

    def __bytes__(self) -> bytes:
        return b"tls client hello"


class BareServerName:
    servername = "example.com"


class BareServerNameExtension:
    def __init__(self) -> None:
        self.servernames = [BareServerName()]


BareServerNameExtension.__name__ = "TLS_Ext_ServerName"


class MetadataPacket(Packet):
    def __init__(self, layers: list[Packet]) -> None:
        Packet.__init__(self)
        self._metadata_layers = layers

    def getlayer(self, layer: object, *args: object, **kwargs: object) -> Packet | None:
        for candidate in self._metadata_layers:
            if isinstance(candidate, layer):  # type: ignore[arg-type]
                return candidate
        return None

    def layers(self) -> list[type[Packet]]:
        return [type(layer) for layer in self._metadata_layers]

    def __len__(self) -> int:
        return 128


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


def test_decode_extracts_bounded_dns_metadata() -> None:
    packet = Ether() / IP() / UDP(sport=53000, dport=53) / DNS(
        qr=1, rcode=3, qd=DNSQR(qname="example.com")
    )

    result = decode(packet)

    assert result.metadata is not None
    assert result.metadata.dns is not None
    assert result.metadata.dns.query_name == "example.com."
    assert result.metadata.dns.response_code == 3
    assert result.metadata.dns.is_response is True


def test_decode_extracts_http_fields_without_query_or_payload() -> None:
    packet = (
        Ether()
        / IP()
        / TCP()
        / HTTP()
        / HTTPRequest(
            Method=b"GET",
            Host=b"example.com",
            Path=b"/safe?token=secret#fragment",
        )
        / Raw(load=b"Authorization: Bearer secret")
    )

    result = decode(packet)

    assert result.metadata is not None
    assert result.metadata.http is not None
    assert result.metadata.http.method == "GET"
    assert result.metadata.http.host == "example.com"
    assert result.metadata.http.path == "/safe"
    assert "secret" not in repr(result.metadata)


def test_decode_extracts_http_response_status() -> None:
    result = decode(Ether() / IP() / TCP() / HTTP() / HTTPResponse(Status_Code=b"200"))

    assert result.metadata is not None
    assert result.metadata.http == result.metadata.http.__class__(status=200)


def test_decode_extracts_tls_client_hello_sni_without_decryption() -> None:
    packet = MetadataPacket(
        [
            Ether(),
            IP(),
            TCP(dport=443),
            BareTLS(),
            BareClientHello(
                version=0x0303,
                extensions=[BareServerNameExtension()],
            ),
        ]
    )

    result = decode(packet)

    assert result.metadata is not None
    assert result.metadata.tls is not None
    assert result.metadata.tls.version == "TLS 1.2"
    assert result.metadata.tls.handshake_type == "client_hello"
    assert result.metadata.tls.server_name == "example.com"


def test_decode_marks_incomplete_encrypted_and_over_cap_metadata_unavailable() -> None:
    incomplete_tls = decode(MetadataPacket([Ether(), IP(), TCP(dport=443), BareTLS()]))
    oversized_dns = decode(
        Ether() / IP() / UDP(dport=53) / DNS(qd=DNSQR(qname="x" * 300)),
        DecodeContext(inspected_header_bytes=64),
    )
    oversized_http = decode(
        Ether() / IP() / TCP() / HTTP() / HTTPRequest(Host=b"h" * 300),
        DecodeContext(metadata_string_length=64),
    )

    assert incomplete_tls.metadata is not None
    assert incomplete_tls.metadata.tls is None
    assert oversized_dns.metadata is not None
    assert oversized_dns.metadata.dns is None
    assert oversized_http.metadata is not None
    assert oversized_http.metadata.http is None