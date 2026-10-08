"""Convert transient Scapy packets into metadata-only normalized records."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from ipaddress import IPv4Address, IPv6Address
from typing import TypeAlias

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.packet import NoPayload, Packet

from traffic_analyser.models import PacketMetadata, Protocol


class DecodeStatus(str, Enum):
    """Categories returned by the normalized decoder."""

    DECODED = "decoded"
    UNSUPPORTED = "unsupported"
    MALFORMED = "malformed"
    SKIPPED = "skipped"


@dataclass(frozen=True, slots=True)
class DecodeContext:
    """Optional acquisition metadata supplied by offline or live readers."""

    timestamp: datetime | None = None
    captured_length: int | None = None
    original_length: int | None = None


@dataclass(frozen=True, slots=True)
class DecodeResult:
    """A categorized decoder result that never retains the source packet."""

    status: DecodeStatus
    metadata: PacketMetadata | None = None
    reason: str | None = None

    @property
    def decoded(self) -> bool:
        return self.status is DecodeStatus.DECODED


DecodeOutcome: TypeAlias = DecodeResult


def decode(packet: Packet, context: DecodeContext | None = None) -> DecodeResult:
    """Decode one Scapy packet into normalized metadata or a skip category."""
    if not isinstance(packet, Packet):
        return DecodeResult(DecodeStatus.MALFORMED, reason="packet is not a Scapy packet")

    try:
        context = context or DecodeContext()
        captured_length = (
            len(packet) if context.captured_length is None else context.captured_length
        )
        original_length = context.original_length
        if original_length is None:
            original_length = int(getattr(packet, "wirelen", captured_length) or captured_length)
        timestamp = context.timestamp or _packet_timestamp(packet)
        if captured_length < 0 or original_length < captured_length:
            return DecodeResult(DecodeStatus.MALFORMED, reason="invalid packet lengths")
        if captured_length < original_length:
            return DecodeResult(DecodeStatus.MALFORMED, reason="truncated packet")

        link_protocol = _link_protocol(packet)
        if link_protocol is None and not _starts_with_network_layer(packet):
            return DecodeResult(DecodeStatus.UNSUPPORTED, reason="unsupported link layer")

        ip_layer = packet.getlayer(IP)
        ipv6_layer = packet.getlayer(IPv6)
        if ip_layer is not None and ipv6_layer is not None:
            return DecodeResult(DecodeStatus.MALFORMED, reason="multiple network layers")
        network_layer = ip_layer or ipv6_layer
        if network_layer is None and _has_unknown_network_layer(packet):
            return DecodeResult(DecodeStatus.UNSUPPORTED, reason="unsupported network layer")

        metadata = _build_metadata(
            packet,
            timestamp=timestamp,
            captured_length=captured_length,
            original_length=original_length,
            link_protocol=link_protocol,
            network_layer=network_layer,
        )
        return DecodeResult(DecodeStatus.DECODED, metadata=metadata)
    except (AttributeError, IndexError, TypeError, ValueError, OverflowError) as error:
        return DecodeResult(DecodeStatus.MALFORMED, reason=str(error))


def _packet_timestamp(packet: Packet) -> datetime:
    value = getattr(packet, "time", None)
    if value is None:
        return datetime.now(UTC)
    return datetime.fromtimestamp(float(value), tz=UTC)


def _link_protocol(packet: Packet) -> Protocol | None:
    return Protocol.ETHERNET if packet.getlayer(Ether) is not None else None


def _starts_with_network_layer(packet: Packet) -> bool:
    return packet.__class__ in (IP, IPv6)


def _has_unknown_network_layer(packet: Packet) -> bool:
    if packet.getlayer(Ether) is None:
        return False
    payload = packet.payload
    return not isinstance(payload, NoPayload) and packet.getlayer(IP) is None and packet.getlayer(IPv6) is None


def _build_metadata(
    packet: Packet,
    *,
    timestamp: datetime,
    captured_length: int,
    original_length: int,
    link_protocol: Protocol | None,
    network_layer: Packet | None,
) -> PacketMetadata:
    transport_protocol: Protocol | None = None
    source_address: IPv4Address | IPv6Address | None = None
    destination_address: IPv4Address | IPv6Address | None = None
    if isinstance(network_layer, IP):
        network_protocol = Protocol.IPV4
        source_address = IPv4Address(str(network_layer.src))
        destination_address = IPv4Address(str(network_layer.dst))
    elif isinstance(network_layer, IPv6):
        network_protocol = Protocol.IPV6
        source_address = IPv6Address(str(network_layer.src))
        destination_address = IPv6Address(str(network_layer.dst))
    else:
        network_protocol = None

    tcp = packet.getlayer(TCP)
    udp = packet.getlayer(UDP)
    icmp = packet.getlayer(ICMP)
    icmpv6 = _icmpv6_layer(packet)
    source_port: int | None = None
    destination_port: int | None = None
    tcp_flags: tuple[str, ...] = ()
    icmp_type: int | None = None
    icmp_code: int | None = None
    if tcp is not None:
        transport_protocol = Protocol.TCP
        source_port = int(tcp.sport)
        destination_port = int(tcp.dport)
        tcp_flags = tuple(str(tcp.flags))
    elif udp is not None:
        transport_protocol = Protocol.UDP
        source_port = int(udp.sport)
        destination_port = int(udp.dport)
    elif icmp is not None:
        transport_protocol = Protocol.ICMP
        icmp_type = int(icmp.type)
        icmp_code = int(icmp.code)
    elif icmpv6 is not None:
        transport_protocol = Protocol.ICMPV6
        icmp_type = int(icmpv6.type)
        icmp_code = int(icmpv6.code)

    ethernet = packet.getlayer(Ether)
    return PacketMetadata(
        timestamp=timestamp,
        captured_length=captured_length,
        original_length=original_length,
        link_protocol=link_protocol,
        network_protocol=network_protocol,
        transport_protocol=transport_protocol,
        source_address=source_address,
        destination_address=destination_address,
        source_port=source_port,
        destination_port=destination_port,
        source_mac=_optional_string(ethernet, "src"),
        destination_mac=_optional_string(ethernet, "dst"),
        tcp_flags=tcp_flags,
        icmp_type=icmp_type,
        icmp_code=icmp_code,
    )


def _icmpv6_layer(packet: Packet) -> Packet | None:
    for layer_class in packet.layers():
        if layer_class.__name__.startswith("ICMPv6"):
            return packet.getlayer(layer_class)
    return None


def _optional_string(layer: Packet | None, field_name: str) -> str | None:
    if layer is None:
        return None
    value = getattr(layer, field_name, None)
    return None if value is None else str(value)


__all__ = ["DecodeContext", "DecodeOutcome", "DecodeResult", "DecodeStatus", "decode"]