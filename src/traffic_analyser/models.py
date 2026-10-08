"""Typed, metadata-only contracts shared by the analyser pipeline."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, IntEnum
from ipaddress import IPv4Address, IPv6Address
from types import MappingProxyType
from typing import TypeAlias

IPAddress: TypeAlias = IPv4Address | IPv6Address


class Protocol(str, Enum):
    """Protocol labels used by normalized records and aggregate counters."""

    ETHERNET = "ethernet"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    ICMPV6 = "icmpv6"
    DNS = "dns"
    HTTP = "http"
    TLS = "tls"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class EndpointKey:
    """An endpoint identified by an IP address and optional transport port."""

    address: IPAddress
    port: int | None = None

    def __post_init__(self) -> None:
        if self.port is not None and not 0 <= self.port <= 65535:
            raise ValueError("endpoint port must be between 0 and 65535")

    def canonical(self) -> str:
        """Return the stable ``address[:port]`` representation for reports."""
        address = str(self.address)
        return f"{address}:{self.port}" if self.port is not None else address


@dataclass(frozen=True, slots=True)
class ConversationKey:
    """A bidirectional flow with endpoints sorted by their canonical values.

    Sorting makes ``(source, destination)`` and ``(destination, source)`` the
    same key while retaining address-family information in each endpoint.
    """

    first: EndpointKey
    second: EndpointKey

    @classmethod
    def from_endpoints(cls, first: EndpointKey, second: EndpointKey) -> ConversationKey:
        """Build a canonical key by lexicographically ordering endpoint values."""
        return cls(*sorted((first, second), key=lambda endpoint: endpoint.canonical()))

    def canonical(self) -> str:
        return f"{self.first.canonical()} <-> {self.second.canonical()}"


@dataclass(frozen=True, slots=True)
class DnsMetadata:
    """Bounded DNS metadata extracted without retaining packet payloads."""

    query_name: str | None = None
    response_code: int | None = None
    is_response: bool | None = None


@dataclass(frozen=True, slots=True)
class HttpMetadata:
    """Observable HTTP header metadata."""

    method: str | None = None
    host: str | None = None
    path: str | None = None
    status: int | None = None


@dataclass(frozen=True, slots=True)
class TlsMetadata:
    """Observable TLS handshake metadata; no decrypted content is represented."""

    version: str | None = None
    handshake_type: str | None = None
    server_name: str | None = None


@dataclass(frozen=True, slots=True)
class PacketMetadata:
    """Normalized packet metadata; raw packets and arbitrary bytes are excluded."""

    timestamp: datetime
    captured_length: int
    original_length: int
    link_protocol: Protocol | None = None
    network_protocol: Protocol | None = None
    transport_protocol: Protocol | None = None
    source_address: IPAddress | None = None
    destination_address: IPAddress | None = None
    source_port: int | None = None
    destination_port: int | None = None
    source_mac: str | None = None
    destination_mac: str | None = None
    tcp_flags: tuple[str, ...] = ()
    icmp_type: int | None = None
    icmp_code: int | None = None
    dns: DnsMetadata | None = None
    http: HttpMetadata | None = None
    tls: TlsMetadata | None = None

    def __post_init__(self) -> None:
        if self.captured_length < 0 or self.original_length < 0:
            raise ValueError("packet lengths cannot be negative")
        if self.captured_length > self.original_length:
            raise ValueError("captured length cannot exceed original length")
        for port in (self.source_port, self.destination_port):
            if port is not None and not 0 <= port <= 65535:
                raise ValueError("packet ports must be between 0 and 65535")

    def source_endpoint(self) -> EndpointKey | None:
        if self.source_address is None:
            return None
        return EndpointKey(self.source_address, self.source_port)

    def destination_endpoint(self) -> EndpointKey | None:
        if self.destination_address is None:
            return None
        return EndpointKey(self.destination_address, self.destination_port)

    def conversation(self) -> ConversationKey | None:
        source = self.source_endpoint()
        destination = self.destination_endpoint()
        if source is None or destination is None:
            return None
        return ConversationKey.from_endpoints(source, destination)


@dataclass(frozen=True, slots=True)
class ProtocolCounter:
    protocol: Protocol
    packets: int = 0
    bytes: int = 0


@dataclass(frozen=True, slots=True)
class TimeBucket:
    start: datetime
    end: datetime
    packets: int = 0
    bytes: int = 0


class WarningCategory(str, Enum):
    MALFORMED_PACKET = "malformed_packet"
    UNSUPPORTED_PROTOCOL = "unsupported_protocol"
    SKIPPED_PACKET = "skipped_packet"
    PROCESSING = "processing_warning"


@dataclass(frozen=True, slots=True)
class ProcessingWarning:
    category: WarningCategory
    message: str
    packet_index: int | None = None


@dataclass(frozen=True, slots=True)
class ProcessingStatistics:
    received: int = 0
    decoded: int = 0
    unsupported: int = 0
    malformed: int = 0
    skipped: int = 0


@dataclass(frozen=True, slots=True)
class AnalysisResult:
    """Final bounded analysis output consumed by reports and visualizations."""

    total_packets: int = 0
    total_bytes: int = 0
    start_time: datetime | None = None
    end_time: datetime | None = None
    time_buckets: tuple[TimeBucket, ...] = ()
    protocol_counters: tuple[ProtocolCounter, ...] = ()
    top_source_endpoints: tuple[tuple[EndpointKey, int], ...] = ()
    top_destination_endpoints: tuple[tuple[EndpointKey, int], ...] = ()
    top_conversations: tuple[tuple[ConversationKey, int], ...] = ()
    packet_sizes: tuple[int, ...] = ()
    processing: ProcessingStatistics = field(default_factory=ProcessingStatistics)
    warnings: tuple[ProcessingWarning, ...] = ()
    dns_summaries: tuple[DnsMetadata, ...] = ()
    http_summaries: tuple[HttpMetadata, ...] = ()
    tls_summaries: tuple[TlsMetadata, ...] = ()


class ExitCode(IntEnum):
    """Stable process exit codes for expected CLI outcomes."""

    SUCCESS = 0
    INVALID_CLI_INPUT = 2
    OFFLINE_INPUT_ERROR = 3
    CAPTURE_BACKEND_ERROR = 4
    PROCESSING_WARNING = 5


class ErrorCategory(str, Enum):
    INVALID_CLI_INPUT = "invalid_cli_input"
    OFFLINE_INPUT = "offline_input"
    CAPTURE_BACKEND = "capture_backend"
    PROCESSING_WARNING = "processing_warning"


_ERROR_EXIT_CODES: Mapping[ErrorCategory, ExitCode] = MappingProxyType(
    {
        ErrorCategory.INVALID_CLI_INPUT: ExitCode.INVALID_CLI_INPUT,
        ErrorCategory.OFFLINE_INPUT: ExitCode.OFFLINE_INPUT_ERROR,
        ErrorCategory.CAPTURE_BACKEND: ExitCode.CAPTURE_BACKEND_ERROR,
        ErrorCategory.PROCESSING_WARNING: ExitCode.PROCESSING_WARNING,
    }
)


@dataclass(frozen=True, slots=True)
class AnalysisError:
    category: ErrorCategory
    message: str

    @property
    def exit_code(self) -> ExitCode:
        return _ERROR_EXIT_CODES[self.category]


__all__ = [
    "AnalysisError",
    "AnalysisResult",
    "ConversationKey",
    "DnsMetadata",
    "EndpointKey",
    "ErrorCategory",
    "ExitCode",
    "HttpMetadata",
    "IPAddress",
    "PacketMetadata",
    "ProcessingStatistics",
    "ProcessingWarning",
    "Protocol",
    "ProtocolCounter",
    "TimeBucket",
    "TlsMetadata",
    "WarningCategory",
]