"""Deterministic presentation-time redaction for sensitive identifiers."""

from __future__ import annotations

import hashlib
from dataclasses import replace

from traffic_analyser.models import (
    ConversationKey,
    DnsMetadata,
    EndpointKey,
    HttpMetadata,
    TlsMetadata,
)


class Redactor:
    """Redact displayed identifiers without changing analysis state."""

    def __init__(self, enabled: bool = True, digest_size: int = 10) -> None:
        if digest_size < 4 or digest_size > 32:
            raise ValueError("digest_size must be between 4 and 32")
        self.enabled = enabled
        self.digest_size = digest_size

    def identifier(self, value: str | None, *, kind: str = "value") -> str | None:
        """Return a stable label for a sensitive value, or the clear value."""
        if value is None:
            return None
        if not self.enabled:
            return value
        digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[: self.digest_size]
        return f"<redacted:{kind}:{digest}>"

    def endpoint(self, endpoint: EndpointKey) -> str:
        """Return a privacy-safe endpoint label while retaining its port."""
        address = self.identifier(str(endpoint.address), kind="ip")
        return f"{address}:{endpoint.port}" if endpoint.port is not None else address or "<unknown>"

    def conversation(self, conversation: ConversationKey) -> str:
        """Return a privacy-safe bidirectional conversation label."""
        return f"{self.endpoint(conversation.first)} <-> {self.endpoint(conversation.second)}"

    def dns(self, metadata: DnsMetadata) -> DnsMetadata:
        return replace(metadata, query_name=self.identifier(metadata.query_name, kind="dns"))

    def http(self, metadata: HttpMetadata) -> HttpMetadata:
        return replace(
            metadata,
            host=self.identifier(metadata.host, kind="http-host"),
            path=self.identifier(metadata.path, kind="http-path"),
        )

    def tls(self, metadata: TlsMetadata) -> TlsMetadata:
        return replace(
            metadata,
            server_name=self.identifier(metadata.server_name, kind="tls-sni"),
        )

    def mac(self, value: str | None) -> str | None:
        return self.identifier(value, kind="mac")


def redact_identifier(
    value: str | None, *, kind: str = "value", enabled: bool = True
) -> str | None:
    """Redact one displayed identifier using the default deterministic policy."""
    return Redactor(enabled=enabled).identifier(value, kind=kind)


def redact_endpoint(endpoint: EndpointKey, *, enabled: bool = True) -> str:
    """Format one endpoint for a report or plot label."""
    return Redactor(enabled=enabled).endpoint(endpoint)


def redact_conversation(conversation: ConversationKey, *, enabled: bool = True) -> str:
    """Format one conversation for a report or plot label."""
    return Redactor(enabled=enabled).conversation(conversation)


__all__ = [
    "Redactor",
    "redact_conversation",
    "redact_endpoint",
    "redact_identifier",
]
