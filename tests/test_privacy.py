from ipaddress import IPv4Address, IPv6Address

from traffic_analyser.models import (
    ConversationKey,
    DnsMetadata,
    EndpointKey,
    HttpMetadata,
    TlsMetadata,
)
from traffic_analyser.privacy import Redactor, redact_identifier


def test_redaction_is_deterministic_and_hides_identifiers() -> None:
    value = "198.51.100.20"
    redactor = Redactor()

    first = redactor.identifier(value, kind="ip")
    second = redactor.identifier(value, kind="ip")

    assert first == second
    assert value not in first
    assert redact_identifier(value, kind="ip") == first


def test_endpoint_redaction_supports_ipv4_ipv6_and_ports() -> None:
    redactor = Redactor()
    ipv4 = EndpointKey(IPv4Address("192.0.2.1"), 443)
    ipv6 = EndpointKey(IPv6Address("2001:db8::1"), 8443)

    ipv4_label = redactor.endpoint(ipv4)
    ipv6_label = redactor.endpoint(ipv6)

    assert "192.0.2.1" not in ipv4_label
    assert "2001:db8::1" not in ipv6_label
    assert ipv4_label.endswith(":443")
    assert ipv6_label.endswith(":8443")


def test_conversation_and_mac_redaction_are_presentation_only() -> None:
    first = EndpointKey(IPv4Address("192.0.2.1"), 1234)
    second = EndpointKey(IPv4Address("198.51.100.2"), 443)
    conversation = ConversationKey.from_endpoints(first, second)
    redactor = Redactor()

    label = redactor.conversation(conversation)

    assert "192.0.2.1" not in label
    assert "198.51.100.2" not in label
    assert conversation.canonical() == "192.0.2.1:1234 <-> 198.51.100.2:443"
    assert "aa:bb:cc:dd:ee:ff" not in redactor.mac("aa:bb:cc:dd:ee:ff")


def test_protocol_metadata_redaction_preserves_non_sensitive_fields() -> None:
    redactor = Redactor()
    dns = redactor.dns(DnsMetadata("internal.example", 0, False))
    http = redactor.http(HttpMetadata("GET", "service.example", "/private", 200))
    tls = redactor.tls(TlsMetadata("TLS 1.3", "client_hello", "secure.example"))

    assert dns.query_name is not None and "internal.example" not in dns.query_name
    assert dns.response_code == 0
    assert http.method == "GET" and http.status == 200
    assert http.host is not None and "service.example" not in http.host
    assert http.path is not None and "/private" not in http.path
    assert tls.version == "TLS 1.3" and tls.handshake_type == "client_hello"
    assert tls.server_name is not None and "secure.example" not in tls.server_name


def test_disabled_redaction_returns_cleartext_values() -> None:
    redactor = Redactor(enabled=False)

    assert redactor.identifier("service.example", kind="dns") == "service.example"
    assert redactor.mac("aa:bb:cc:dd:ee:ff") == "aa:bb:cc:dd:ee:ff"