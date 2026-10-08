from typing import Any

import pytest

from traffic_analyser.capture import (
    CaptureAdapter,
    CaptureBackendError,
    CaptureInterfaceError,
    CapturePermissionError,
)


def test_list_interfaces_uses_backend_and_returns_names() -> None:
    adapter = CaptureAdapter(interface_lister=lambda: ["eth0", "lo"])

    assert adapter.list_interfaces() == ("eth0", "lo")


def test_capture_validates_interface_and_forwards_bpf_filter() -> None:
    calls: list[dict[str, Any]] = []
    packets = [object(), object()]

    def fake_sniffer(**kwargs: Any) -> None:
        calls.append(kwargs)
        kwargs["prn"](packets[0])
        kwargs["prn"](packets[1])

    received: list[object] = []
    adapter = CaptureAdapter(
        interface_lister=lambda: ["eth0"], sniffer=fake_sniffer
    )

    adapter.capture(
        "eth0", bpf_filter="tcp or udp", on_packet=received.append  # type: ignore[arg-type]
    )

    assert received == packets
    assert calls[0]["iface"] == "eth0"
    assert calls[0]["filter"] == "tcp or udp"
    assert calls[0]["store"] is False
    assert all(packet not in adapter.__dict__.values() for packet in packets)


def test_unavailable_interface_is_rejected_before_sniff() -> None:
    sniffed = False

    def fake_sniffer(**_kwargs: Any) -> None:
        nonlocal sniffed
        sniffed = True

    adapter = CaptureAdapter(interface_lister=lambda: ["lo"], sniffer=fake_sniffer)

    with pytest.raises(CaptureInterfaceError, match="unavailable"):
        adapter.capture("eth0", on_packet=lambda _packet: None)

    assert sniffed is False


def test_backend_and_permission_failures_are_actionable() -> None:
    with pytest.raises(CaptureBackendError, match="native capture driver"):
        CaptureAdapter(
            interface_lister=lambda: (_ for _ in ()).throw(OSError())
        ).list_interfaces()

    def permission_denied(**_kwargs: Any) -> None:
        raise PermissionError("hidden platform detail")

    adapter = CaptureAdapter(interface_lister=lambda: ["eth0"], sniffer=permission_denied)
    with pytest.raises(CapturePermissionError, match="permission denied") as error:
        adapter.capture("eth0", on_packet=lambda _packet: None)

    assert "hidden platform detail" not in str(error.value)


def test_capture_does_not_invoke_subprocess(monkeypatch: pytest.MonkeyPatch) -> None:
    import subprocess

    def fail(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError("subprocess must not be invoked")

    monkeypatch.setattr(subprocess, "run", fail)
    adapter = CaptureAdapter(interface_lister=lambda: ["lo"], sniffer=lambda **_: None)

    adapter.capture("lo", on_packet=lambda _packet: None)


def test_capture_forwards_stop_filter_and_timeout() -> None:
    calls: list[dict[str, Any]] = []

    def fake_sniffer(**kwargs: Any) -> None:
        calls.append(kwargs)

    adapter = CaptureAdapter(interface_lister=lambda: ["lo"], sniffer=fake_sniffer)
    stop_filter = lambda _packet: True

    adapter.capture(
        "lo",
        on_packet=lambda _packet: None,
        stop_filter=stop_filter,
        timeout=5.0,
    )

    assert calls[0]["stop_filter"] is stop_filter
    assert calls[0]["timeout"] == 5.0