"""Small, transient live-capture adapter around Scapy."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Protocol

from scapy.interfaces import get_if_list
from scapy.packet import Packet
from scapy.sendrecv import sniff

InterfaceLister = Callable[[], Sequence[str]]
PacketCallback = Callable[[Packet], None]
PacketStopFilter = Callable[[Packet], bool]
Sniffer = Callable[..., object]


class CaptureError(Exception):
    """Base class for expected live-capture failures."""


class CaptureInterfaceError(CaptureError):
    """Raised when the requested interface is not available."""


class CaptureBackendError(CaptureError):
    """Raised when the native capture backend cannot be used."""


class CapturePermissionError(CaptureBackendError):
    """Raised when the process lacks permission to capture traffic."""


class CaptureSource(Protocol):
    """Internal source contract consumed by the live workflow."""

    def list_interfaces(self) -> tuple[str, ...]: ...

    def capture(
        self,
        interface: str,
        *,
        bpf_filter: str | None,
        on_packet: PacketCallback,
        stop_filter: PacketStopFilter | None = None,
        timeout: float | None = None,
    ) -> None: ...


class CaptureAdapter:
    """Validate and forward live capture requests without retaining packets."""

    def __init__(
        self,
        *,
        interface_lister: InterfaceLister = get_if_list,
        sniffer: Sniffer = sniff,
    ) -> None:
        self._interface_lister = interface_lister
        self._sniffer = sniffer

    def list_interfaces(self) -> tuple[str, ...]:
        """Return available interface names from the native capture backend."""
        try:
            interfaces = self._interface_lister()
        except Exception as error:
            raise CaptureBackendError(_backend_message()) from error

        return tuple(str(interface) for interface in interfaces if str(interface))

    def validate_interface(self, interface: str) -> None:
        """Reject an unavailable interface before starting capture."""
        if not isinstance(interface, str) or not interface.strip():
            raise CaptureInterfaceError("capture interface must be specified")
        if interface not in self.list_interfaces():
            raise CaptureInterfaceError(
                "capture interface is unavailable; use --list-interfaces to inspect available interfaces"
            )

    def capture(
        self,
        interface: str,
        *,
        bpf_filter: str | None = None,
        on_packet: PacketCallback,
        stop_filter: PacketStopFilter | None = None,
        timeout: float | None = None,
    ) -> None:
        """Capture packets transiently and pass each one to ``on_packet``.

        ``store=False`` is deliberate: Scapy must not build an in-memory packet
        list, and the adapter does not retain packets after the callback returns.
        """
        self.validate_interface(interface)
        if not callable(on_packet):
            raise TypeError("on_packet must be callable")
        if bpf_filter is not None and not isinstance(bpf_filter, str):
            raise TypeError("bpf_filter must be a string or None")
        if stop_filter is not None and not callable(stop_filter):
            raise TypeError("stop_filter must be callable or None")
        if timeout is not None and timeout <= 0:
            raise ValueError("timeout must be greater than zero")

        try:
            sniff_options: dict[str, object] = {
                "iface": interface,
                "filter": bpf_filter,
                "prn": on_packet,
                "store": False,
            }
            if stop_filter is not None:
                sniff_options["stop_filter"] = stop_filter
            if timeout is not None:
                sniff_options["timeout"] = timeout
            self._sniffer(**sniff_options)
        except Exception as error:
            if _is_permission_error(error):
                raise CapturePermissionError(_permission_message()) from error
            raise CaptureBackendError(_backend_message()) from error

    def close(self) -> None:
        """Release capture resources owned by the backend, if any."""


def _is_permission_error(error: Exception) -> bool:
    if isinstance(error, PermissionError):
        return True
    message = str(error).lower()
    return any(
        phrase in message
        for phrase in ("permission denied", "operation not permitted", "access denied")
    )


def _backend_message() -> str:
    return (
        "live capture backend is unavailable; install the platform native capture "
        "driver (libpcap on Linux/macOS or Npcap on Windows)"
    )


def _permission_message() -> str:
    return (
        "capture permission denied; grant access to the capture interface without "
        "running the whole application with unnecessary elevation"
    )


__all__ = [
    "CaptureAdapter",
    "CaptureBackendError",
    "CaptureError",
    "CaptureInterfaceError",
    "CapturePermissionError",
    "CaptureSource",
]