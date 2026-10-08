"""Bounded, metadata-aware iteration over local pcap and pcapng files."""

from __future__ import annotations

import os
import stat
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from io import IOBase
from pathlib import Path
from types import TracebackType
from typing import Self, TypeAlias

from scapy.packet import Packet
from scapy.utils import PcapReader

from traffic_analyser.limits import BoundedSamples, LimitTracker, ResourceLimits
from traffic_analyser.models import ProcessingWarning, WarningCategory

PathInput: TypeAlias = str | os.PathLike[str]
_PCAP_MAGIC = {
    b"\xa1\xb2\xc3\xd4",
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
    b"\x4d\x3c\xb2\xa1",
}
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
_GZIP_MAGIC = b"\x1f\x8b"


class OfflineInputError(Exception):
    """Raised when an offline capture cannot be safely opened or read."""


@dataclass(frozen=True, slots=True)
class OfflinePacket:
    """A transient raw packet record passed to the decoder boundary."""

    packet: Packet
    timestamp: datetime
    captured_length: int
    original_length: int


Reader: TypeAlias = PcapReader


class OfflinePcapReader(Iterator[OfflinePacket]):
    """Lazily read a bounded local classic pcap or pcapng capture."""

    def __init__(self, path: PathInput, limits: ResourceLimits) -> None:
        self.path = Path(path)
        self.limits = limits
        self._reader: Reader | None = None
        self._handle: IOBase | None = None
        self._tracker = LimitTracker(limits)
        self._warnings = BoundedSamples[ProcessingWarning](limits.metadata_samples)
        self._packet_index = 0
        self._first_timestamp: float | None = None

    def __enter__(self) -> Self:
        self._open()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def __iter__(self) -> OfflinePcapReader:
        return self

    def __next__(self) -> OfflinePacket:
        if self._reader is None:
            raise RuntimeError("offline reader must be used as a context manager")

        while True:
            try:
                packet = next(self._reader)
            except StopIteration:
                self.close()
                raise
            except Exception:  # noqa: BLE001 - packet readers expose varied parse errors
                self._warning(
                    WarningCategory.MALFORMED_PACKET,
                    "a capture record could not be decoded",
                )
                continue

            try:
                record = self._record(packet)
            except Exception:  # noqa: BLE001 - malformed packet metadata is skippable
                self._warning(
                    WarningCategory.MALFORMED_PACKET,
                    "a capture record had invalid packet metadata",
                )
                continue

            if record.captured_length < record.original_length:
                self._warning(
                    WarningCategory.MALFORMED_PACKET,
                    "a capture record was truncated",
                )

            elapsed = self._elapsed(record.timestamp)
            if not self._tracker.try_accept(record.captured_length, elapsed):
                self.close()
                raise StopIteration

            self._packet_index += 1
            return record

    @property
    def warnings(self) -> tuple[ProcessingWarning, ...]:
        """Return bounded warnings collected while iterating."""
        return tuple(self._warnings.values)

    @property
    def file_size(self) -> int:
        """Return the validated input size in bytes."""
        if self._handle is None:
            raise RuntimeError("offline reader is not open")
        return os.fstat(self._handle.fileno()).st_size

    def close(self) -> None:
        reader, self._reader = self._reader, None
        self._handle = None
        if reader is not None:
            reader.close()

    def _open(self) -> None:
        if self._reader is not None:
            return
        if self.path.is_symlink():
            raise OfflineInputError("offline input must not be a symbolic link")

        descriptor: int | None = None
        try:
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(self.path, flags)
            handle = os.fdopen(descriptor, "rb")
            stat_result = os.fstat(descriptor)
        except (OSError, ValueError) as error:
            if descriptor is not None:
                os.close(descriptor)
            raise OfflineInputError("offline input is missing or unreadable") from error

        if not stat.S_ISREG(stat_result.st_mode):
            handle.close()
            raise OfflineInputError("offline input must be a regular file")
        if stat_result.st_size > self.limits.max_file_size:
            handle.close()
            raise OfflineInputError("offline input exceeds the configured file-size limit")

        magic = handle.read(4)
        handle.seek(0)
        try:
            if magic in _PCAP_MAGIC:
                reader: Reader = PcapReader(handle)  # type: ignore[arg-type]
            elif magic == _PCAPNG_MAGIC:
                reader = PcapReader(handle)  # type: ignore[arg-type]
            elif magic == _GZIP_MAGIC:
                raise OfflineInputError("compressed capture archives are not supported")
            else:
                raise OfflineInputError("offline input is not a supported pcap format")
        except OfflineInputError:
            handle.close()
            raise
        except Exception as error:
            handle.close()
            raise OfflineInputError("offline input has an invalid capture header") from error

        self._handle = handle
        self._reader = reader

    def _record(self, packet: Packet) -> OfflinePacket:
        timestamp = datetime.fromtimestamp(float(packet.time), tz=UTC)
        captured_length = len(packet)
        original_length = int(getattr(packet, "wirelen", captured_length) or captured_length)
        if captured_length < 0 or original_length < captured_length:
            raise ValueError("invalid packet lengths")
        return OfflinePacket(packet, timestamp, captured_length, original_length)

    def _elapsed(self, timestamp: datetime) -> float:
        current = timestamp.timestamp()
        if self._first_timestamp is None:
            self._first_timestamp = current
            return 0.0
        return max(0.0, current - self._first_timestamp)

    def _warning(self, category: WarningCategory, message: str) -> None:
        self._warnings.add(
            ProcessingWarning(category, message, packet_index=self._packet_index)
        )


def iter_offline_packets(
    path: PathInput, limits: ResourceLimits
) -> Iterator[OfflinePacket]:
    """Yield packets from a validated capture and close the reader afterwards."""
    with OfflinePcapReader(path, limits) as reader:
        yield from reader


__all__ = ["OfflineInputError", "OfflinePacket", "OfflinePcapReader", "iter_offline_packets"]