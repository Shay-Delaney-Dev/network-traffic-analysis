"""Validation and bounded resource tracking for analysis workflows."""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Generic, TypeVar

DEFAULT_CAPTURE_DURATION = 300.0
DEFAULT_PACKET_COUNT = 100_000
DEFAULT_BYTE_COUNT = 100 * 1024 * 1024
DEFAULT_OFFLINE_FILE_SIZE = 1024 * 1024 * 1024
DEFAULT_BUCKET_SIZE = 10.0
DEFAULT_TOP_N = 10
DEFAULT_METADATA_SAMPLES = 100
DEFAULT_INSPECTED_HEADER_BYTES = 4096
DEFAULT_METADATA_STRING_LENGTH = 256

MAX_CAPTURE_DURATION = 24 * 60 * 60.0
MAX_PACKET_COUNT = 1_000_000
MAX_BYTE_COUNT = 10 * 1024 * 1024 * 1024
MAX_OFFLINE_FILE_SIZE = 10 * 1024 * 1024 * 1024
MAX_BUCKET_SIZE = 60 * 60.0
MAX_TOP_N = 1_000
MAX_METADATA_SAMPLES = 1_000
MAX_INSPECTED_HEADER_BYTES = 64 * 1024


def _validate_number(value: object, *, name: str) -> int | float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{name} must be numeric")
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError(f"{name} must be finite")
    return value


def validate_bounded(
    value: object,
    *,
    name: str,
    minimum: float,
    maximum: float,
) -> int | float:
    """Validate an inclusive numeric range for a resource option."""
    number = _validate_number(value, name=name)
    if number < minimum or number > maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return number


def validate_positive_int(value: object, *, name: str, maximum: int) -> int:
    """Validate a positive integer resource option."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")
    return int(validate_bounded(value, name=name, minimum=1, maximum=maximum))


def validate_positive_float(value: object, *, name: str, maximum: float) -> float:
    """Validate a positive finite numeric duration option."""
    number = validate_bounded(value, name=name, minimum=0.0, maximum=maximum)
    if number <= 0:
        raise ValueError(f"{name} must be greater than zero")
    return float(number)


def validate_non_negative_int(value: object, *, name: str) -> int:
    """Validate a packet or file size, allowing an empty file or packet."""
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{name} must be a non-negative integer")
    return value


def validate_file_size(file_size: object, max_file_size: int) -> int:
    """Validate an observed file size against an inclusive maximum."""
    size = validate_non_negative_int(file_size, name="file_size")
    limit = validate_positive_int(
        max_file_size, name="max_file_size", maximum=MAX_OFFLINE_FILE_SIZE
    )
    if size > limit:
        raise ValueError("file_size exceeds max_file_size")
    return size


@dataclass(frozen=True, slots=True)
class ResourceLimits:
    """Conservative, bounded defaults shared by live and offline workflows."""

    max_duration: float = DEFAULT_CAPTURE_DURATION
    max_packets: int = DEFAULT_PACKET_COUNT
    max_bytes: int = DEFAULT_BYTE_COUNT
    max_file_size: int = DEFAULT_OFFLINE_FILE_SIZE
    bucket_size: float = DEFAULT_BUCKET_SIZE
    top_n: int = DEFAULT_TOP_N
    metadata_samples: int = DEFAULT_METADATA_SAMPLES
    inspected_header_bytes: int = DEFAULT_INSPECTED_HEADER_BYTES

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "max_duration",
            validate_positive_float(
                self.max_duration,
                name="max_duration",
                maximum=MAX_CAPTURE_DURATION,
            ),
        )
        for field_name, maximum in (
            ("max_packets", MAX_PACKET_COUNT),
            ("max_bytes", MAX_BYTE_COUNT),
            ("max_file_size", MAX_OFFLINE_FILE_SIZE),
            ("top_n", MAX_TOP_N),
            ("metadata_samples", MAX_METADATA_SAMPLES),
            ("inspected_header_bytes", MAX_INSPECTED_HEADER_BYTES),
        ):
            object.__setattr__(
                self,
                field_name,
                validate_positive_int(
                    getattr(self, field_name), name=field_name, maximum=maximum
                ),
            )
        object.__setattr__(
            self,
            "bucket_size",
            validate_positive_float(
                self.bucket_size, name="bucket_size", maximum=MAX_BUCKET_SIZE
            ),
        )


class LimitTracker:
    """Track accepted packets without retaining packet objects or bytes.

    Byte budgets use captured length, not original length. A packet is accepted
    only when its count, captured bytes, and elapsed duration stay within the
    configured inclusive limits.
    """

    def __init__(self, limits: ResourceLimits) -> None:
        self.limits = limits
        self.accepted_packets = 0
        self.accepted_bytes = 0

    def try_accept(self, captured_length: object, elapsed_seconds: object) -> bool:
        """Accept a packet if all configured budgets still have capacity."""
        length = validate_non_negative_int(captured_length, name="captured_length")
        elapsed = _validate_number(elapsed_seconds, name="elapsed_seconds")
        if elapsed < 0:
            raise ValueError("elapsed_seconds must be non-negative")
        if (
            self.accepted_packets + 1 > self.limits.max_packets
            or self.accepted_bytes + length > self.limits.max_bytes
            or elapsed > self.limits.max_duration
        ):
            return False
        self.accepted_packets += 1
        self.accepted_bytes += length
        return True


Item = TypeVar("Item")


class BoundedSamples(Generic[Item]):
    """Retain at most a configured number of metadata samples."""

    def __init__(self, maximum: int) -> None:
        self.maximum = validate_positive_int(
            maximum, name="maximum", maximum=MAX_METADATA_SAMPLES
        )
        self._items: list[Item] = []

    def add(self, item: Item) -> bool:
        """Add an item while capacity remains; return whether it was retained."""
        if len(self._items) >= self.maximum:
            return False
        self._items.append(item)
        return True

    @property
    def values(self) -> tuple[Item, ...]:
        return tuple(self._items)


__all__ = [
    "DEFAULT_BUCKET_SIZE",
    "DEFAULT_BYTE_COUNT",
    "DEFAULT_CAPTURE_DURATION",
    "DEFAULT_INSPECTED_HEADER_BYTES",
    "DEFAULT_METADATA_SAMPLES",
    "DEFAULT_METADATA_STRING_LENGTH",
    "DEFAULT_OFFLINE_FILE_SIZE",
    "DEFAULT_PACKET_COUNT",
    "DEFAULT_TOP_N",
    "BoundedSamples",
    "LimitTracker",
    "ResourceLimits",
    "validate_bounded",
    "validate_file_size",
    "validate_non_negative_int",
    "validate_positive_float",
    "validate_positive_int",
]
