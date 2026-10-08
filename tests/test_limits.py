from dataclasses import fields

import pytest

from traffic_analyser.limits import (
    DEFAULT_BUCKET_SIZE,
    DEFAULT_BYTE_COUNT,
    DEFAULT_CAPTURE_DURATION,
    DEFAULT_INSPECTED_HEADER_BYTES,
    DEFAULT_METADATA_SAMPLES,
    DEFAULT_OFFLINE_FILE_SIZE,
    DEFAULT_PACKET_COUNT,
    DEFAULT_TOP_N,
    BoundedSamples,
    LimitTracker,
    ResourceLimits,
    validate_file_size,
    validate_positive_float,
    validate_positive_int,
)


def test_defaults_define_all_bounded_resource_categories() -> None:
    limits = ResourceLimits()

    assert limits.max_duration == DEFAULT_CAPTURE_DURATION
    assert limits.max_packets == DEFAULT_PACKET_COUNT
    assert limits.max_bytes == DEFAULT_BYTE_COUNT
    assert limits.max_file_size == DEFAULT_OFFLINE_FILE_SIZE
    assert limits.bucket_size == DEFAULT_BUCKET_SIZE
    assert limits.top_n == DEFAULT_TOP_N
    assert limits.metadata_samples == DEFAULT_METADATA_SAMPLES
    assert limits.inspected_header_bytes == DEFAULT_INSPECTED_HEADER_BYTES
    assert {field.name for field in fields(limits)} == {
        "max_duration",
        "max_packets",
        "max_bytes",
        "max_file_size",
        "bucket_size",
        "top_n",
        "metadata_samples",
        "inspected_header_bytes",
    }


@pytest.mark.parametrize("value", [0, -1, "10", True, float("inf")])
def test_positive_integer_validation_rejects_invalid_values(value: object) -> None:
    with pytest.raises((TypeError, ValueError)):
        validate_positive_int(value, name="max_packets", maximum=100)


@pytest.mark.parametrize("value", [0, -1, "1.5", True, float("nan")])
def test_positive_float_validation_rejects_invalid_values(value: object) -> None:
    with pytest.raises((TypeError, ValueError)):
        validate_positive_float(value, name="max_duration", maximum=100.0)


def test_validation_rejects_values_above_reasonable_bounds() -> None:
    with pytest.raises(ValueError):
        ResourceLimits(max_packets=1_000_001)
    with pytest.raises(ValueError):
        ResourceLimits(bucket_size=3600.1)


@pytest.mark.parametrize("file_size", [0, 100])
def test_file_size_limit_includes_boundary(file_size: int) -> None:
    assert validate_file_size(file_size, 100) == file_size


def test_file_size_limit_rejects_one_byte_over_boundary() -> None:
    with pytest.raises(ValueError):
        validate_file_size(101, 100)


def test_tracker_rejects_packet_before_packet_or_byte_budget_is_exceeded() -> None:
    tracker = LimitTracker(ResourceLimits(max_packets=2, max_bytes=100))

    assert tracker.try_accept(60, 0) is True
    assert tracker.try_accept(40, 1) is True
    assert tracker.try_accept(1, 2) is False
    assert tracker.accepted_packets == 2
    assert tracker.accepted_bytes == 100


def test_tracker_rejects_packet_after_duration_boundary() -> None:
    tracker = LimitTracker(ResourceLimits(max_duration=5.0))

    assert tracker.try_accept(1, 5.0) is True
    assert tracker.try_accept(1, 5.1) is False


def test_tracker_uses_captured_length_not_original_length() -> None:
    tracker = LimitTracker(ResourceLimits(max_bytes=60))

    assert tracker.try_accept(60, 0) is True
    assert tracker.accepted_bytes == 60


def test_bounded_samples_stop_retaining_items_at_capacity() -> None:
    samples = BoundedSamples[str](2)

    assert samples.add("first") is True
    assert samples.add("second") is True
    assert samples.add("third") is False
    assert samples.values == ("first", "second")
