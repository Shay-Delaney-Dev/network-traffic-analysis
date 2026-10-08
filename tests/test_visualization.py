from datetime import UTC, datetime
from ipaddress import IPv4Address

import matplotlib

matplotlib.use("Agg")

from matplotlib.figure import Figure

from traffic_analyser.models import (
    AnalysisResult,
    ConversationKey,
    EndpointKey,
    PacketSizeCounter,
    ProcessingStatistics,
    Protocol,
    ProtocolCounter,
    TimeBucket,
)
from traffic_analyser.visualization import (
    PLOT_FILENAMES,
    PlotOutputError,
    packet_size_distribution_chart,
    protocol_distribution_chart,
    save_plots,
    top_endpoints_chart,
    traffic_volume_chart,
)


def populated_result() -> AnalysisResult:
    source = EndpointKey(IPv4Address("192.0.2.1"), 1234)
    destination = EndpointKey(IPv4Address("198.51.100.2"), 443)
    return AnalysisResult(
        total_packets=2,
        total_bytes=160,
        start_time=datetime(2026, 1, 1, tzinfo=UTC),
        end_time=datetime(2026, 1, 1, 0, 0, 2, tzinfo=UTC),
        time_buckets=(
            TimeBucket(
                datetime(2026, 1, 1, tzinfo=UTC),
                datetime(2026, 1, 1, 0, 0, 10, tzinfo=UTC),
                2,
                160,
            ),
        ),
        protocol_counters=(ProtocolCounter(Protocol.TCP, 2, 160),),
        top_source_endpoints=((source, 2),),
        top_destination_endpoints=((destination, 2),),
        top_conversations=((ConversationKey.from_endpoints(source, destination), 2),),
        packet_sizes=(PacketSizeCounter(80, 2),),
        processing=ProcessingStatistics(received=2, decoded=2),
    )


def test_all_chart_builders_render_populated_results_headlessly() -> None:
    figures = (
        traffic_volume_chart(populated_result()),
        protocol_distribution_chart(populated_result()),
        top_endpoints_chart(populated_result(), redact=True),
        packet_size_distribution_chart(populated_result()),
    )

    assert all(isinstance(figure, Figure) for figure in figures)
    assert all(figure.axes for figure in figures)
    for figure in figures:
        figure.clf()


def test_all_chart_builders_render_empty_results_with_messages() -> None:
    figures = (
        traffic_volume_chart(AnalysisResult()),
        protocol_distribution_chart(AnalysisResult()),
        top_endpoints_chart(AnalysisResult(), redact=True),
        packet_size_distribution_chart(AnalysisResult()),
    )

    for figure in figures:
        assert figure.axes
        assert any(axis.texts for axis in figure.axes)
        figure.clf()


def test_endpoint_labels_are_redacted_and_payloads_are_not_plotted() -> None:
    figure = top_endpoints_chart(populated_result(), redact=True)
    axis = figure.axes[0]
    rendered_text = " ".join(
        [text.get_text() for text in axis.texts]
        + [tick.get_text() for tick in axis.get_yticklabels()]
        + [tick.get_text() for tick in axis.get_xticklabels()]
        + [axis.get_title()]
    )

    assert "192.0.2.1" not in rendered_text
    assert "198.51.100.2" not in rendered_text
    assert "payload" not in rendered_text
    assert "<redacted:" in rendered_text
    figure.clf()


def test_save_plots_creates_predictable_files_without_overwriting(tmp_path) -> None:
    paths = save_plots(populated_result(), tmp_path, redact=True)

    assert tuple(path.name for path in paths) == PLOT_FILENAMES
    assert all(path.is_file() for path in paths)

    try:
        save_plots(populated_result(), tmp_path)
    except PlotOutputError as error:
        assert "refusing to overwrite" in str(error)
    else:
        raise AssertionError("existing plot output was overwritten")


def test_save_plots_rejects_missing_directory(tmp_path) -> None:
    missing = tmp_path / "missing"

    try:
        save_plots(AnalysisResult(), missing)
    except PlotOutputError as error:
        assert "existing directory" in str(error)
    else:
        raise AssertionError("missing output directory was accepted")


def test_save_plots_rejects_symbolic_link_directory(tmp_path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    link.symlink_to(target, target_is_directory=True)

    try:
        save_plots(AnalysisResult(), link)
    except PlotOutputError as error:
        assert "symbolic link" in str(error)
    else:
        raise AssertionError("symbolic-link output directory was accepted")
