import ast
import re
from pathlib import Path

SOURCE_ROOT = Path(__file__).parents[1] / "src" / "traffic_analyser"


def source_files() -> tuple[Path, ...]:
    return tuple(sorted(SOURCE_ROOT.glob("*.py")))


def test_source_does_not_use_process_or_network_execution() -> None:
    forbidden_imports = {
        "subprocess",
        "socket",
        "requests",
        "urllib.request",
        "http.client",
    }
    forbidden_calls = {
        "system",
        "popen",
        "execv",
        "execve",
        "execvp",
        "execvpe",
        "Popen",
        "run",
    }

    for path in source_files():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported = {alias.name for alias in node.names}
                assert imported.isdisjoint(forbidden_imports), path
            elif isinstance(node, ast.ImportFrom):
                assert node.module not in forbidden_imports, path
            elif isinstance(node, ast.Call):
                function_name = (
                    node.func.id
                    if isinstance(node.func, ast.Name)
                    else node.func.attr
                    if isinstance(node.func, ast.Attribute)
                    else None
                )
                assert function_name not in forbidden_calls, (path, function_name)


def test_source_has_no_raw_capture_writers_or_payload_logging() -> None:
    forbidden_terms = (
        "PcapWriter",
        "PcapNgWriter",
        "wrpcap",
        "sendp",
        "payload=%",
        "payload:",
    )

    for path in source_files():
        source = path.read_text(encoding="utf-8")
        assert not any(term in source for term in forbidden_terms), path


def test_generated_plot_names_are_fixed_safe_basenames() -> None:
    from traffic_analyser.visualization import PLOT_FILENAMES

    assert all(re.fullmatch(r"[a-z0-9_]+\.png", name) for name in PLOT_FILENAMES)


def test_normalized_models_do_not_expose_raw_packet_or_payload_fields() -> None:
    from traffic_analyser.models import PacketMetadata

    field_names = set(PacketMetadata.__dataclass_fields__)
    assert not field_names.intersection({"packet", "payload", "raw", "raw_bytes"})
    annotations = repr(PacketMetadata.__annotations__)
    assert "bytes" not in annotations
    assert "Packet" not in annotations
