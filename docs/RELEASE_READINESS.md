# MVP Release Readiness

Status: release candidate evidence recorded on 2026-10-08.

## Verification commands

Run these commands from an activated Python 3.11+ virtual environment:

```text
pytest
ruff check .
mypy src
pip-audit --local
traffic-analyser --version
traffic-analyser --help
```

The release baseline on Python 3.12 passed with 104 tests, Ruff, mypy, and
pip-audit. `pip-audit --local` reports the local `traffic-analyser` package as
not auditable by package name; Scapy, Matplotlib, NumPy, and development
dependencies were audited from the installed environment. The console entry
point reported version `0.1.0` and displayed the authorised-use notice.

## Acceptance evidence

| # | MVP acceptance criterion | Evidence |
|---:|---|---|
| 1 | List and select a live interface | `tests/test_capture.py`, `tests/test_cli.py` |
| 2 | Optional BPF filter | `tests/test_capture.py`, `tests/test_cli.py` |
| 3 | Live duration, packet, and byte limits | `tests/test_limits.py`, `tests/test_workflow.py` |
| 4 | Classic pcap analysis | `tests/test_pcap_reader.py`, `tests/test_workflow.py` |
| 5 | Pcapng analysis | `tests/test_pcap_reader.py`, `tests/test_workflow.py` |
| 6 | Offline file, packet, and byte limits | `tests/test_pcap_reader.py`, `tests/test_limits.py` |
| 7 | Shared live/offline normalized pipeline | `tests/test_workflow.py` |
| 8 | Ethernet, IPv4/IPv6, TCP/UDP/ICMP analysis | `tests/test_decoder.py`, `tests/test_aggregator.py` |
| 9 | Bounded DNS/HTTP/TLS metadata without decryption | `tests/test_decoder.py`, `tests/test_models.py` |
| 10 | Complete console report and warnings | `tests/test_reporting.py`, `tests/test_workflow.py` |
| 11 | Four populated and empty plots | `tests/test_visualization.py` |
| 12 | Explicit plot display and saving | `tests/test_cli.py`, `tests/test_visualization.py` |
| 13 | Malformed and unsupported packet continuation | `tests/test_decoder.py`, `tests/test_pcap_reader.py`, `tests/test_workflow.py` |
| 14 | No raw payload retention, printing, transmission, or automatic saving | `tests/test_security.py`, `tests/test_models.py` |
| 15 | Deterministic console and plot redaction | `tests/test_privacy.py`, `tests/test_reporting.py`, `tests/test_visualization.py` |
| 16 | No shell commands or external packet analyzers | `tests/test_security.py` |
| 17 | Bounded capture, processing, and aggregation | `tests/test_limits.py`, `tests/test_aggregator.py` |
| 18 | Safe input paths and generated output names | `tests/test_pcap_reader.py`, `tests/test_security.py`, `tests/test_cli.py` |
| 19 | Installation, permissions, privacy, limitations, and authorised use documented | `README.md`, CLI help, `pyproject.toml` |
| 20 | Unit, integration, fixture, and security coverage | `tests/`, especially `test_workflow.py`, `test_pcap_reader.py`, and `test_security.py` |

## Cross-platform matrix

| Platform | Offline analysis | Live capture | Release status |
|---|---|---|---|
| Linux | Supported by automated tests | Requires a libpcap-compatible backend and least-privilege capture access | Verified in current environment for offline and mocked live paths |
| macOS | Supported by automated tests | Requires a libpcap-compatible backend and platform capture permission | Documentation verified; native live capture not available in this environment |
| Windows | Supported by automated tests | Requires Npcap or another supported Scapy backend and platform capture permission | Documentation verified; native live capture not available in this environment |

Live integration remains mocked so the test suite never requires access to a
third-party network or elevated privileges. Native driver behavior must be
confirmed on each target host during deployment.

## Release checklist

- [x] Package metadata and `traffic-analyser` console entry point are defined.
- [x] Python 3.11+ and constrained runtime/development dependencies are documented.
- [x] Classic pcap and pcapng workflows have representative deterministic tests.
- [x] Live capture tests use mocked sources and cover cleanup and interruption.
- [x] Headless Matplotlib rendering and safe plot output are tested.
- [x] Security tests cover subprocesses, raw capture writes, payload retention, and safe filenames.
- [x] README and CLI help include authorised-use, privacy, permission, and platform guidance.
- [x] Dependency audit completed; local-package audit limitation is recorded above.
- [ ] Native live capture verified with libpcap on Linux and macOS and Npcap on Windows.

## Assumptions and deferred decisions

- The release environment provides Python 3.11 or newer and the native capture
  backend required for live operation.
- The documented captured-length byte-limit semantics and canonical conversation
  representation remain the MVP contract.
- Native live-capture verification is deployment work because this environment
  cannot safely or portably exercise all three operating systems.
- Structured exports, compressed archives, uploads, external analyzers, and
  TLS decryption remain outside the MVP.