# Network Traffic Analyser

`traffic-analyser` is a local, metadata-only analyser for authorised inspection
of live traffic and local classic pcap or pcapng files. It reports traffic
volume, protocol distribution, top endpoints and conversations, packet sizes,
and observable DNS, HTTP, and TLS handshake metadata.

Only inspect traffic that you are authorised to access. The tool is not an
intrusion-detection system and does not bypass access controls or monitoring.

## Installation

Requirements:

- Python 3.11 or newer
- Scapy 2.5 through the supported pre-3.0 releases
- Matplotlib 3.6 through the supported pre-4.0 releases

Create an environment and install the package with its development tools:

```text
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

The application has no network service dependency. Use `traffic-analyser
--version` to check the installed version and `traffic-analyser --help` for
the command summary.

## Usage

List interfaces without starting capture:

```text
traffic-analyser live --list-interfaces
```

Capture and analyse an authorised interface:

```text
traffic-analyser live \
	--interface eth0 \
	--filter "tcp or udp" \
	--max-duration 60 \
	--bucket-size 5 \
	--redact
```

Analyse a local capture:

```text
traffic-analyser pcap ./captures/example.pcapng \
	--max-packets 100000 \
	--max-bytes 104857600 \
	--redact \
	--save-plots ./reports
```

The `pcap` command accepts classic pcap and pcapng files. Symbolic links,
directories, compressed archives, unreadable files, unsupported formats, and
files over the configured size limit are rejected.

### Command options

Both analysis commands support:

- `--bucket-size SECONDS`: positive time-bucket size; default `10` seconds.
- `--max-packets COUNT`: maximum packets accepted; default `100000`.
- `--max-bytes BYTES`: maximum captured bytes accepted; default `104857600`
	(100 MiB).
- `--redact`: replace sensitive identifiers in reports and plot labels with
	deterministic labels.
- `--show-plots`: display the four plots after analysis.
- `--save-plots DIRECTORY`: save the four plots to an existing directory.
- `--log-level LEVEL`: diagnostic level `DEBUG`, `INFO`, `WARNING`, `ERROR`,
	or `CRITICAL`; default `WARNING`.

The `live` command additionally supports:

- `--interface NAME`: interface to capture; required unless listing interfaces.
- `--filter BPF`: optional Berkeley Packet Filter passed to the capture backend.
- `--list-interfaces`: list available interfaces and exit.
- `--max-duration SECONDS`: maximum capture duration; default `300` seconds.

The `pcap` command additionally supports:

- `PATH`: local pcap or pcapng path to analyse.
- `--max-file-size BYTES`: maximum input file size; default `1073741824`
	(1 GiB).

All numeric limits must be positive and are bounded by conservative maximums:
24 hours for duration, 1,000,000 packets, 10 GiB of captured bytes, 10 GiB of
input file size, and 1 hour for bucket size. The byte limit uses captured packet length,
not original wire length, and a packet is accepted only when
accepting it remains within every configured limit.

## Capture setup and permissions

Scapy uses the operating system's native packet-capture backend. Install the
appropriate driver before using `live`:

- Linux and macOS: a libpcap-compatible backend.
- Windows: Npcap or another supported Scapy capture backend.

Grant the minimum permission needed to access the capture interface. Prefer a
platform-specific capture group, capability, or driver configuration where
available; do not run the whole application with unnecessary elevation. A
backend or permission failure is reported with an actionable message. Live
capture is intentionally not required for offline pcap analysis.

## Privacy and data handling

The analyser processes packets in memory and passes only bounded normalized
metadata to the aggregator. It does not retain raw packet bytes or Scapy
packet objects after decoding, automatically save captures, transmit traffic,
or log payloads, credentials, cookies, tokens, or arbitrary packet contents.

Supported core protocols are Ethernet, IPv4, IPv6, TCP, UDP, ICMP, and ICMPv6.
DNS, visible HTTP headers, and TLS handshake metadata are reported only when
observable. TLS is not decrypted and private keys are never handled. Fragmented,
encrypted, truncated, malformed, or unsupported data may produce unavailable
metadata or a warning; absence of a decoded protocol is not proof that it was
absent from the capture.

### Redaction

Redaction is applied at the presentation boundary, so aggregation remains
useful while console reports and plot labels hide sensitive identifiers. With
`--redact`, IP addresses, hostnames, DNS names, HTTP host and path metadata,
TLS server names, MAC addresses when displayed, endpoints, conversations, and
the displayed input basename receive deterministic SHA-256-based labels. The
same identifier produces the same label during and across runs.

Cleartext mode may expose sensitive network information and should only be
used for authorised traffic. Redaction is not encryption and does not protect
identifiers from offline guessing of likely input values.

## Reports and plots

The normal report includes time range, packet and byte totals, processing
counts, traffic volume, protocol totals, top endpoints, conversations,
packet-size information, available protocol metadata, and warnings. Empty,
all-skipped, and no-observable-field inputs render a clear report rather than
failing.

Plots are opt-in. `--show-plots` displays them, `--save-plots DIRECTORY`
saves them, and using neither option does neither. Both options may be used
together. Saving requires an existing writable directory and refuses to
overwrite existing files. The generated names are:

```text
traffic_volume.png
protocol_distribution.png
top_endpoints.png
packet_size_distribution.png
```

Plots use a non-interactive backend when only saving is requested, which makes
headless use and automation supported.

## Exit codes

- `0`: successful analysis, including a clean stop or partial result after
	interruption.
- `2`: invalid command-line input or invalid plot destination.
- `3`: missing, unreadable, unsupported, malformed-header, symbolic-link,
	non-regular, or over-limit offline input.
- `4`: unavailable capture interface, backend, or capture permission failure.
- `5`: reserved processing-warning outcome in the error contract; individual
	packet warnings are currently reported while processing continues.

Expected failures do not print tracebacks by default. Individual malformed or
unsupported packets are counted and warned about so later packets can still be
analysed.

## Testing and development

Run the test suite and configured static checks from an activated environment:

```text
pytest
ruff check .
mypy src
```

The tests use deterministic packets and headless Matplotlib fixtures. They do
not require access to a third-party network; live capture is tested through
mocked adapters. They also check redaction, bounded limits, safe plot output,
metadata-only models, and the absence of subprocess capture tooling.

## Known limitations and future work

Capture availability and required permissions vary by operating system and
native driver. HTTP metadata is limited to visible headers, TLS metadata does
not include decrypted content, and fragmented or incomplete headers may not be
recoverable. The analyser uses bounded top-N and metadata samples, so it does
not provide an unlimited historical record. Platform-specific live-capture
integration should be verified on the target host.

Potential future work includes broader protocol metadata and additional
platform-specific capture validation after the MVP release criteria are met.

## Explicit exclusions

This MVP does not provide a web or GUI interface, uploads or network
transmission, raw-capture persistence, arbitrary payload inspection, password
or secret extraction, TLS decryption, compressed archive support, structured
JSON or CSV export, external analyzers such as tshark or Wireshark, intrusion
verdicts, alerting, or anomaly detection.
