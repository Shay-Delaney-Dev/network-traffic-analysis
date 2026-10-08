# network-traffic-analysis

## Privacy redaction

Redaction is applied at the presentation boundary, so aggregation remains
useful while console reports and plot labels can hide sensitive identifiers.
With redaction enabled, IP addresses, hostnames, DNS names, HTTP host and path
metadata, TLS server names, MAC addresses, endpoints, and conversations are
replaced with deterministic SHA-256-based labels. The same identifier produces
the same label during a run and across runs.

Cleartext mode may expose sensitive network information and should only be used
for traffic the operator is authorised to inspect. Redaction is not encryption;
it does not protect identifiers from offline guessing of likely input values.
