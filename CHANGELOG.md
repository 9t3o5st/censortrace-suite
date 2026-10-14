# Changelog

All notable changes to the **CensorTrace** toolkit and the **CensorTrace Suite**
repository are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned
- Strict `mypy` typing gate in CI (ratcheted module-by-module).
- ODoH proxy-list discovery and per-relay metadata-leak scoring.
- Longitudinal "shutdown watch" mode (repeated scans + time-series export).

## [2.0.0] - 2026-10-14

CensorTrace v2 is a ground-up rewrite of the diagnostic tool around an
**asynchronous plugin architecture**. The v1 single-file script is preserved
unchanged as the frozen `legacy` entry point.

### Added
- **Async core (`censortrace/core.py`)** — `asyncio`-first `CensorshipProbe`
  base class, normalized `Verdict` vocabulary
  (`pass / blocked / throttled / poisoned / warn / degraded / error / skipped`)
  and structured `Finding` / `ProbeResult` data models with machine-readable
  indicator keys (e.g. `dns.blockpage_ip`, `tcp.rst_injection`).
- **Plugin system** — probes self-register via the `@register` decorator;
  the CLI discovers them by walking `censortrace/probes/`. Adding a new
  measurement no longer touches any central switchboard code.
- **`ScanRunner` orchestrator (`censortrace/report.py`)** — runs all selected
  probes concurrently behind a semaphore, collects results, builds the v2
  report model (schema version 2) and emits **JSON and YAML** reports plus
  Rich console output.
- **DNS probe (`probes/dns_probe.py`)** — ISP-vs-control-resolver differential
  over UDP/TCP for A/AAAA; detects known NIN blockpage sinks
  (`10.10.34.34/.35/.36`, `d0::11`), transaction-ID mismatches (off-path forged
  answers), sub-5s TTLs and NXDOMAIN injection.
- **TLS/SNI probe (`probes/tls_probe.py`)** — baseline SNI handshake, no-SNI,
  TCP-fragmented ClientHello (2-segment and half-split, optional inter-segment
  pause) and fake-SNI-first evasion arms; **TCP RST-injection fingerprinting**
  via raw-socket TTL/window deltas when privileges allow.
- **ECH probe (`probes/ech_probe.py`)** — four-arm differential measurement
  keyed on the `encrypted_client_hello` extension (current codepoint 0xFE0D and
  draft 0xFF03, decoy outer SNI), distinguishing presence-based ECH filtering
  from plain SNI-keyword blocking.
- **QUIC/HTTP3 probe (`probes/quic_probe.py` + `quicwire.py`)** — dependency-free
  QUIC long-header codec; tests UDP/443 reachability against public h3 canaries,
  per-version Initial filtering (v1 / draft-29 / v2 / GREASE),
  Version-Negotiation suppression and Alt-Svc advertisement context.
- **Encrypted-DNS probe (`probes/encdns_probe.py` + `probes/odoh_crypto.py`)** —
  side-by-side **DoT (853/TCP), DoH (GET+POST, RFC 8484), ODoH (RFC 9230) and
  DoQ (853/UDP)** availability with metadata-leak checks; real HPKE
  (RFC 9180 X25519-HKDF256-AESGCM) end-to-end ODoH round-trips when the
  optional `cryptography` extra is installed, honest degradation otherwise.
- **Tunnel-fingerprinting probe (`probes/tunnel_probe.py`)** — signature-based
  differential probing of **WireGuard initiation messages, OpenVPN
  CONTROL_V1 hard-reset packets and VLESS/Reality-style hellos**, each paired
  with an equal-size random control payload so only asymmetric DPI reactions
  are interpreted.
- **Iran/NIN heuristics (`censortrace/heuristics.py`, `config.py`)** —
  centralized, auditable indicator database: blockpage IP sets, injected-RST
  TTL-delta/window rules, resolver/endpoint inventories (Cloudflare, Google,
  Quad9, public ODoH relay pairs).
- **Typer + Rich CLI (`censortrace/cli.py`)** — commands `scan`, `probe`,
  `probes`, `legacy`; live progress bars, colour-coded verdict tables, summary
  panel, `--verbose` streaming findings, and severity-based exit codes
  (0 clean / 1 degraded / 2 interference detected).
- **Packaging** — `pyproject.toml` (+ `setup.cfg` shim) with console-script
  `censortrace`, extras `[yaml]` and `[odoh]`, Python ≥ 3.11.
- **Test suite (`tools/censortrace/tests/`)** — offline mock-socket unit tests
  covering every probe plugin, the DNS/TLS/QUIC wire codecs, the heuristics,
  the ScanRunner and the CLI (no network access required).
- **CI/CD (`.github/workflows/ci.yml`, `release.yml`)** — ruff lint, mypy
  type-check and pytest across Python 3.11 / 3.12 / 3.13; wheel/sdist build
  and GitHub Release artifacts on tag.
- **Containerization** — `Dockerfile` and `docker-compose.yml` for one-shot
  and scheduled scans.
- **Documentation** — rewritten root README and `docs/architecture.md`,
  `docs/probes-reference.md`, `docs/output-schema.md`,
  `docs/safety-notes.md`; `CONTRIBUTING.md`, `SECURITY.md`.
- **Research artifacts** — whitepaper
  *"From Filtering to Whitelisting: Measuring Iran's Internet Control Stack,
  2025–2026"* (`papers/whitepaper-2026-iran-internet-control.md` + `.tex`) and
  anonymized example scan data under `data/sample-results/`.

### Changed
- Version bumped to **2.0.0** everywhere (`pyproject.toml`, `setup.cfg`,
  `censortrace/__init__.py`, legacy script `__version__`, CLI `--version`, docs).
- Report format migrated to schema version 2 (structured `findings[]` with
  `indicator` / `severity` / `detail` / `evidence`, plus `summary.verdict_counts`).
- Requirements narrowed to runtime deps (`typer`, `rich`); dev tools moved to
  the `dev` extra.
- `censortrace probe list` renamed to `censortrace probes` (registry listing).

### Removed
- Hard runtime dependencies on `requests` and `colorama` for the v2 package
  (the frozen legacy script keeps its own imports).
- The synchronous monolithic scan loop and its interactive-only workflow.

### Breaking changes (v1 → v2)
1. Entry point: `python censortrace_cli.py --domain X` →
   `censortrace scan --domain X` (or `python -m censortrace.cli scan ...`).
   v1 invocations still work through `censortrace legacy ...`.
2. Output: free-text stdout replaced by Rich-rendered tables + JSON/YAML files;
   scripts parsing v1 stdout must migrate to `report.json` (schema 2).
3. Exit codes now encode severity (0/1/2) instead of always 0.
4. Python ≥ 3.11 required (asyncio task-group-era standard library use).
5. Flag renames: `--json` → `--output <prefix>` (+ `--yaml/--no-yaml`),
   `--tls-port` retained, timeouts now configured via `ProbeConfig`.

## [1.0.0] - 2025-03-01

### Added
- Initial CensorTrace Suite release: two research papers
  (*The Silent Walls of the Web*, *Iran's Multi-Layer Internet Censorship
  Architecture*) and the v1 single-file Python diagnostic script
  (DNS UDP/TCP/DoH/DoT, HTTP/S censorship checks, SNI probing, TCP reset
  detection, throttling measurement, traceroute/ping helpers, packet export).

[Unreleased]: https://github.com/9t3o5st/censortrace-suite/compare/v2.0.0...HEAD
[2.0.0]: https://github.com/9t3o5st/censortrace-suite/releases/tag/v2.0.0
[1.0.0]: https://github.com/9t3o5st/censortrace-suite/releases/tag/v1.0.0
