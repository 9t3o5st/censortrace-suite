"""Async orchestration: run every registered probe concurrently and emit
machine-readable (JSON / YAML) plus human-readable (Rich) reports.
"""

from __future__ import annotations

import asyncio
import json
import os
import platform
import socket
import time
from datetime import datetime, timezone
from typing import Any, Iterable

from . import __version__, config
from .config import ProbeConfig
from .core import POSITIVE_VERDICTS, CensorshipProbe, ProbeResult, Verdict, all_probes


# --------------------------------------------------------------------------
# Vantage-point metadata (who measured what, from where)
# --------------------------------------------------------------------------
def _as_info() -> dict[str, Any]:
    """Best-effort anonymised AS/country lookup via a plain HTTP echo service.

    Kept optional: probes must work fully offline, so failures are swallowed.
    """
    info: dict[str, Any] = {"hostname": socket.gethostname()}
    try:  # local resolver as a hint of the vantage point
        info["local_ip"] = next(
            (s.getsockname()[0] for s in [
                _probe_socket("8.8.8.8"), _probe_socket("2001:4860:4860::8888")
            ] if s), None
        )
    except Exception:
        pass
    return info


def _probe_socket(dest: str) -> socket.socket | None:
    family = socket.AF_INET6 if ":" in dest else socket.AF_INET
    try:
        s = socket.socket(family, socket.SOCK_DGRAM)
        s.connect((dest, 80))
        return s
    except OSError:
        return None


# --------------------------------------------------------------------------
# Orchestrator
# --------------------------------------------------------------------------
class ScanRunner:
    """Instantiate selected probe classes and run them concurrently."""

    def __init__(
        self,
        cfg: ProbeConfig,
        probe_names: Iterable[str] | None = None,
        on_probe_start=None,
        on_probe_done=None,
    ) -> None:
        self.cfg = cfg
        registry = all_probes()
        names = list(probe_names) if probe_names else sorted(registry)
        self.probes: list[CensorshipProbe] = [registry[n](cfg) for n in names if n in registry]
        self.on_probe_start = on_probe_start
        self.on_probe_done = on_probe_done

    async def run(self) -> list[ProbeResult]:
        sem = asyncio.Semaphore(max(1, self.cfg.max_concurrency))

        async def _guarded(p: CensorshipProbe) -> ProbeResult:
            async with sem:
                if self.on_probe_start:
                    self.on_probe_start(p)
                res = await p.timed_run()
                if self.on_probe_done:
                    self.on_probe_done(p, res)
                return res

        # gather == "run DNS, TLS, QUIC … simultaneously"; return_exceptions is
        # unnecessary because timed_run() already traps everything per-probe.
        return await asyncio.gather(*(_guarded(p) for p in self.probes))


# --------------------------------------------------------------------------
# Report model + writers
# --------------------------------------------------------------------------
def build_report(cfg: ProbeConfig, results: list[ProbeResult]) -> dict[str, Any]:
    positives = [r for r in results if r.verdict in POSITIVE_VERDICTS]
    return {
        "tool": "censortrace",
        "version": __version__,
        "schema": 2,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "vantage_point": {
            "platform": f"{platform.system()} {platform.release()}",
            "python": platform.python_version(),
            **_as_info(),
        },
        "target": {
            "domain": cfg.domain,
            "tls_port": cfg.tls_port,
            "control_resolvers": list(cfg.control_resolvers),
        },
        "summary": {
            "probes_run": len(results),
            "positives": len(positives),
            "verdict_counts": {
                v.value: sum(1 for r in results if r.verdict is v) for v in Verdict
            },
            "overall": "interference_detected" if positives else "no_interference_observed",
        },
        "results": [r.to_dict() for r in results],
    }


def write_reports(report: dict[str, Any], out_prefix: str,
                  formats: tuple[str, ...] = ("json", "yaml")) -> list[str]:
    os.makedirs(os.path.dirname(out_prefix) or ".", exist_ok=True)
    written: list[str] = []
    if "json" in formats:
        path = f"{out_prefix}.json"
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, ensure_ascii=False, default=str)
        written.append(path)
    if "yaml" in formats:
        path = f"{out_prefix}.yaml"
        try:
            import yaml  # PyYAML — optional at runtime
            with open(path, "w", encoding="utf-8") as fh:
                yaml.safe_dump(report, fh, sort_keys=False, allow_unicode=True)
        except ImportError:  # graceful fallback: JSON-in-YAML is valid YAML
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(report, fh, indent=2, ensure_ascii=False, default=str)
        written.append(path)
    return written


async def run_scan(
    cfg: ProbeConfig,
    probe_names: Iterable[str] | None = None,
    on_probe_start=None,
    on_probe_done=None,
) -> tuple[list[ProbeResult], dict[str, Any]]:
    t0 = time.perf_counter()
    results = await ScanRunner(cfg, probe_names, on_probe_start, on_probe_done).run()
    report = build_report(cfg, results)
    report["scan_duration_s"] = round(time.perf_counter() - t0, 3)
    return results, report
