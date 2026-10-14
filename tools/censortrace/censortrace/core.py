"""Core abstractions shared by every probe plugin.

Adding a new measurement = subclass `CensorshipProbe`, implement `async run()`,
and decorate the class with `@register`. The orchestrator discovers probes via
the registry — no central switchboard to modify.
"""

from __future__ import annotations

import abc
import enum
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Type

from .config import ProbeConfig


class Verdict(str, enum.Enum):
    """Normalized outcome vocabulary for machine-readable reports."""

    PASS = "pass"            # no interference observed
    BLOCKED = "blocked"      # definitive blocking evidence
    THROTTLED = "throttled"  # bandwidth interference
    POISONED = "poisoned"    # forged answer (DNS/RST injection)
    WARN = "warn"            # soft negative signal worth attention
    DEGRADED = "degraded"    # intermittent / partial failure
    ERROR = "error"          # probe could not complete (not a finding)
    SKIPPED = "skipped"      # prerequisites missing (e.g. no raw sockets)


#: Statuses that mean "censorship signal detected".
POSITIVE_VERDICTS = {Verdict.BLOCKED, Verdict.POISONED, Verdict.THROTTLED}


@dataclass
class Finding:
    """One atomic observation, e.g. 'ISP resolver returned 10.10.34.34'.

    ``message`` is the human-readable headline; ``detail`` is kept as an alias
    so legacy/whitepaper terminology still round-trips in reports.
    """

    indicator: str                    # machine key, e.g. "dns.blockpage_ip"
    severity: str                     # "info" | "low" | "medium" | "high"
    message: str                      # human readable headline
    evidence: dict[str, Any] = field(default_factory=dict)

    @property
    def detail(self) -> str:
        return self.message


@dataclass
class ProbeResult:
    probe: str
    target: str
    verdict: Verdict
    findings: list[Finding] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)   # rtts, ratios...
    raw: dict[str, Any] = field(default_factory=dict)       # packets/hex etc.
    duration_s: float = 0.0
    error: str | None = None

    @property
    def elapsed_ms(self) -> float:
        return self.duration_s * 1000.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "probe": self.probe,
            "target": self.target,
            "verdict": self.verdict.value,
            "duration_s": round(self.duration_s, 3),
            "error": self.error,
            "findings": [
                {
                    "indicator": f.indicator,
                    "severity": f.severity,
                    "detail": f.message,
                    "evidence": f.evidence,
                }
                for f in self.findings
            ],
            "metrics": self.metrics,
            "raw": self.raw,
        }


class CensorshipProbe(abc.ABC):
    """Base interface for all measurements.

    Subclasses must define ``name``/``description`` and implement ``run``.
    Probes must never raise for expected network failures — catch them and
    return an ``ERROR`` verdict so one bad path cannot kill the scan.
    """

    name: str = "base"
    description: str = ""
    #: Soft dependencies on other probes' results (informational ordering).
    requires: tuple[str, ...] = ()

    def __init__(self, config: ProbeConfig) -> None:
        self.config = config

    @abc.abstractmethod
    async def run(self) -> ProbeResult:  # pragma: no cover - interface
        ...

    # -- helpers ----------------------------------------------------------
    def result(self, verdict: Verdict, **kw: Any) -> ProbeResult:
        return ProbeResult(
            probe=self.name, target=self.config.domain, verdict=verdict, **kw
        )

    async def timed_run(self) -> ProbeResult:
        start = time.perf_counter()
        try:
            res = await self.run()
        except Exception as exc:  # defensive: probes should handle own errors
            res = self.result(Verdict.ERROR, error=f"{type(exc).__name__}: {exc}")
        res.duration_s = time.perf_counter() - start
        return res


# --------------------------------------------------------------------------
# Plugin registry
# --------------------------------------------------------------------------
_REGISTRY: dict[str, Type[CensorshipProbe]] = {}


def register(cls: Type[CensorshipProbe]) -> Type[CensorshipProbe]:
    """Class decorator: add a probe to the plugin registry."""
    if not issubclass(cls, CensorshipProbe):
        raise TypeError(f"{cls!r} must subclass CensorshipProbe")
    _REGISTRY[cls.name] = cls
    return cls


def all_probes() -> dict[str, Type[CensorshipProbe]]:
    return dict(_REGISTRY)


def get_probe(name: str) -> Type[CensorshipProbe]:
    return _REGISTRY[name]
