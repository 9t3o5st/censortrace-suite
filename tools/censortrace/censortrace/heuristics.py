"""Iran/NIN-specific DPI heuristics shared by the probes.

Centralised so every module applies the *same* evidence rules and so the
thresholds can be tuned per vantage point without touching probe code.
"""

from __future__ import annotations

from typing import Any

from . import config


def blockpage_hit(ips: list[str]) -> list[str]:
    """Return the subset of ``ips`` that are known Iranian blockpage sinks."""
    return [ip for ip in ips if ip in config.IRAN_BLOCKPAGE_IPS]


def classify_dns_answers(
    answers: dict[str, Any], control_ips: set[str] | None = None
) -> dict[str, Any]:
    """Compare an ISP-resolver answer set against a clean control answer set.

    Returns a dict of booleans + evidence used to build Findings:
      poisoned_blockpage : any answer IP is a known 10.10.34.x sink
      zero_ttl           : suspiciously low TTL (< 5s) — forged cache-buster
      divergent          : answers differ from control (NXDOMAIN vs A, or IPs)
      ttl_short          : TTL below the domain's authoritative minimum
    """
    ips: list[str] = answers.get("ips", [])
    ttls: list[int] = answers.get("ttls", [])
    rcode: int = answers.get("rcode", 0)
    out: dict[str, Any] = {
        "poisoned_blockpage": False,
        "zero_ttl": False,
        "divergent": False,
        "ttl_short": False,
        "blockpage_ips": [],
    }
    hits = blockpage_hit(ips)
    if hits:
        out["poisoned_blockpage"] = True
        out["blockpage_ips"] = hits
    if ttls and min(ttls) < 5:
        out["zero_ttl"] = True
    if ttls and max(ttls) <= 60:
        out["ttl_short"] = True
    if control_ips is not None:
        if rcode == 3:                       # ISP says NXDOMAIN, control resolves
            out["divergent"] = True
        elif control_ips and not set(ips) & control_ips:
            out["divergent"] = True
    return out


def rst_injection_verdict(
    baseline_ttl: int | None,
    rst_ttl: int | None,
    rst_window: int | None,
    rst_seq_plausible: bool | None = None,
) -> dict[str, Any]:
    """Decide whether an observed RST looks like NIN DPI injection.

    Evidence model (per CensorTrace / NIN measurement literature):
      * injected RST arrives with LOWER TTL than the legit SYN/ACK path
        (middlebox is closer to us than the origin), delta >= IRAN_RST_TTL_DELTA_MAX
      * injected RST commonly carries window == 0
      * injected RST sequence often does NOT match the live byte counter
    """
    ev: dict[str, Any] = {"ttl_delta": None, "injected": False, "reasons": []}
    if baseline_ttl and rst_ttl:
        delta = baseline_ttl - rst_ttl
        ev["ttl_delta"] = delta
        if delta >= config.IRAN_RST_TTL_DELTA_MAX:
            ev["injected"] = True
            ev["reasons"].append(
                f"RST TTL {rst_ttl} is {delta} hops below baseline {baseline_ttl}"
            )
    if rst_window in config.IRAN_RST_WINDOW_SUSPECT:
        ev["injected"] = True
        ev["reasons"].append("RST window size is 0 (typical injector signature)")
    if rst_seq_plausible is False:
        ev["injected"] = True
        ev["reasons"].append("RST sequence number invalid for the live stream")
    return ev


#: Fake-SNI decoys used by the SNI-evasion probe.  The first entry mirrors what
#: tools like "sniffstream"/frodo ship; keep them benign, always-resolvable names.
FAKE_SNI_CANDIDATES = ("www.google.com", "www.microsoft.com", "example.com")
