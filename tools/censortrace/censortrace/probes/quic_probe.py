"""QUIC / HTTP3 tester.

Answers three operational questions from a single vantage point:

  1. Is UDP/443 *reachable* at all?
       - silent timeout            -> blackhole filtering of UDP 443
       - ICMP port-unreachable     -> explicit reject (fast-fail filtering)
       - Initial received back     -> open path
  2. Does the DPI choke particular QUIC *versions*?
       We send Initials with version 1, draft-29, v2 and a GREASE version and
       compare reply/timeout rates per version — differential by construction.
  3. Does the middlebox drop or forge *Version Negotiation* handling?
       A GREASE-version Initial should make an RFC-compliant server answer VN.
       If the legit VN never arrives while v1 Initials do get replies, the DPI
       is stripping/silencing VN packets (a known NIN technique to trap clients
       into TCP fallback where SNI inspection applies).

Plus a lightweight Alt-Svc discovery step over TCP HTTPS (stdlib http.client)
to confirm the target actually serves h3 before blaming the network.

No aioquic required — we use the structurally-valid codec in ``quicwire``.
"""

from __future__ import annotations

import asyncio
import socket
import ssl
import struct
import time
from typing import Any
from urllib.parse import urlparse

from .. import tls
from ..config import ProbeConfig, QUIC_TEST_TARGETS
from ..core import CensorshipProbe, Finding, ProbeResult, Verdict, register
from ..net import udp_exchange
from ..quicwire import (
    PK_INITIAL, VERSION_DRAFT29, VERSION_GREASE, VERSION_V1, VERSION_V2,
    initial_packet, looks_like_version_negotiation, parse_long_header,
    supported_versions_from_vn,
)

VERSION_NAMES = {
    VERSION_V1: "v1",
    VERSION_DRAFT29: "draft-29",
    VERSION_V2: "v2",
    VERSION_GREASE: "grease",
}


@register
class QUICProbe(CensorshipProbe):
    name = "quic"
    description = "UDP/443 reachability, per-version Initial filtering, VN suppression, h3 check"

    async def run(self) -> ProbeResult:
        cfg = self.cfg
        findings: list[Finding] = []
        metrics: dict[str, Any] = {}

        # Resolve both the web target and well-known h3 servers concurrently.
        try:
            ips = list(cfg.target_ips) or await tls.resolve(cfg.domain, cfg.tcp_timeout)
        except Exception:
            ips = []
        domain_ip = ips[0] if ips else None

        targets: dict[str, tuple[str, int]] = {}
        if domain_ip:
            targets["target"] = (domain_ip, 443)
        for label, (ip, _host) in QUIC_TEST_TARGETS.items():
            targets[f"known_h3_{label}"] = (ip, 443)

        # ---- phase 1: concurrent per-version Initial probes --------------
        async def probe_version(host: str, port: int, version: int) -> dict[str, Any]:
            ch = tls.build_client_hello(
                cfg.domain if host == domain_ip else "cloudflare.com",
                quic_dcid=bytes([0x11] * 8),
                alpn=("h3",),
            )
            pkt, dcid = initial_packet(ch, version=version)
            ex = await udp_exchange(host, port, [pkt], timeout=cfg.quic_timeout,
                                    expect_replies=2)
            out: dict[str, Any] = {
                "sent_bytes": ex.sent_bytes,
                "replies": len(ex.responses),
                "rtt_ms": round(min(ex.rtts_ms), 1) if ex.rtts_ms else None,
                "icmp_unreachable": ex.icmp_unreachable,
                "timed_out": ex.timed_out,
                "error": ex.error,
                "reply_types": [],
                "vn_versions": [],
            }
            for data in ex.responses:
                p = parse_long_header(data)
                if p is None:
                    out["reply_types"].append("short_header_or_unknown")
                    continue
                tname = {PK_INITIAL: "Initial"}.get(p["pkt_type"], f"type{p['pkt_type']}")
                if p["version"] == 0:
                    tname = "VersionNegotiation"
                    out["vn_versions"] = [hex(v) for v in supported_versions_from_vn(data)]
                out["reply_types"].append(tname)
            return out

        tasks: dict[str, asyncio.Task] = {}
        for tname, (host, port) in targets.items():
            for ver in (VERSION_V1, VERSION_DRAFT29, VERSION_V2, VERSION_GREASE):
                key = f"{tname}/{VERSION_NAMES[ver]}"
                tasks[key] = asyncio.create_task(probe_version(host, port, ver))

        results = {k: await v for k, v in tasks.items()}
        metrics["probes"] = results

        # ---- analysis -----------------------------------------------------
        # UDP-443 blanket block? Use the *known h3* endpoints as canaries.
        canary_keys = [k for k in results if k.startswith("known_h3")]
        canary_blocked = [k for k in canary_keys
                          if results[k]["timed_out"] or results[k]["icmp_unreachable"]]
        if canary_keys and len(canary_blocked) == len(canary_keys):
            mode = ("ICMP-rejected"
                    if any(results[k]["icmp_unreachable"] for k in canary_keys)
                    else "silently dropped")
            findings.append(Finding(
                "quic.udp443_blocked", "high",
                f"All QUIC Initials to public h3 servers were {mode}: UDP/443 "
                "is filtered at the ISP edge (HTTP/3 unusable; clients fall back to TCP).",
                {"canaries": canary_blocked},
            ))
            verdict = Verdict.BLOCKED
        else:
            verdict = Verdict.PASS
            # per-version differential on the actual target
            if domain_ip:
                per_ver = {VERSION_NAMES[v]: results.get(f"target/{VERSION_NAMES[v]}")
                           for v in VERSION_NAMES}
                open_v = [n for n, r in per_ver.items() if r and r["replies"]]
                dead_v = [n for n, r in per_ver.items() if r and not r["replies"]]
                if per_ver.get("v1") and per_ver["v1"]["replies"] and \
                        any(n in dead_v for n in ("draft-29", "v2")):
                    findings.append(Finding(
                        "quic.version_selective_drop", "medium",
                        f"QUIC v1 gets replies but versions {dead_v} are dropped — "
                        "DPI is doing version-aware filtering.",
                        {"open": open_v, "dropped": dead_v},
                    ))
                grease = per_ver.get("grease")
                if grease and not grease["replies"] and per_ver.get("v1", {}).get("replies"):
                    findings.append(Finding(
                        "quic.vn_suppressed", "medium",
                        "GREASE-version Initial got no Version-Negotiation reply "
                        "while v1 Initials did — middlebox appears to suppress VN "
                        "(forces clients onto TCP where SNI DPI applies).",
                        {"grease": grease, "v1": per_ver["v1"]},
                    ))
                tgt = per_ver.get("v1")
                if tgt and (tgt["timed_out"] or tgt["icmp_unreachable"]) and canary_blocked != canary_keys:
                    findings.append(Finding(
                        "quic.target_unreachable", "low",
                        "Public h3 servers answered but this target's UDP/443 did not "
                        "(target may simply not serve QUIC — check Alt-Svc).",
                        {"v1": tgt},
                    ))

        # ---- phase 2: Alt-Svc advertisement over TCP (context) -----------
        altsvc = await self._check_altsvc(cfg)
        metrics["altsvc"] = altsvc
        if altsvc.get("found") and verdict is Verdict.BLOCKED:
            findings.append(Finding(
                "quic.altsvc_but_blocked", "info",
                "Target advertises h3 via Alt-Svc but UDP/443 is filtered — "
                "clients will stall ~1 RTT then fall back to TCP/443.",
                altsvc,
            ))

        return self.result(verdict, findings=findings, metrics=metrics,
                           raw={"note": "structurally-valid Initials; full QUIC "
                                        "crypto intentionally not implemented"})

    @staticmethod
    async def _check_altsvc(cfg: ProbeConfig) -> dict[str, Any]:
        """GET / over TLS and look at the Alt-Svc header (stdlib only)."""
        import http.client

        def worker() -> dict[str, Any]:
            try:
                ctx = ssl.create_default_context()
                conn = http.client.HTTPSConnection(cfg.domain, timeout=5, context=ctx)
                conn.request("GET", "/", headers={"Host": cfg.domain,
                                                  "User-Agent": "censortrace/2.0"})
                resp = conn.getresponse()
                av = resp.getheader("Alt-Svc", "")
                conn.close()
                return {"found": "h3=" in av, "alt_svc": av[:200]}
            except Exception as exc:
                return {"error": f"{type(exc).__name__}: {exc}"}
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, worker)
