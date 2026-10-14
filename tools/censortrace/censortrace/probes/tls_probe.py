"""TLS/SNI interference + TCP-RST injection fingerprinting + SNI evasion.

Sub-checks (one probe, three techniques, all concurrent):
  * baseline ClientHello with real SNI      -> is the domain killed at SNI time?
  * ClientHello without SNI                 -> port open but SNI-keyword blocked?
  * fake-SNI first, then real SNI on a new conn ("SNI spoof / frodo" style)
  * TCP-fragmented ClientHello (split record across two segments, optional
    pause) — defeats DPI that only inspects the first segment
  * RST fingerprint: TTL/window of the reset vs the SYN/ACK baseline
    (raw socket when available; heuristic fallback otherwise)
"""

from __future__ import annotations

import asyncio
import socket
import struct
import time
from typing import Any

from .. import tls
from ..config import FAKE_SNI_CANDIDATES, ProbeConfig
from ..core import CensorshipProbe, Finding, ProbeResult, Verdict, register
from ..heuristics import rst_injection_verdict


@register
class TLSProbe(CensorshipProbe):
    name = "tls"
    description = "TLS SNI blocking, RST-injection fingerprint, fragmentation & fake-SNI evasion"

    async def run(self) -> ProbeResult:
        cfg = self.cfg
        try:
            ips = list(cfg.target_ips) or await tls.resolve(cfg.domain, cfg.tcp_timeout)
        except Exception as exc:
            return self.result(Verdict.ERROR, error=f"resolution failed: {exc}")
        if not ips:
            return self.result(Verdict.ERROR, error="no A records for target")
        ip = ips[0]

        # -- concurrent variants -----------------------------------------
        base_ch = tls.build_client_hello(cfg.domain)
        nosni_ch = tls.build_client_hello(cfg.domain, sni=None)

        variants: dict[str, asyncio.Task] = {
            "baseline_sni": asyncio.create_task(
                tls.tls_handshake_attempt(ip, cfg.tls_port, cfg.domain, base_ch,
                                         timeout=cfg.tls_timeout)),
            "no_sni": asyncio.create_task(
                tls.tls_handshake_attempt(ip, cfg.tls_port, None, nosni_ch,
                                         timeout=cfg.tls_timeout)),
            # split the ClientHello after the 5-byte record header + 20 bytes:
            # the SNI hostname lands entirely in segment #2
            "fragment_25": asyncio.create_task(
                tls.tls_handshake_attempt(ip, cfg.tls_port, cfg.domain, base_ch,
                                         timeout=cfg.tls_timeout, split_at=25,
                                         pause_between_ms=100)),
            "fragment_half": asyncio.create_task(
                tls.tls_handshake_attempt(ip, cfg.tls_port, cfg.domain, base_ch,
                                         timeout=cfg.tls_timeout,
                                         split_at=len(base_ch) // 2)),
        }

        # fake-SNI technique: complete a decoy handshake on conn A, then open
        # conn B with the real SNI — some DPI boxes only arm per-flow on the
        # first observed ClientHello of a *connection tuple*.
        async def fake_sni_seq() -> dict[str, Any]:
            outcomes: dict[str, Any] = {}
            for decoy in FAKE_SNI_CANDIDATES[:2]:
                r = await tls.tls_handshake_attempt(ip, cfg.tls_port, decoy,
                                                    timeout=cfg.tls_timeout)
                outcomes[f"decoy_{decoy}"] = r["outcome"]
                if r["outcome"] != "ok":
                    continue
                real = await tls.tls_handshake_attempt(ip, cfg.tls_port, cfg.domain,
                                                       base_ch, timeout=cfg.tls_timeout)
                outcomes["real_after_decoy"] = real["outcome"]
                outcomes["detail"] = real
                return outcomes
            outcomes["real_after_decoy"] = "no-working-decoy"
            return outcomes

        variants["fake_sni"] = asyncio.create_task(fake_sni_seq())

        results = {k: await t for k, t in variants.items()}
        findings: list[Finding] = []
        metrics: dict[str, Any] = {}

        base = results["baseline_sni"]
        metrics["baseline_outcome"] = base["outcome"]
        metrics["baseline_rtt_ms"] = round(base["elapsed_ms"], 1)

        blocked_like = {"rst", "timeout", "eof", "alert"}
        if base["outcome"] in blocked_like:
            sev = "high" if base["outcome"] == "rst" else "medium"
            findings.append(Finding(
                "tls.sni_blocked", sev,
                f"Baseline handshake with SNI={cfg.domain} ended in "
                f"'{base['outcome']}' ({base.get('error') or 'no error detail'})",
                {"ip": ip, "response_hex": base["response_hex"][:128]},
            ))

        # Evasion cross-comparison
        for key, label in (("no_sni", "without-SNI"),
                           ("fragment_25", "2-segment fragmented"),
                           ("fragment_half", "half-split fragmented")):
            r = results[key]
            metrics[f"{key}_outcome"] = r["outcome"]
            if base["outcome"] in blocked_like and r["outcome"] == "ok":
                findings.append(Finding(
                    "tls.evasion_success", "info",
                    f"DPI bypassed by {label} ClientHello while baseline was "
                    f"'{base['outcome']}' — keyword match on the first segment.",
                    {"variant": key},
                ))
        fs = results["fake_sni"]
        metrics["fake_sni"] = {k: v for k, v in fs.items() if k != "detail"}
        if base["outcome"] in blocked_like and fs.get("real_after_decoy") == "ok":
            findings.append(Finding(
                "tls.evasion_success", "info",
                "Fake-SNI-first sequence completed the real handshake although "
                "the direct attempt was blocked.",
                {"decoys_tried": list(FAKE_SNI_CANDIDATES[:2])},
            ))

        # RST fingerprinting (raw socket path if root, else best-effort)
        rst_fp = await self._rst_fingerprint(ip, base)
        metrics["rst_fingerprint"] = rst_fp
        if rst_fp.get("injected"):
            findings.append(Finding(
                "tcp.rst_injection", "high",
                "Reset packet matches NIN DPI injector signature: "
                + "; ".join(rst_fp["reasons"]),
                rst_fp,
            ))

        verdict = self._verdict(base["outcome"], findings)
        return self.result(verdict, findings=findings, metrics=metrics,
                           raw={"variants": {k: {kk: vv for kk, vv in v.items()
                                                 if kk != "response_hex"}
                                             for k, v in results.items()
                                             if isinstance(v, dict)}})

    # ------------------------------------------------------------------
    @staticmethod
    def _verdict(baseline: str, findings: list[Finding]) -> Verdict:
        if any(f.indicator == "tcp.rst_injection" for f in findings):
            return Verdict.POISONED          # forged RST == injection
        if baseline == "ok":
            return Verdict.PASS
        if baseline == "rst":
            return Verdict.BLOCKED
        if baseline in ("timeout", "eof"):
            return Verdict.BLOCKED           # silent drop
        if baseline == "alert":
            return Verdict.DEGRADED          # could be origin-side rejection
        return Verdict.ERROR

    async def _rst_fingerprint(self, ip: str, base: dict) -> dict[str, Any]:
        """Compare TTL/window of RST vs SYN/ACK using a raw socket if possible."""
        from ..net import have_raw_socket, parse_ipv4_header, TCP_RST, TCP_SYNACK

        if base["outcome"] != "rst":
            return {"observed_rst": False}
        if not have_raw_socket():
            # No root: we still know a reset arrived; report limited evidence.
            return {"observed_rst": True, "raw_socket": False,
                    "note": "run as root for TTL/window fingerprinting"}

        loop = asyncio.get_running_loop()
        captured: list[dict[str, Any]] = []
        stop = asyncio.Event()

        def reader() -> None:
            rs = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            rs.settimeout(0.5)
            try:
                while not stop.is_set():
                    try:
                        data, _ = rs.recvfrom(65535)
                    except socket.timeout:
                        continue
                    h = parse_ipv4_header(data)
                    if h.get("src_ip") == ip and h.get("tcp_flags", 0) & TCP_RST:
                        captured.append(h)
            finally:
                rs.close()

        task = loop.run_in_executor(None, reader)
        baseline_ttl: int | None = None
        try:
            # measure legit path TTL via the SYN/ACK of a fresh connection
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setblocking(False)
            try:
                await asyncio.wait_for(loop.sock_connect(s, (ip, 443)), 5)
                # getpeername won't give TTL; use a TCP_INFO-less trick:
                # send our crafted CH and read reply TTL from raw capture instead.
                writer_sock = s
            except OSError:
                writer_sock = None
            if writer_sock is not None:
                writer_sock.sendall(tls.build_client_hello(self.cfg.domain))
                await asyncio.sleep(1.5)
                writer_sock.close()
        finally:
            stop.set()
            await task

        synack_ttl = next((c["ttl"] for c in captured
                           if c.get("tcp_flags", 0) == TCP_SYNACK), None)
        rst = next((c for c in captured if c.get("tcp_flags", 0) & TCP_RST), None)
        if rst is None:
            return {"observed_rst": True, "raw_socket": True,
                    "note": "RST seen by kernel but not captured on raw socket"}
        ev = rst_injection_verdict(
            baseline_ttl=synack_ttl or 64,   # conservative default baseline
            rst_ttl=rst["ttl"],
            rst_window=rst.get("tcp_window"),
        )
        ev.update({"observed_rst": True, "raw_socket": True,
                   "rst_ttl": rst["ttl"], "rst_window": rst.get("tcp_window"),
                   "synack_ttl": synack_ttl})
        return ev
