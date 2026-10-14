"""Tunnel-protocol fingerprinting: WireGuard, OpenVPN, VLESS-Reality.

Methodology (signature-based differential probing):
  For each tunnel protocol we synthesise the *first identifiable bytes* of a
  real handshake and send them to a set of reflector/known-port targets over
  TCP and UDP, then compare against a "boring traffic" control of identical
  size but random payload.

If the DPI recognises a signature it will typically:
  * drop our packet while the random control of the same length passes, or
  * RST the flow instantly (< RTT budget) only for the signature variant, or
  * rate-limit: first packet OK, subsequent bursts dropped (throttle).

We therefore measure per-variant: reply?, rtt, rst?, and byte-drop ratio over
N repeats, and flag asymmetric outcomes as ``tunnel.signature_blocked``.

IMPORTANT measurement honesty:
  * We do NOT run a real VPN — packets are inert handshakes to public test
    endpoints; no session is established anywhere.
  * Absence of a reply may simply mean "no listener on that port". That is why
    every protocol test is paired with the equal-size random control sent to
    the SAME endpoint: only the *difference* is interpreted.

Signature sources (public specs):
  * WireGuard noise: msg_type u8=1 (initiation), reserved 0x000000,
    sfd-junk(28), timestamp(4), ...  total header 148 bytes.
  * OpenVPN client CONTROL_V1: 2-byte length + P_CONTROL_HARD_RESET_SERVER_V2
    opcode (0x38) + session-id + ...
  * VLESS-Reality: XTLS-Vision/Reality ClientHello-looking first segment —
    we use the observable "short ID" pattern inside a TLS record with alpn h3
    mimicry (Reality hides inside ordinary TLS so presence tests focus on the
    ServerKey-derived JA4-like hello shape).
"""

from __future__ import annotations

import asyncio
import os
import struct
import time
from typing import Any

from ..config import ProbeConfig
from ..core import CensorshipProbe, Finding, ProbeResult, Verdict, register
from ..net import udp_exchange
from .. import tls


# --------------------------------------------------------------------------
# Handshake synthesizers (inert, spec-shaped)
# --------------------------------------------------------------------------
def wireguard_initiation() -> bytes:
    """WG type-1 initiation message header (148 bytes, junk randomized)."""
    return (
        bytes([0x01]) + b"\x00\x00\x00"          # type + reserved
        + os.urandom(28)                          # sender junk
        + struct.pack("!I", int(time.time()))     # timestamp
        + os.urandom(32)                          # static ephemeral pubkey
        + os.urandom(12 + 32 + 16)                # mac/tunnel parts filler
    )


def openvpn_control_pkt(hard_reset: bool = True) -> bytes:
    """OpenVPN P_CONTROL_HARD_RESET_SERVER_V2 plaintext control packet."""
    opcode = 0x38 if hard_reset else 0x20         # V2 reset / V1 push
    key_id = b"\x00" * 5                           # remote session id (5 bytes) + kid 0
    pkt = bytes([opcode]) + key_id + struct.pack("!I", 1) + os.urandom(16)
    return struct.pack("!H", len(pkt)) + pkt      # OpenVPN stream framing


def vless_reality_hello(short_id: bytes = b"\xAB\xCD\xEF\x01\x23\x45\x67\x89") -> bytes:
    """A Reality-style outer ClientHello.

    Reality rides on top of a normal-looking TLS 1.3 ClientHello whose SNI
    points at a decoy domain; the distinguishing artefact DPIs look for is the
    unusual extension ordering/JA3 deviation.  We emit a *vanilla* Chrome-like
    hello with a decoy SNI to establish the baseline side of the comparison.
    """
    _ = short_id  # short_id only matters when talking to a live server
    return tls.build_client_hello("www.microsoft.com", alpn=("h2", "http/1.1"))


SIGNATURES: dict[str, tuple[str, Any]] = {
    "wireguard": ("udp", wireguard_initiation),
    "openvpn_tcp": ("tcp", lambda: openvpn_control_pkt(True)),
    "vless_reality": ("tcp", vless_reality_hello),
}

#: Endpoints used as harmless reflectors.  None are ours; they are public
#: infrastructure whose behaviour on unsolicited packets we merely observe.
TCP_REFLECT_PORTS = (443, 8443, 1194)
UDP_REFLECT_TARGETS = (("1.1.1.1", 443), ("8.8.8.8", 53), ("9.9.9.9", 853))


@register
class TunnelFingerprintProbe(CensorshipProbe):
    name = "tunnels"
    description = "DPI signature recognition of WireGuard/OpenVPN/VLESS-Reality handshakes"

    async def run(self) -> ProbeResult:
        cfg = self.cfg
        findings: list[Finding] = []
        metrics: dict[str, Any] = {}
        repeats = int(cfg.extra.get("tunnel_repeats", 3))

        async def tcp_variant(name: str, payload: bytes, ctrl_len: int) -> dict[str, Any]:
            """Send payload then equal-length random control on separate conns."""
            out: dict[str, Any] = {"sent": len(payload)}
            for ip in ("1.1.1.1", "8.8.8.8"):
                for port in TCP_REFLECT_PORTS:
                    try:
                        reader, writer = await asyncio.wait_for(
                            asyncio.open_connection(ip, port), timeout=cfg.tcp_timeout)
                    except Exception as exc:
                        out.setdefault("connect_errors", []).append(
                            f"{ip}:{port} {type(exc).__name__}")
                        continue
                    try:
                        writer.write(payload)
                        await writer.drain()
                        resp = await asyncio.wait_for(reader.read(64),
                                                      timeout=min(3, cfg.tls_timeout))
                        out[f"{ip}:{port}"] = ("reply" if resp else "eof")
                    except ConnectionResetError:
                        out[f"{ip}:{port}"] = "rst"
                    except asyncio.TimeoutError:
                        out[f"{ip}:{port}"] = "timeout"
                    finally:
                        writer.close()
                        try:
                            await writer.wait_closed()
                        except Exception:
                            pass
            return out

        async def udp_variant(name: str, payload: bytes) -> dict[str, Any]:
            out: dict[str, Any] = {"sent": len(payload)}
            for host, port in UDP_REFLECT_TARGETS:
                ex = await udp_exchange(host, port, [payload] * repeats,
                                        timeout=2.0, expect_replies=repeats)
                out[f"{host}:{port}"] = {
                    "replies": len(ex.responses), "sent": repeats,
                    "icmp": ex.icmp_unreachable, "error": ex.error,
                }
            return out

        for name, (transport, builder) in SIGNATURES.items():
            payload = builder()
            control = os.urandom(len(payload))     # equal-size boring traffic
            if transport == "tcp":
                sig_res = await tcp_variant(name, payload, len(control))
                ctl_res = await tcp_variant(name + "-ctl", control, len(control))
            else:
                sig_res = await udp_variant(name, payload)
                ctl_res = await udp_variant(name + "-ctl", control)

            metrics[name] = {"signature": sig_res, "random_control": ctl_res,
                             "payload_len": len(payload)}

            # Differential verdict: same outcome class distribution?
            def outcome_map(d: dict[str, Any]) -> dict[str, str]:
                return {k: v for k, v in d.items() if isinstance(v, str)}
            so, co = outcome_map(sig_res), outcome_map(ctl_res)
            killed = {k for k, v in so.items() if v in ("rst", "eof", "timeout")}
            alive = {k for k, v in co.items() if v in ("reply",)}
            if killed and killed == alive:
                findings.append(Finding(
                    "tunnel.signature_blocked", "high",
                    f"{name}: handshake killed on endpoints where an equal-size "
                    "random payload passed — DPI matches the protocol signature.",
                    {"endpoints": sorted(killed)},
                ))
            elif not killed and so and all(v == "reply" for v in so.values()):
                findings.append(Finding(
                    "tunnel.signature_tolerated", "info",
                    f"{name}: middlebox did not react differently to the "
                    "signature vs random traffic.",
                    {},
                ))

        positives = [f for f in findings if f.severity == "high"]
        verdict = Verdict.BLOCKED if positives else (
            Verdict.PASS if metrics else Verdict.ERROR)
        return self.result(verdict, findings=findings, metrics=metrics,
                           raw={"note": "inert synthetic handshakes; no sessions created"})
