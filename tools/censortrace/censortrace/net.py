"""Low-level async network primitives shared by all probes.

Everything here is stdlib-only (asyncio + socket) so the tool runs on locked-down
measurement vantage points where scapy / aioquic cannot be installed.

Provides:
  * connected-UDP helper with per-datagram RTT and ICMP-port-unreachable detection
  * asyncio UDP endpoint returning (transport, protocol) with a datagram queue
  * real X25519 key pairs (pure-python RFC 7748 scalar mult) for well-formed
    ClientHello key_share extensions
  * raw-socket TCP helpers used by the RST-injection fingerprinter
"""

from __future__ import annotations

import asyncio
import socket
import struct
import time
from dataclasses import dataclass, field
from typing import Any, Callable


# --------------------------------------------------------------------------
# Connected-UDP one-shot exchange (QUIC Initials, tunnel handshakes, DoQ)
# --------------------------------------------------------------------------
@dataclass
class UdpExchange:
    sent_bytes: int = 0
    responses: list[bytes] = field(default_factory=list)
    rtts_ms: list[float] = field(default_factory=list)
    icmp_unreachable: bool = False     # recv queue error => port filtered
    error: str | None = None
    timed_out: bool = False


async def udp_exchange(
    host: str,
    port: int,
    packets: list[bytes],
    *,
    timeout: float = 3.0,
    expect_replies: int = 1,
    inter_packet_delay: float = 0.0,
    family: int = socket.AF_INET,
) -> UdpExchange:
    """Send ``packets`` from an ephemeral connected UDP socket, collect replies.

    A connected socket lets us distinguish three DPI behaviours that matter:
      * replies received            -> path open
      * silent timeout              -> UDP dropped (blackhole filtering)
      * ConnectionRefusedError      -> ICMP port-unreachable returned
    """
    ex = UdpExchange()
    loop = asyncio.get_running_loop()
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.setblocking(False)
    try:
        await asyncio.wait_for(loop.sock_connect(sock, (host, port)), timeout)
    except (asyncio.TimeoutError, OSError) as exc:
        ex.error = f"connect: {type(exc).__name__}: {exc}"
        sock.close()
        return ex

    try:
        for pkt in packets:
            if inter_packet_delay:
                await asyncio.sleep(inter_packet_delay)
            t0 = time.perf_counter()
            try:
                await loop.sock_sendall(sock, pkt)
                ex.sent_bytes += len(pkt)
            except OSError as exc:
                ex.error = f"send: {type(exc).__name__}: {exc}"
                break
            deadline = t0 + timeout
            got_any = False
            while time.perf_counter() < deadline:
                try:
                    data = await asyncio.wait_for(
                        loop.sock_recv(sock, 65535),
                        max(0.05, deadline - time.perf_counter()),
                    )
                except asyncio.TimeoutError:
                    break
                except ConnectionRefusedError:
                    ex.icmp_unreachable = True
                    break
                except OSError as exc:
                    if exc.errno in (111, 113):  # ECONNREFUSED / EHOSTUNREACH
                        ex.icmp_unreachable = True
                        break
                    ex.error = f"recv: {type(exc).__name__}: {exc}"
                    break
                if data:
                    got_any = True
                    ex.responses.append(data)
                    ex.rtts_ms.append((time.perf_counter() - t0) * 1000)
                    if len(ex.responses) >= expect_replies:
                        break
            if ex.icmp_unreachable or ex.error:
                break
        if not ex.responses and not ex.icmp_unreachable and not ex.error:
            ex.timed_out = True
    finally:
        sock.close()
    return ex


# --------------------------------------------------------------------------
# Persistent asyncio UDP endpoint (stateful QUIC probing)
# --------------------------------------------------------------------------
class QueueDatagramProtocol(asyncio.DatagramProtocol):
    """Buffers every datagram into an awaitable asyncio.Queue."""

    def __init__(self) -> None:
        self.queue: asyncio.Queue[tuple[bytes, tuple]] = asyncio.Queue()
        self.last_error: Exception | None = None

    def datagram_received(self, data: bytes, addr: tuple) -> None:
        self.queue.put_nowait((data, addr))

    def error_received(self, exc: Exception) -> None:
        self.last_error = exc
        self.queue.put_nowait((b"", ("error", exc)))


async def open_udp_endpoint(
    remote: tuple[str, int] | None = None,
    family: int = socket.AF_INET,
) -> tuple[asyncio.DatagramTransport, QueueDatagramProtocol]:
    loop = asyncio.get_running_loop()
    transport, proto = await loop.create_datagram_endpoint(
        QueueDatagramProtocol,
        remote_addr=remote,
        family=family,
    )
    return transport, proto  # type: ignore[return-value]


# --------------------------------------------------------------------------
# Pure-python X25519 (RFC 7748 §5) — used to build *real* key_share values
# --------------------------------------------------------------------------
_P = 2**255 - 19
_X25519_BASE = 9


def _x25519_cswap(swap: int, x_2: int, x_3: int) -> tuple[int, int]:
    dummy = swap & (x_2 ^ x_3)
    return x_2 ^ dummy, x_3 ^ dummy


def _x25519_ladder(u: int, k: int) -> int:
    x1, x2, z2, x3, z3 = u, 1, 0, u, 1
    for t in range(254, -1, -1):
        kt = (k >> t) & 1
        x2, x3 = _x25519_cswap(kt, x2, x3)
        z2, z3 = _x25519_cswap(kt, z2, z3)
        a, aa = (x2 + z2) % _P, (x2 - z2) % _P
        b, bb = (x3 + z3) % _P, (x3 - z3) % _P
        x3, z3 = (a * bb) % _P, (b * aa) % _P
        x2, z2 = (aa * aa) % _P, (bb * bb) % _P
        z2 = (z2 * u) % _P
        x3 = ((x3 + z3) % _P) ** 2 % _P
        z3 = ((x3 - z3) % _P) ** 2 % _P
        x2, z2 = aa, z2
        swap = kt
        x2, x3 = _x25519_cswap(swap, x2, x3)
        z2, z3 = _x25519_cswap(swap, z2, z3)
    return x2 * pow(z2, _P - 2, _P) % _P


def _decode_scalar(priv: bytes) -> int:
    k = bytearray(priv[:32])
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    return int.from_bytes(k, "little")


def decode_x25519_ucoord(pub: bytes) -> int:
    u = int.from_bytes(pub[:32], "little") & ((1 << 255) - 1)
    return u


def x25519_public(priv: bytes) -> bytes:
    """Return the 32-byte little-endian X25519 public value for ``priv``."""
    out = _x25519_ladder(_X25519_BASE, _decode_scalar(priv))
    return out.to_bytes(32, "little")


def x25519_keypair() -> tuple[bytes, bytes]:
    priv = bytearray(__import__("os").urandom(32))
    pub = x25519_public(bytes(priv))
    return bytes(priv), pub


# --------------------------------------------------------------------------
# Raw sockets (root-only; probes must degrade gracefully without them)
# --------------------------------------------------------------------------
def have_raw_socket(family: int = socket.AF_INET, proto: int = socket.IPPROTO_TCP) -> bool:
    try:
        s = socket.socket(family, socket.SOCK_RAW, proto)
        s.close()
        return True
    except OSError:
        return False


def parse_ipv4_header(data: bytes) -> dict[str, Any]:
    """Parse enough of the IPv4 header for TTL/window fingerprinting."""
    if len(data) < 20:
        return {}
    ver_ihl, _tos, total, _tid, _fl, ttl, proto, _csum = struct.unpack(
        "!BBHHHBBH", data[:10]
    )
    ihl = (ver_ihl & 0x0F) * 4
    out: dict[str, Any] = {
        "version": ver_ihl >> 4,
        "ttl": ttl,
        "protocol": proto,
        "total_len": total,
        "l4_offset": ihl,
        "src_ip": socket.inet_ntoa(data[12:16]),
        "dst_ip": socket.inet_ntoa(data[16:20]),
    }
    if proto == 6 and len(data) >= ihl + 20:
        l4 = data[ihl:]
        sport, dport, seq, ack, doff_flags, window, _c, _u = struct.unpack(
            "!HHIIHHHH", l4[:20]
        )
        out.update(
            tcp_sport=sport, tcp_dport=dport, tcp_seq=seq, tcp_ack=ack,
            tcp_flags=doff_flags & 0x1FF, tcp_window=window,
            tcp_options=l4[20:(doff_flags >> 12)],
        )
    return out


TCP_RST = 0x004
TCP_SYNACK = 0x012
TCP_SYN = 0x002
