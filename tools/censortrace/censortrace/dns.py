"""Minimal async DNS wire codec (RFC 1035 messages over UDP/TCP).

Kept dependency-free so probes can run in restricted environments; if
`dnspython` is installed it is used for RDAP-style parsing niceties, but the
codec below is authoritative for byte-level work (we need exact control of
query IDs and TTLs to detect forged answers).
"""

from __future__ import annotations

import asyncio
import random
import socket
import struct
from dataclasses import dataclass, field
from typing import Any

TYPE_A, TYPE_AAAA, TYPE_CNAME, TYPE_HTTPS = 1, 28, 5, 65
CLASS_IN = 1


def build_query(domain: str, qtype: int = TYPE_A, tid: int | None = None) -> tuple[bytes, int]:
    tid = tid if tid is not None else random.randint(0, 0xFFFF)
    header = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    labels = domain.strip(".").split(".")
    qname = b"".join(bytes([len(l)]) + l.encode("idna") for l in labels) + b"\x00"
    return header + qname + struct.pack("!HH", qtype, CLASS_IN), tid


def _parse_name(data: bytes, offset: int) -> tuple[str, int]:
    parts: list[str] = []
    jumped, orig = False, offset
    while offset < len(data):
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:
            if not jumped:
                orig = offset + 2
                jumped = True
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            name, _ = _parse_name(data, ptr)
            parts.append(name)
            offset += 2
            break
        offset += 1
        parts.append(data[offset:offset + length].decode("ascii", "replace"))
        offset += length
    return ".".join(parts), (orig if jumped else offset)


@dataclass
class Answer:
    name: str
    rtype: int
    ttl: int
    rdata: str


@dataclass
class DnsResponse:
    tid: int
    flags: int
    answers: list[Answer] = field(default_factory=list)
    raw: bytes = b""

    @property
    def rcode(self) -> int:
        return self.flags & 0xF

    @property
    def truncated(self) -> bool:
        return bool(self.flags & 0x0200)

    def ips(self) -> list[str]:
        return [a.rdata for a in self.answers if a.rtype in (TYPE_A, TYPE_AAAA)]


def parse_response(data: bytes) -> DnsResponse:
    if len(data) < 12:
        raise ValueError("response too short")
    tid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
    resp = DnsResponse(tid=tid, flags=flags, raw=data)
    offset = 12
    for _ in range(qd):
        _, offset = _parse_name(data, offset)
        offset += 4
    for _ in range(an + ns + ar):
        if offset + 10 > len(data):
            break
        name, offset = _parse_name(data, offset)
        rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", data[offset:offset + 10])
        offset += 10
        rdata_bytes = data[offset:offset + rdlen]
        offset += rdlen
        if rtype == TYPE_A and rdlen == 4:
            rdata = socket.inet_ntoa(rdata_bytes)
        elif rtype == TYPE_AAAA and rdlen == 16:
            rdata = socket.inet_ntop(socket.AF_INET6, rdata_bytes)
        elif rtype in (TYPE_CNAME, TYPE_HTTPS):
            try:
                rdata, _ = _parse_name(data, offset - rdlen)
            except Exception:
                rdata = rdata_bytes.hex()
        else:
            rdata = rdata_bytes.hex()
        if rtype != TYPE_A or True:  # keep everything, classify later
            resp.answers.append(Answer(name, rtype, ttl, rdata))
        if offset >= len(data):
            break
    return resp


# --------------------------------------------------------------------------
# Transports
# --------------------------------------------------------------------------
class _DnsProtocol(asyncio.DatagramProtocol):
    def __init__(self, future: asyncio.Future) -> None:
        self.future = future

    def datagram_received(self, data: bytes, addr: tuple) -> None:
        if not self.future.done():
            self.future.set_result(data)

    def error_received(self, exc: Exception) -> None:
        if not self.future.done():
            self.future.set_exception(exc)


async def query_udp(server: str, domain: str, qtype: int = TYPE_A,
                    timeout: float = 3.0, port: int = 53) -> DnsResponse:
    msg, tid = build_query(domain, qtype)
    loop = asyncio.get_running_loop()
    fut: asyncio.Future = loop.create_future()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: _DnsProtocol(fut), remote_addr=(server, port)
    )
    try:
        transport.sendto(msg)
        data = await asyncio.wait_for(asyncio.shield(fut), timeout)
    finally:
        transport.close()
    resp = parse_response(data)
    if resp.tid != tid:
        # mismatched transaction id => likely injected/spoofed answer
        resp.flags |= 0x8000  # internal marker bit for probes
    return resp


async def query_tcp(server: str, domain: str, qtype: int = TYPE_A,
                    timeout: float = 3.0, port: int = 53) -> DnsResponse:
    msg, tid = build_query(domain, qtype)
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(server, port), timeout=timeout)
    try:
        writer.write(struct.pack("!H", len(msg)) + msg)
        await writer.drain()
        hdr = await asyncio.wait_for(reader.readexactly(2), timeout=timeout)
        (rlen,) = struct.unpack("!H", hdr)
        data = await asyncio.wait_for(reader.readexactly(rlen), timeout=timeout)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
    return parse_response(data)
