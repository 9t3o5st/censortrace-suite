"""Offline mock network layer shared by the CensorTrace v2 test-suite.

Every probe in ``censortrace.probes`` performs I/O through a small number of
choke points:

  * ``asyncio.open_connection``       (TLS/SNI arms, DoT, tunnel-TCP)
  * ``loop.create_datagram_endpoint`` (DNS UDP)
  * ``loop.sock_connect/sendall/recv``(net.udp_exchange: QUIC, DoQ, tunnel-UDP)
  * ``http.client.HTTPSConnection``   (DoH GET/POST, Alt-Svc check)
  * ``getaddrinfo``                   (tls.resolve / system resolution)

Tests describe a *network scenario* (which endpoints are open, what each
resolver answers, whether DPI kills certain traffic) and these mocks emulate
the observable behaviour — injected RSTs (ConnectionResetError), silent drops
(empty read / hang), ICMP port-unreachable (ConnectionRefusedError) and forged
DNS answers. No real sockets are created while the patch is installed.
"""

from __future__ import annotations

import asyncio
import socket
import struct
from dataclasses import dataclass, field
from typing import Any, Callable

# ---------------------------------------------------------------------------
# Scenario description
# ---------------------------------------------------------------------------


@dataclass
class MockScenario:
    """Declarative description of a filtered network for tests."""

    #: TCP endpoint behaviour: key "ip:port" (or "*:port") -> outcome.
    #: outcomes: "open" | "rst" | "refused" | "drop-empty" | "hang"
    tcp: dict[str, str] = field(default_factory=dict)
    #: bytes returned by reader.read() on an open connection
    tcp_reply: bytes = b"\x16\x03\x03\x00\x10" + b"\x00" * 16
    #: UDP endpoint behaviour: key "ip:port" -> "reply" | "timeout" | "refused"
    udp: dict[str, str] = field(default_factory=dict)
    #: reply bytes for udp endpoints marked "reply"; may be callable(pkt)->bytes|None
    udp_reply: Any = b"\xc3\x00\x00\x00\x00\x01"
    #: DNS resolvers: ip -> callable(domain, qtype, tid) -> response bytes | None
    #:   None => resolver silently drops the query (timeout).
    dns: dict[str, Callable[[str, int, int], bytes | None]] = field(default_factory=dict)
    #: DoH/HTTPS routes: substring of full URL -> spec dict
    #:   {"status":int,"body":bytes|callable,"content_type":str,"error":str,"alt_svc":str}
    https: dict[str, dict[str, Any]] = field(default_factory=dict)
    #: getaddrinfo overrides: domain -> [ipv4]; default: TEST-NET-3 address
    addresses: dict[str, list[str]] = field(default_factory=dict)
    default_addr: str = "203.0.113.10"

    def tcp_outcome(self, host: str, port: int) -> str:
        return self.tcp.get(f"{host}:{port}", self.tcp.get(f"*:{port}", "open"))

    def udp_outcome(self, host: str, port: int) -> str:
        return self.udp.get(f"{host}:{port}", self.udp.get("*", "reply"))


# ---------------------------------------------------------------------------
# Fake stream reader/writer pair (asyncio.open_connection stand-in)
# ---------------------------------------------------------------------------


class FakeStreamReader:
    def __init__(self, scenario: MockScenario, mode: str) -> None:
        self._scenario = scenario
        self._mode = mode          # "normal" | "hang"
        self._fed = False
        self._buffer = bytearray()

    async def read(self, n: int = -1) -> bytes:
        if self._mode == "hang":
            await asyncio.sleep(3600)  # caller-side wait_for fires first
            return b""
        if not self._fed:
            self._fed = True
            if self._mode == "normal":
                data = self._scenario.tcp_reply
                self._buffer += data if n is None or n < 0 or n <= 0 else data[:n]
        out = bytes(self._buffer)
        self._buffer.clear()
        return out

    async def readexactly(self, n: int) -> bytes:
        data = await self.read(n)
        if len(data) < n:
            raise asyncio.IncompleteReadError(data, n)
        return data

    def at_eof(self) -> bool:
        return self._fed and not self._buffer


class _FakeTransport:
    def __init__(self) -> None:
        self.bytes_sent = 0

    def get_extra_info(self, name: str, default: Any = None) -> Any:
        return default


class FakeStreamWriter:
    def __init__(self, reader: FakeStreamReader) -> None:
        self._reader = reader
        self.transport = _FakeTransport()

    async def drain(self) -> None:
        return None

    def write(self, data: bytes) -> None:
        self.transport.bytes_sent += len(data)

    def close(self) -> None:
        pass

    async def wait_closed(self) -> None:
        pass


# ---------------------------------------------------------------------------
# Fake datagram transport (loop.create_datagram_endpoint stand-in)
# ---------------------------------------------------------------------------


class FakeDatagramTransport:
    def __init__(self, scenario: MockScenario, host: str, port: int,
                 loop: asyncio.AbstractEventLoop) -> None:
        self.scenario = scenario
        self.host = host
        self.port = port
        self.loop = loop
        self.protocol: Any = None
        self.closed = False
        self.sent: list[bytes] = []

    def sendto(self, data: bytes, addr: Any = None) -> None:
        self.sent.append(data)
        # DNS-style resolver hook takes precedence for port 53
        responder = self.scenario.dns.get(self.host)
        reply: bytes | None = None
        if responder is not None:
            domain, qtype, tid = parse_dns_query(data)
            reply = responder(domain, qtype, tid)
        elif self.scenario.udp_outcome(self.host, self.port) == "reply":
            r = self.scenario.udp_reply
            reply = r(data) if callable(r) else r
        # "timeout" => reply stays None and nothing is delivered

        if reply:
            proto = self.protocol

            async def deliver() -> None:
                if not self.closed and proto is not None:
                    proto.datagram_received(reply, (self.host, self.port))

            self.loop.call_soon(lambda: asyncio.ensure_future(deliver()))
        else:
            outcome = self.scenario.udp_outcome(self.host, self.port)
            if outcome == "refused" and self.protocol is not None:
                exc = ConnectionRefusedError(111, "Connection refused")
                fut = getattr(self.protocol, "future", None)
                if isinstance(fut, asyncio.Future) and not fut.done():
                    fut.set_exception(exc)

    def close(self) -> None:
        self.closed = True


# ---------------------------------------------------------------------------
# Minimal DNS query parser (for scenario responders)
# ---------------------------------------------------------------------------


def parse_dns_query(msg: bytes) -> tuple[str, int, int]:
    tid = struct.unpack("!H", msg[:2])[0]
    i = 12
    labels: list[str] = []
    while i < len(msg):
        ln = msg[i]
        if ln == 0:
            i += 1
            break
        labels.append(msg[i + 1:i + 1 + ln].decode("ascii", "replace"))
        i += 1 + ln
    qtype = struct.unpack("!H", msg[i:i + 2])[0] if i + 2 <= len(msg) else 1
    return ".".join(labels), qtype, tid


# ---------------------------------------------------------------------------
# Fake HTTPSConnection (DoH + Alt-Svc)
# ---------------------------------------------------------------------------


class FakeHTTPSResponse:
    def __init__(self, status: int, body: bytes, headers: dict[str, str]) -> None:
        self.status = status
        self._body = body
        self._headers = {k.lower(): v for k, v in headers.items()}

    def read(self) -> bytes:
        return self._body

    def getheader(self, name: str, default: str | None = None) -> str | None:
        return self._headers.get(name.lower(), default)


class FakeHTTPSConnection:
    scenario: MockScenario  # injected by NetworkPatch

    def __init__(self, host: str, port: int | None = None,
                 timeout: float | None = None, context: Any = None) -> None:
        self.host = host
        self.port = port or 443

    def request(self, method: str, path: str, body: bytes | None = None,
                headers: dict[str, str] | None = None) -> None:
        full = f"https://{self.host}{path}"
        spec = None
        for needle, s in self.scenario.https.items():
            if needle in full:
                spec = s
                break
        if spec is None:
            raise ConnectionResetError(104, f"mock: no route for {full}")
        self._spec = spec
        self._method = method
        self._path = path

    def getresponse(self) -> FakeHTTPSResponse:
        spec = self._spec
        if spec.get("error"):
            raise ConnectionResetError(104, str(spec["error"]))
        body = spec.get("body", b"")
        if callable(body):
            body = body(self._method, self._path)
        headers = {"Content-Type": spec.get("content_type", "application/dns-message")}
        if "alt_svc" in spec:
            headers["Alt-Svc"] = spec["alt_svc"]
        return FakeHTTPSResponse(spec.get("status", 200), body, headers)

    def close(self) -> None:
        pass


# ---------------------------------------------------------------------------
# The patch itself
# ---------------------------------------------------------------------------


class NetworkPatch:
    """Context manager installing all offline mocks for one scenario.

    Must be used inside a running event loop (async tests)::

        with NetworkPatch(scenario) as net:
            result = await probe.run()
    """

    def __init__(self, scenario: MockScenario) -> None:
        self.scenario = scenario
        self.connections: list[tuple[str, int]] = []
        self._saved: dict[str, Any] = {}

    # -- coroutine targets -------------------------------------------------
    async def _open_connection(self, host: str, port: int, **kw: Any):
        self.connections.append((host, port))
        outcome = self.scenario.tcp_outcome(host, port)
        if outcome == "rst":
            raise ConnectionResetError(104, "Connection reset by peer")
        if outcome == "refused":
            raise ConnectionRefusedError(111, "Connection refused")
        mode = "hang" if outcome == "hang" else "normal"
        reader = FakeStreamReader(self.scenario, mode)
        writer = FakeStreamWriter(reader)
        if outcome == "drop-empty":
            reader._scenario = MockScenario(tcp_reply=b"")  # empty reads
        return reader, writer

    async def _getaddrinfo(self, host, port, family=0, type=0, proto=0, flags=0):
        ips = self.scenario.addresses.get(str(host), [self.scenario.default_addr])
        fam = socket.AF_INET6 if (ips and ":" in ips[0]) else socket.AF_INET
        return [(fam, socket.SOCK_STREAM, 0, "", (ip, port or 0)) for ip in ips]

    def _create_datagram_endpoint(self, protocol_factory, remote_addr=None, **kw):
        loop = asyncio.get_running_loop()
        host, port = (remote_addr or ("203.0.113.99", 0))[:2]
        transport = FakeDatagramTransport(self.scenario, str(host), int(port), loop)
        proto = protocol_factory()
        transport.protocol = proto
        return transport, proto

    async def _sock_connect(self, sock, addr):
        host, port = addr[:2]
        if self.scenario.udp_outcome(host, port) == "refused":
            raise ConnectionRefusedError(111, "Connection refused")
        setattr(sock, "_ct_peer", (host, port))

    async def _sock_sendall(self, sock, data):
        setattr(sock, "_ct_last", data)

    async def _sock_recv(self, sock, n):
        host, port = getattr(sock, "_ct_peer", ("203.0.113.99", 443))
        outcome = self.scenario.udp_outcome(host, port)
        if outcome == "timeout":
            await asyncio.sleep(3600)
        if outcome == "refused":
            raise ConnectionRefusedError(111, "Connection refused")
        r = self.scenario.udp_reply
        pkt = getattr(sock, "_ct_last", b"")
        return (r(pkt) if callable(r) else r) or b""

    # -- install/uninstall --------------------------------------------------
    def __enter__(self) -> "NetworkPatch":
        import http.client

        loop = asyncio.get_running_loop()
        self._saved = {
            "open_connection": asyncio.open_connection,
            "getaddrinfo": loop.getaddrinfo,
            "create_dgram": loop.create_datagram_endpoint,
            "sock_connect": loop.sock_connect,
            "sock_sendall": loop.sock_sendall,
            "sock_recv": loop.sock_recv,
            "https_conn": http.client.HTTPSConnection,
        }
        asyncio.open_connection = self._open_connection            # type: ignore[assignment]
        loop.getaddrinfo = self._getaddrinfo                        # type: ignore[method-assign]
        loop.create_datagram_endpoint = self._create_datagram_endpoint  # type: ignore[method-assign]
        loop.sock_connect = self._sock_connect                      # type: ignore[method-assign]
        loop.sock_sendall = self._sock_sendall                      # type: ignore[method-assign]
        loop.sock_recv = self._sock_recv                            # type: ignore[method-assign]
        FakeHTTPSConnection.scenario = self.scenario
        http.client.HTTPSConnection = FakeHTTPSConnection           # type: ignore[misc]
        return self

    def __exit__(self, *exc: Any) -> None:
        import http.client

        loop = asyncio.get_running_loop()
        asyncio.open_connection = self._saved["open_connection"]      # type: ignore[assignment]
        loop.getaddrinfo = self._saved["getaddrinfo"]                 # type: ignore[method-assign]
        loop.create_datagram_endpoint = self._saved["create_dgram"]   # type: ignore[method-assign]
        loop.sock_connect = self._saved["sock_connect"]               # type: ignore[method-assign]
        loop.sock_sendall = self._saved["sock_sendall"]               # type: ignore[method-assign]
        loop.sock_recv = self._saved["sock_recv"]                     # type: ignore[method-assign]
        http.client.HTTPSConnection = self._saved["https_conn"]       # type: ignore[misc]


# ---------------------------------------------------------------------------
# Wire-format builders used by scenarios
# ---------------------------------------------------------------------------


def dns_a_answer(domain: str, ips: list[str], ttl: int = 300, tid: int | None = None,
                 echo_tid: int | None = "same") -> bytes:
    """Craft a DNS response carrying A records for ``domain``.

    ``echo_tid``: None/"same" echoes the query tid; an int forges a different
    one (off-path injection signature).
    """
    labels = domain.strip(".").split(".")
    qname = b"".join(bytes([len(l)]) + l.encode() for l in labels) + b"\x00"
    assert tid is not None, "dns_a_answer requires the query tid"
    answer_tid = tid if echo_tid in (None, "same") else int(echo_tid)
    header = struct.pack("!HHHHHH", answer_tid, 0x8180, 1, len(ips), 0, 0)
    question = qname + struct.pack("!HH", 1, 1)
    answers = b""
    for ip in ips:
        answers += (b"\xc0\x0c" + struct.pack("!HIH", 1, 1, ttl)
                    + struct.pack("!H", 4) + socket.inet_aton(ip))
    return header + question + answers


def dns_nxdomain(domain: str, tid: int) -> bytes:
    labels = domain.strip(".").split(".")
    qname = b"".join(bytes([len(l)]) + l.encode() for l in labels) + b"\x00"
    return struct.pack("!HHHHHH", tid, 0x8183, 1, 0, 0, 0) + qname + struct.pack("!HH", 1, 1)


def quic_vn_packet(dcid: bytes, scid: bytes, versions: list[int]) -> bytes:
    """Version Negotiation long-header packet (RFC 9000 §6.0)."""
    first = 0xC0 | (len(scid) - 1) if len(scid) <= 16 else 0xC0
    pkt = bytes([first]) + struct.pack("!I", 0) + dcid + scid
    for v in versions:
        pkt += struct.pack("!I", v)
    return pkt + b"\x00" * (1200 - len(pkt))


def quic_initial_reply(vn_versions: list[int] | None = None) -> bytes:
    """A dummy server reply: either a v1 Initial or a VN packet."""
    if vn_versions is not None:
        return quic_vn_packet(b"\x11" * 8, b"\x22" * 8, vn_versions)
    dcid, scid = b"\x11" * 8, b"\x22" * 8
    hdr = bytes([0xC0]) + struct.pack("!I", 0x00000001) + bytes([8]) + dcid \
        + bytes([8]) + scid
    token = b"\x00"
    rest = b"\x00" + b"\x40\x00\xff" + b"\x06" + b"\x00" * 16
    return (hdr + token + rest).ljust(1200, b"\x00")


def serverhello_record() -> bytes:
    return b"\x16\x03\x03\x00\x10" + b"\x00" * 16


def tls_alert_record(desc: int = 0x28) -> bytes:
    return b"\x15\x03\x03\x00\x02\x02" + bytes([desc])
