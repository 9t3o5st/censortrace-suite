"""Hand-rolled TLS ClientHello builder + async TCP helpers.

Why hand-rolled: `ssl` cannot emit arbitrary extensions (ECH), cannot split a
ClientHello across TCP segments, and cannot set custom record/extension bytes.
Every DPI-evasion probe needs byte-level control of the handshake.

This module is intentionally dependency-free (stdlib only).
"""

from __future__ import annotations

import asyncio
import os
import random
import socket
import ssl
import struct
import time
from typing import Any

# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------
EXT_SERVER_NAME = 0x0000
EXT_SUPPORTED_GROUPS = 0x000A
EXT_EC_POINT_FORMATS = 0x000B
EXT_SIGNATURE_ALGORITHMS = 0x000D
EXT_APPLICATION_LAYER_PROTOCOL = 0x0010
EXT_KEY_SHARE = 0x0028
EXT_SUPPORTED_VERSIONS = 0x002A
EXT_PSK_KEY_EXCHANGE_MODES = 0x002B
EXT_RECORD_SIZE_LIMIT = 0x002C  # fragmentation helper (RFC 8449)
EXT_ECH = 0xFE0D                # encrypted_client_hello (inner content type 0)
EXT_ECH_OLD = 0xFF03            # pre-standard draft codepoint some stacks use

TLS12_VERSION = 0x0303
TLS13_DRAFT_RR = 0x7A1A         # legacy supported_versions value Chrome uses

X25519_GROUP = 0x001D

CONTENT_TYPE_HANDSHAKE = 0x16
HS_CLIENT_HELLO = 0x01


# --------------------------------------------------------------------------
# ClientHello construction
# --------------------------------------------------------------------------
def _ext(code: int, body: bytes) -> bytes:
    return struct.pack("!HH", code, len(body)) + body


def sni_extension(hostname: str) -> bytes:
    name = hostname.encode("ascii")
    entry = struct.pack("!BH", 0x00, len(name)) + name  # host_name type + len
    lst = struct.pack("!H", len(entry)) + entry
    return _ext(EXT_SERVER_NAME, lst)


def supported_versions_extension(versions: tuple[int, ...]) -> bytes:
    body = bytes([len(versions) * 2]) + b"".join(struct.pack("!H", v) for v in versions)
    return _ext(EXT_SUPPORTED_VERSIONS, body)


def key_share_extension(x25519_pub: bytes | None = None) -> bytes:
    if x25519_pub is None:
        # Generate an ephemeral X25519 private/public pair with the stdlib-only
        # trick of using OpenSSL via ssl? Not exposed — fall back to random
        # bytes: DPI probes never complete crypto anyway, middleboxes parse
        # structure only. For real-handshake variants pass a genuine key.
        x25519_pub = os.urandom(32)
    entry = struct.pack("!HH", X25519_GROUP, len(x25519_pub)) + x25519_pub
    lst = struct.pack("!H", len(entry)) + entry
    return _ext(EXT_KEY_SHARE, lst)


def signature_algorithms_extension() -> bytes:
    schemes = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]
    body = struct.pack("!H", len(schemes) * 2) + b"".join(
        struct.pack("!H", s) for s in schemes
    )
    return _ext(EXT_SIGNATURE_ALGORITHMS, body)


def ech_extension(payload: bytes | None = None, old_codepoint: bool = False) -> bytes:
    """encrypted_client_hello extension.

    ``payload`` should be an ECHClientHello (outer) structure; when probing
    purely for *presence-based* DPI rules, any well-formed-looking body works
    because the middlebox only pattern-matches extension type 0xFE0D/0xFF03.
    """
    if payload is None:
        # syntactically plausible: type=outer(1), config_id, ipv6info-len, enc, padding
        payload = bytes([0x01, 0x2A, 0x00]) + os.urandom(48)
    code = EXT_ECH_OLD if old_codepoint else EXT_ECH
    return _ext(code, payload)


def record_size_limit_extension(n: int = 64) -> bytes:
    return _ext(EXT_RECORD_SIZE_LIMIT, struct.pack("!H", n))


def build_client_hello(
    hostname: str,
    *,
    sni: str | None = "auto",          # override / None to omit SNI entirely
    with_ech: bool = False,
    ech_old_codepoint: bool = False,
    ech_payload: bytes | None = None,
    record_size_limit: int | None = None,
    random_bytes: bytes | None = None,
    alpn: tuple[str, ...] | None = None,
    extra_extensions: tuple[tuple[int, bytes], ...] = (),
    quic_dcid: bytes | None = None,
) -> bytes:
    """Serialize a TLS 1.3-style ClientHello (legacy_version=1.2).

    ``quic_dcid`` adds the ``quic_transport_parameters`` extension (0x0039) so
    the same builder serves both TCP-TLS DPI probes and QUIC Initial packets.
    """
    if sni == "auto":
        sni = hostname

    ciphers = [
        0x1301,  # TLS_AES_128_GCM_SHA256
        0x1303,  # TLS_AES_256_GCM_SHA384
        0x1302,  # TLS_CHACHA20_POLY1305_SHA256
        0xC02C, 0xC02B, 0x003C, 0x003D,  # TLS 1.2 fallbacks
    ]
    cipher_body = struct.pack("!H", len(ciphers) * 2) + b"".join(
        struct.pack("!H", c) for c in ciphers
    )

    compression = bytes([0x01, 0x00])  # one method: NULL

    groups = struct.pack("!H", 4) + struct.pack("!H", 2) + struct.pack("!H", X25519_GROUP)
    point_fmts = bytes([0x01, 0x00])

    exts = bytearray()
    if sni is not None:
        exts += sni_extension(sni)
    if alpn:
        body = b"".join(bytes([len(a)]) + a.encode("ascii") for a in alpn)
        exts += _ext(EXT_APPLICATION_LAYER_PROTOCOL, struct.pack("!H", len(body)) + body)
    exts += _ext(EXT_SUPPORTED_GROUPS, groups)
    exts += _ext(EXT_EC_POINT_FORMATS, point_fmts)
    exts += signature_algorithms_extension()
    exts += supported_versions_extension((TLS12_VERSION, TLS13_DRAFT_RR, 0x0304))
    exts += key_share_extension()
    exts += _ext(EXT_PSK_KEY_EXCHANGE_MODES, bytes([0x02, 0x00, 0x01]))
    if record_size_limit:
        exts += record_size_limit_extension(record_size_limit)
    for code, body in extra_extensions:
        exts += _ext(code, body)
    if quic_dcid is not None:
        from .quicwire import quic_client_hello_extension
        code, body = quic_client_hello_extension(quic_dcid)
        exts += _ext(code, body)
    if with_ech:
        exts += ech_extension(ech_payload, old_codepoint=ech_old_codepoint)

    hello_extensions = struct.pack("!H", len(exts)) + bytes(exts)

    client_hello = (
        struct.pack("!H", TLS12_VERSION)
        + (random_bytes or os.urandom(32))
        + bytes([0x00])                      # legacy session_id length
        + cipher_body
        + compression
        + hello_extensions
    )

    handshake = (
        bytes([HS_CLIENT_HELLO])
        + struct.pack("!I", len(client_hello))[1:]   # 3-byte HS length
        + client_hello
    )

    record = (
        bytes([CONTENT_TYPE_HANDSHAKE, 0x03, 0x01])
        + struct.pack("!H", len(handshake))
        + handshake
    )
    return record


# --------------------------------------------------------------------------
# Async TCP helpers used by every transport-level probe
# --------------------------------------------------------------------------
async def tcp_open(
    ip: str, port: int, timeout: float
) -> tuple[Any, asyncio.StreamWriter]:
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(ip, port), timeout=timeout
    )
    return reader, writer


async def tls_handshake_attempt(
    ip: str,
    port: int,
    sni: str | None,
    raw_client_hello: bytes | None = None,
    timeout: float = 8.0,
    split_at: int | None = None,       # TCP fragmentation: send two segments
    pause_between_ms: int = 0,
) -> dict[str, Any]:
    """Send a (possibly crafted) ClientHello and classify the outcome.

    Returns a dict with: outcome in {ok, rst, alert, timeout, eof, error},
    elapsed_ms, server_ttl (if measurable), response bytes (hex, truncated).
    """
    result: dict[str, Any] = {
        "outcome": "error", "elapsed_ms": 0.0, "response_hex": "",
        "alert": None, "server_cert_present": False, "error": None,
    }
    start = time.perf_counter()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
    except (asyncio.TimeoutError, ConnectionResetError, OSError) as exc:
        result["outcome"] = "rst" if isinstance(exc, ConnectionResetError) else "error"
        result["error"] = f"{type(exc).__name__}: {exc}"
        result["elapsed_ms"] = (time.perf_counter() - start) * 1000
        return result

    sock = writer.transport.get_extra_info("socket")
    if sock is not None:
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 0 if split_at else 1)
        except OSError:
            pass

    try:
        if raw_client_hello is None:
            raw_client_hello = build_client_hello(sni or "", sni=sni)

        if split_at:
            writer.write(raw_client_hello[:split_at])
            await writer.drain()
            if pause_between_ms:
                await asyncio.sleep(pause_between_ms / 1000.0)
            writer.write(raw_client_hello[split_at:])
        else:
            writer.write(raw_client_hello)
        await writer.drain()

        resp = await asyncio.wait_for(reader.read(1024), timeout=timeout)
        elapsed = (time.perf_counter() - start) * 1000
        result["elapsed_ms"] = elapsed
        result["response_hex"] = resp[:256].hex()
        if not resp:
            result["outcome"] = "eof"           # silent drop
        elif resp[0] == 0x15:                    # Alert record
            desc = resp[7] if len(resp) >= 8 else None
            result["outcome"] = "alert"
            result["alert"] = desc
        elif resp[0] == 0x16:                    # ServerHello => passed DPI
            result["outcome"] = "ok"
            result["server_cert_present"] = True
        else:
            result["outcome"] = "ok"
    except ConnectionResetError as exc:
        result["outcome"] = "rst"
        result["error"] = f"ConnectionResetError: {exc}"
    except asyncio.TimeoutError:
        result["outcome"] = "timeout"
    except ssl.SSLError as exc:
        result["outcome"] = "alert"
        result["error"] = str(exc)
    except OSError as exc:
        result["outcome"] = "error"
        result["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        try:
            writer.close()
        except Exception:
            pass
        result.setdefault("elapsed_ms", (time.perf_counter() - start) * 1000)
    return result


async def resolve(domain: str, timeout: float = 3.0) -> list[str]:
    loop = asyncio.get_running_loop()
    infos = await asyncio.wait_for(loop.getaddrinfo(domain, None, socket.AF_INET), timeout)
    return sorted({i[4][0] for i in infos})
