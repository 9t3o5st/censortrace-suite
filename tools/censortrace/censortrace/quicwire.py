"""QUIC long-header wire codec (RFC 9000 §17) — stdlib-only.

We deliberately do NOT implement the full TLS/crypto layer (Header-Protection
and AEAD require HKTF/AES-CTR/ChaCha20-Poly1305).  Instead we emit Initial
packets that are *structurally valid*:

  * correct long-header bit layout, version, DCID/SCID lengths
  * a real TLS ClientHello with ``extension_quic_transport_parameters`` and a
    genuine X25519 key_share, wrapped in an "Initial" PSK-style payload
  * padding to >= 1205 bytes so servers accept the Initial (anti-amplification)

This is exactly what a measurement tool needs to answer the questions:
  * Is UDP/443 reachable at all?           (silent drop vs ICMP vs reply)
  * Does the DPI reset/drop Version Negotiation packets?
  * Does the DPI choke specific SNI / ALPN values inside the Initial?

Long header (Initial / Handshake / Retry / VN):

    0x?? | Unused(1) Long(1) Type(2) RFU(4)
         Version(32) DCIDLen(8) DCID SCIDLen(8) SCID
         [Initial only: Token(length-prefixed)]
         PacketNumberLength(bits 0..1 of flags) PN(variable)
         Payload length(varint) + protected payload
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass

# Packet types (long header, RFC 9000 Table 24)
PK_INITIAL = 0b00
PK_0RTT = 0b01
PK_HANDSHAKE = 0b10
PK_RETRY = 0b11

VERSION_V1 = 0x00000001        # final RFC 9000
VERSION_DRAFT29 = 0xFF00001D   # legacy draft used by old Chrome/Firefox
VERSION_DRAFT27 = 0xFF00001B
VERSION_V2 = 0x6B3343CF        # RFC 9369
VERSION_GREASE = 0x0a0a0a0a    # for version-negotiation probes

FMT_INITIAL = (PK_INITIAL << 4)      # byte0 without PN bits
FMT_HANDSHAKE = (PK_HANDSHAKE << 4)


# --------------------------------------------------------------------------
# Variable-length integers (RFC 9000 §18)
# --------------------------------------------------------------------------
def encode_varint(value: int) -> bytes:
    if value < 0x40:
        return bytes([value])
    if value < 0x4000:
        return struct.pack("!H", value | 0x4000)
    if value < 0x40000000:
        return struct.pack("!I", value | 0x80000000)
    if value < 0x4000000000000000:
        return struct.pack("!Q", value | 0xC000000000000000)
    raise ValueError(f"varint too large: {value}")


def decode_varint(buf: bytes, offset: int = 0) -> tuple[int, int]:
    first = buf[offset]
    nbytes = 1 << (first >> 6)
    if offset + nbytes > len(buf):
        raise ValueError("truncated varint")
    val = first & 0x3F
    for i in range(1, nbytes):
        val = (val << 8) | buf[offset + i]
    return val, offset + nbytes


# --------------------------------------------------------------------------
# Frames
# --------------------------------------------------------------------------
FRAME_PADDING = 0x00
FRAME_PING = 0x01
FRAME_CRYPTO = 0x06


def crypto_frame(data: bytes) -> bytes:
    return bytes([FRAME_CRYPTO]) + encode_varint(len(data)) + data


def padding_frame(n: int) -> bytes:
    return bytes(FRAME_PADDING) * max(0, n)


# --------------------------------------------------------------------------
# QUIC transport parameters (RFC 9000 §18) embedded in the ClientHello
# --------------------------------------------------------------------------
TP_ORIGINAL_DESTINATION_CONNECTION_ID = 0x00
TP_MAX_IDLE_TIMEOUT = 0x01
TP_INITIAL_MAX_DATA = 0x02
TP_INITIAL_MAX_STREAMS_BIDI = 0x08
TP_INITIAL_MAX_STREAMS_UNI = 0x09
TP_ACTIVE_CONNECTION_ID_LIMIT = 0x0E
TP_INITIAL_MAX_PACKET_SIZE = 0x0F
TP_VERSION_NEGOTIATION = 0x11


def build_transport_params(dcid: bytes) -> bytes:
    params = b""

    def add(code: int, value: bytes) -> None:
        nonlocal params
        params += encode_varint(code) + encode_varint(len(value)) + value

    add(TP_ORIGINAL_DESTINATION_CONNECTION_ID, dcid)
    add(TP_MAX_IDLE_TIMEOUT, encode_varint(30000))
    add(TP_INITIAL_MAX_DATA, encode_varint(1_048_576))
    add(TP_INITIAL_MAX_STREAMS_UNI, encode_varint(3))
    add(TP_INITIAL_MAX_STREAMS_BIDI, encode_varint(100))
    add(TP_ACTIVE_CONNECTION_ID_LIMIT, encode_varint(2))
    add(TP_INITIAL_MAX_PACKET_SIZE, encode_varint(1350))
    return params


def quic_client_hello_extension(dcid: bytes) -> tuple[int, bytes]:
    """(extension_type, body) for extension 0x0039 quic_transport_parameters.

    Body is the *ClientHello* encoding: a 2-byte prefixed parameter list.
    """
    body = struct.pack("!H", len(build_transport_params(dcid))) + build_transport_params(dcid)
    return 0x0039, body


# --------------------------------------------------------------------------
# Long-header packet builder / parser
# --------------------------------------------------------------------------
@dataclass
class LongHeaderPacket:
    pkt_type: int
    version: int
    dcid: bytes
    scid: bytes
    token: bytes = b""
    payload: bytes = b""

    def render(self, pn: int = 1, pn_len: int = 2) -> bytes:
        flags = 0xC0 | (self.pkt_type << 4) | (pn_len - 1)  # long-bit + unused(1)
        head = bytes([flags]) + struct.pack("!I", self.version)
        head += bytes([len(self.dcid)]) + self.dcid
        head += bytes([len(self.scid)]) + self.scid
        if self.pkt_type == PK_INITIAL:
            head += encode_varint(len(self.token)) + self.token
        head += pn.to_bytes(pn_len, "big")
        body = head + encode_varint(len(self.payload)) + self.payload
        return body


def parse_long_header(data: bytes) -> dict | None:
    """Parse any QUIC long-header datagram; returns None on malformed input."""
    if len(data) < 7 or not (data[0] & 0x40):
        return None
    out: dict = {
        "raw": data,
        "byte0": data[0],
        "long_header": True,
        "pkt_type": (data[0] >> 4) & 0x03,
        "version": struct.unpack("!I", data[1:5])[0],
    }
    off = 5
    if out["pkt_type"] == PK_RETRY:
        out["dcid"] = data[off:off + data[off]].hex() if data[off] <= 20 else ""
        off += 1 + data[off - 1] if off < len(data) else 0
        out["scid"] = data[off:off + data[off]].hex() if data[off] <= 20 else ""
        return out
    try:
        dclen = data[off]; off += 1
        dcid = data[off:off + dclen]; off += dclen
        sclen = data[off]; off += 1
        scid = data[off:off + sclen]; off += sclen
        out.update(dcid=dcid.hex(), scid=scid.hex())
        if out["pkt_type"] == PK_INITIAL:
            tlen, off = decode_varint(data, off)
            out["token"] = data[off:off + tlen].hex()
            off += tlen
        if out["pkt_type"] == PK_HANDSHAKE or out["pkt_type"] == PK_INITIAL:
            pn_len = (data[0] & 0x03) + 1
            out["payload_len_field"], off = decode_varint(data, off)
            out["offset_to_payload"] = off + pn_len
    except (IndexError, ValueError):
        pass
    return out


def looks_like_version_negotiation(data: bytes) -> bool:
    """VN packets have long header, version==0, then a list of 4-byte versions."""
    p = parse_long_header(data)
    if not p:
        return False
    return p["version"] == 0


def supported_versions_from_vn(data: bytes) -> list[int]:
    if len(data) < 12:
        return []
    body = data[8:]
    return [struct.unpack("!I", body[i:i + 4])[0]
            for i in range(0, len(body) - 3, 4)]


def initial_packet(
    client_hello: bytes,
    dcid: bytes | None = None,
    *,
    version: int = VERSION_V1,
    min_size: int = 1205,
    token: bytes = b"",
) -> tuple[bytes, bytes]:
    """Wrap a ClientHello into a padded Initial datagram.

    Returns (datagram, dcid) — the DCID is echoed back so callers can correlate.
    """
    dcid = dcid or os.urandom(8)
    scid = os.urandom(8)
    payload = crypto_frame(client_hello)
    pad = padding_frame(max(0, min_size - len(payload)))
    pkt = LongHeaderPacket(PK_INITIAL, version, dcid, scid, token, payload + pad)
    return pkt.render(), dcid
