"""Optional ODoH end-to-end crypto (RFC 9230 + RFC 9180 HPKE base mode).

Requires the ``cryptography`` package (pip install 'censortrace[odoh]').
If it is missing, ``hpke_available()`` returns False and the encdns probe
degrades to transport-level checks only — never claiming e2e success.

Ciphersuites in use by public relays:
  KEM  = DHKEM(X25519, HKDF-SHA256) = 0x0020   -> kem_id(2) || kdf_id(2)
  KDF  = HKDF-SHA256                = 0x0001
  AEAD = AES-128-GCM (0x0001) or ChaCha20-Poly1305 (0x0003) -> aead_id(2)
"""

from __future__ import annotations

import hashlib
import struct
from typing import Any

try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey, X25519PublicKey)
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    _HAVE_CRYPTO = True
except ImportError:      # pragma: no cover - environment without cryptography
    _HAVE_CRYPTO = False


def hpke_available() -> bool:
    return _HAVE_CRYPTO


_KEM_ID = 0x0020          # DHKEM(X25519, HKDF-SHA256)
_KDF_ID = 0x0001          # HKDF-SHA256


# --------------------------------------------------------------------------
# ConcatKDF (RFC 9180 §4)
# --------------------------------------------------------------------------
def _concat_kdf(ikm: bytes, info: bytes, length: int) -> bytes:
    digest, t_i, i = b"", b"", 1
    while len(digest) < length:
        t_i = hashlib.sha256(t_i + i.to_bytes(1, "big") + info).digest()
        digest += t_i
        i += 1
    return digest[:length]


class HpkeSession:
    """Minimal stateful HPKE sender session (encap once, seal/open with seq)."""

    def __init__(self, receiver_pub_bytes: bytes, aead_id: int = 0x0001) -> None:
        if not _HAVE_CRYPTO:
            raise RuntimeError("cryptography not installed")
        self.aead_id = aead_id
        self.receiver = X25519PublicKey.from_public_bytes(receiver_pub_bytes)
        self.eph = X25519PrivateKey.generate()
        self.enc = self.eph.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

        ss = self.eph.exchange(self.receiver)
        kem_suite = b"HPKE-v1" + struct.pack("!H", _KEM_ID) + b"e"
        kem_context = self.enc + receiver_pub_bytes
        derived_ss = _concat_kdf(ss, kem_suite + b"shared_secret" + kem_context, 32)

        self.suite = (b"HPKE-v1" + struct.pack("!HH", _KEM_ID, _KDF_ID)
                      + struct.pack("!H", aead_id))
        secret = _concat_kdf(derived_ss, b"psk0" + self.suite, 32)
        key = _concat_kdf(secret, b"key" + self.suite, 16)
        self.base_nonce = _concat_kdf(secret, b"base_nonce" + self.suite, 12)
        self.exporter_secret = _concat_kdf(secret, b"exp" + self.suite, 32)
        self.aead = AESGCM(key) if aead_id == 0x0001 else ChaCha20Poly1305(key)
        self._seq = 0

    def _nonce(self, seq: int) -> bytes:
        return bytes(a ^ b for a, b in zip(
            self.base_nonce, seq.to_bytes(12, "little").ljust(12, b"\x00")))

    def seal(self, plaintext: bytes, aad: bytes = b"") -> bytes:
        ct = self.aead.encrypt(self._nonce(self._seq), plaintext, aad)
        self._seq += 1
        return ct

    def open_(self, ct: bytes, aad: bytes = b"", seq: int | None = None) -> bytes:
        s = self._seq if seq is None else seq
        return self.aead.decrypt(self._nonce(s), ct, aad)

    def response_keys(self) -> tuple[Any, bytes]:
        """ODoH §4.2: response key/nonce exported under label 'odoh'."""
        rk = _concat_kdf(self.exporter_secret, b"odoh-response-key", 16)
        rn = _concat_kdf(self.exporter_secret, b"odoh-response-nonce", 12)
        aead = AESGCM(rk) if self.aead_id == 0x0001 else ChaCha20Poly1305(rk)
        return aead, rn


# --------------------------------------------------------------------------
# ODoH message framing (RFC 9230 §4)
# --------------------------------------------------------------------------
ODOH_VERSION = 0x0001


def build_odoh_query(session: HpkeSession, dns_wire_msg: bytes, config_id: bytes,
                     kem_id: int = _KEM_ID) -> bytes:
    """ObliviousDNSQuery{version, config_id, encrypted_message}.

    encrypted_message = HPKE.seal(dns-msg) with AAD = the query header so the
    relay can authenticate framing without decrypting contents.
    """
    header = (struct.pack("!HH", ODOH_VERSION, kem_id)
              + bytes([len(config_id)]) + config_id
              + struct.pack("!H", len(session.enc)) + session.enc)
    ct = session.seal(dns_wire_msg, aad=header)
    return header + ct


def parse_odoh_response(data: bytes, session: HpkeSession) -> bytes:
    """Unwrap ObliviousDNSMessage{datagram_type=2, cont, payload} then decrypt."""
    off = 0
    (otype,) = struct.unpack("!H", data[off:off + 2]); off += 2
    if otype != 0x0002:
        raise ValueError(f"unexpected oblivious msg type {otype:#04x}")
    (clen,) = struct.unpack("!B", data[off:off + 1]); off += 1
    cont = data[off:off + clen]; off += clen
    payload = data[off:]
    aead, nonce = session.response_keys()
    return aead.decrypt(nonce, payload, cont)


def parse_odoh_config_list(cfgdata: bytes) -> list[dict[str, Any]]:
    """Parse ODoHConfigList -> [ODoHConfig{kem_id,kdf_id,aead_id,config_id,public_key}]."""
    off = 0
    (_ver,) = struct.unpack("!H", cfgdata[off:off + 2]); off += 2
    (total,) = struct.unpack("!H", cfgdata[off:off + 2]); off += 2
    configs: list[dict[str, Any]] = []
    end = off + total
    while off + 6 <= end:
        kem_id, kdf_id, aead_id = struct.unpack("!HHH", cfgdata[off:off + 6])
        off += 6
        (cid_len,) = struct.unpack("!H", cfgdata[off:off + 2]); off += 2
        config_id = cfgdata[off:off + cid_len]; off += cid_len
        (pk_len,) = struct.unpack("!H", cfgdata[off:off + 2]); off += 2
        pubkey = cfgdata[off:off + pk_len]; off += pk_len
        configs.append({"kem_id": kem_id, "kdf_id": kdf_id, "aead_id": aead_id,
                        "config_id": config_id, "public_key": pubkey})
    return configs


async def odoh_roundtrip(pair: dict[str, str], qdomain: str) -> tuple[bool, Any]:
    """Full ODoH query through relay -> target for ``qdomain``.

    Fetches the target's ODoHConfigList over plain HTTPS, picks the first
    supported config, HPKE-seals a DNS query and POSTs it to the relay.
    Returns (success, detail).
    """
    import asyncio
    import ssl
    import http.client
    from urllib.parse import urlsplit

    from .. import dns as _dns

    def fetch(url: str, method: str = "GET", body: bytes | None = None,
              headers: dict[str, str] | None = None) -> tuple[int, bytes]:
        parts = urlsplit(url)
        conn = http.client.HTTPSConnection(parts.hostname, parts.port or 443,
                                           timeout=8,
                                           context=ssl.create_default_context())
        try:
            conn.request(method, parts.path or "/", body=body, headers=headers or {})
            resp = conn.getresponse()
            return resp.status, resp.read()
        finally:
            conn.close()

    loop = asyncio.get_running_loop()

    status, cfgdata = await loop.run_in_executor(None, fetch, pair["target_configs"])
    if status != 200:
        return False, f"config fetch HTTP {status}"
    try:
        configs = parse_odoh_config_list(cfgdata)
    except (struct.error, IndexError) as exc:
        return False, f"config parse failed ({exc}); head={cfgdata[:24].hex()}"
    if not configs:
        return False, "empty ODoHConfigList"
    cfg = next((c for c in configs if c["kem_id"] == _KEM_ID
                and c["kdf_id"] == _KDF_ID and c["aead_id"] in (0x0001, 0x0003)),
               configs[0])

    msg, _tid = _dns.build_query(qdomain, _dns.TYPE_A)
    sess = HpkeSession(cfg["public_key"], aead_id=cfg["aead_id"])
    query = build_odoh_query(sess, msg, cfg["config_id"])
    rstatus, rbody = await loop.run_in_executor(
        None, fetch, pair["proxy"], "POST", query,
        {"Content-Type": "application/oblivious-dns-message",
         "Accept": "application/oblivious-dns-message"})
    if rstatus != 200:
        return False, f"relay HTTP {rstatus}: {rbody[:80]!r}"
    try:
        plain = parse_odoh_response(rbody, sess)
        parsed = _dns.parse_response(plain)
        return True, {"ips": parsed.ips(), "rcode": parsed.rcode,
                      "config": {"kem_id": cfg["kem_id"], "aead_id": cfg["aead_id"]}}
    except Exception as exc:
        return False, f"decrypt/parse failed: {type(exc).__name__}: {exc}"
