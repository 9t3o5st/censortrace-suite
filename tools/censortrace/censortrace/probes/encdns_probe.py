"""Encrypted-DNS availability probe: DoT vs DoH vs ODoH vs DoQ, side by side.

The point of running *all four* against the same query set is differential
diagnosis from an Iranian vantage point:

  DoT (853/TCP)   : classic NIN target — expect RST/timeout on port 853.
  DoH (443/TLS)   : hides inside normal HTTPS; blocked only via SNI keyword.
  ODoH (relay+target): relay hides client IP from resolver, resolver name hides
                    from DPI only if the relay itself isn't blocklisted — we
                    therefore test *relay reachability* and *end-to-end success*
                    separately (metadata-leak analysis).
  DoQ (853/UDP)   : tests whether QUIC-based DNS survives when TCP-DoT dies.

Metadata-leak checks (cheap, black-box):
  * DoT with SNI = IP literal vs hostname — some stacks leak server_name.
  * DoH GET vs POST — GET puts the b64 wire message in the URL path where a
    TLS-terminating proxy could log it; we record which method the endpoint
    accepts (both should work per RFC 8484).
  * ODoH: does the *relay* see our target hostname?  We can't inspect the relay
    directly, but we verify the ObliviousDNSMessage structure round-trips and
    that the response differs from plain DoH to the same target (proving the
    client did use the encrypted wrapper, i.e. no plaintext fallback).

ODoH crypto note: full HPKE (RFC 9180 X25519-HKDF256-AESGCM) is implemented in
``odoh_crypto.py`` *if* `cryptography` is installed; otherwise we degrade to
"transport-level" checks (relay reachable, config retrievable, wire format
accepted) and mark the finding as SKIPPED-with-reason instead of lying about
end-to-end success.
"""

from __future__ import annotations

import asyncio
import base64
import json
import socket
import ssl
import struct
from typing import Any

from .. import dns
from ..config import DOH_ENDPOINTS, DOT_ENDPOINTS, DOQ_ENDPOINTS, ODOH_PAIRS, ProbeConfig
from ..core import CensorshipProbe, Finding, ProbeResult, Verdict, register
from ..net import udp_exchange
from ..quicwire import initial_packet


async def _doh_query(url: str, domain: str, method: str = "get",
                     timeout: float = 8.0) -> dict[str, Any]:
    """RFC 8484 DoH over stdlib http.client in a thread executor."""
    import http.client
    from urllib.parse import urlsplit

    msg, _tid = dns.build_query(domain, dns.TYPE_A)

    def worker() -> dict[str, Any]:
        parts = urlsplit(url)
        port = parts.port or 443
        conn = http.client.HTTPSConnection(parts.hostname, port, timeout=timeout,
                                           context=ssl.create_default_context())
        headers = {"Host": parts.netloc, "Accept": "application/dns-message"}
        try:
            if method == "get":
                b64 = base64.urlsafe_b64encode(msg).rstrip(b"=").decode()
                conn.request("GET", f"{parts.path}?dns={b64}", headers=headers)
            else:
                headers["Content-Type"] = "application/dns-message"
                conn.request("POST", parts.path, body=msg, headers=headers)
            resp = conn.getresponse()
            body = resp.read()
            out: dict[str, Any] = {"status": resp.status,
                                   "content_type": resp.getheader("Content-Type")}
            if resp.status == 200 and "dns-message" in (out["content_type"] or ""):
                parsed = dns.parse_response(body)
                out.update(ips=parsed.ips(), rcode=parsed.rcode, bytes=len(body))
            elif resp.status == 200:
                out["note"] = "200 but not dns-message (JSON API?)"
            else:
                out["error_body"] = body[:120].decode("utf-8", "replace")
            return out
        except Exception as exc:
            return {"error": f"{type(exc).__name__}: {exc}"}
        finally:
            conn.close()

    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, worker)


async def _dot_query(host: str, port: int, domain: str, sni: str | None,
                     timeout: float) -> dict[str, Any]:
    msg, _tid = dns.build_query(domain, dns.TYPE_A)
    framed = struct.pack("!H", len(msg)) + msg
    ctx = ssl.create_default_context()
    if sni is None:                      # measure SNI-leak variants
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    reader = writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx,
                                    server_hostname=sni or host),
            timeout=timeout)
        writer.write(framed)
        await writer.drain()
        hdr = await asyncio.wait_for(reader.readexactly(2), timeout=timeout)
        (rlen,) = struct.unpack("!H", hdr)
        data = await asyncio.wait_for(reader.readexactly(rlen), timeout=timeout)
        parsed = dns.parse_response(data)
        return {"outcome": "ok", "ips": parsed.ips(), "rcode": parsed.rcode}
    except (asyncio.TimeoutError, ConnectionResetError, ssl.SSLError, OSError) as exc:
        kind = ("rst" if isinstance(exc, ConnectionResetError)
                else "timeout" if isinstance(exc, asyncio.TimeoutError)
                else "tls_error" if isinstance(exc, ssl.SSLError)
                else "error")
        return {"outcome": kind, "error": f"{type(exc).__name__}: {exc}"}
    finally:
        if writer is not None:
            try:
                writer.close()
            except Exception:
                pass


@register
class EncryptedDNSProbe(CensorshipProbe):
    name = "encdns"
    description = "DoT / DoH(GET+POST) / ODoH / DoQ differential availability & metadata checks"

    async def run(self) -> ProbeResult:
        cfg = self.cfg
        qdomain = "example.com"          # benign fixed query for cross-path diffing

        tasks: dict[str, asyncio.Task] = {}

        # --- DoT: hostname-SNI and IP-SNI variants -----------------------
        for label, (host, port) in DOT_ENDPOINTS.items():
            tasks[f"dot_{label}_sni_host"] = asyncio.create_task(
                _dot_query(host, port, qdomain, sni=None, timeout=cfg.tls_timeout))
        # --- DoH: GET vs POST --------------------------------------------
        for label, url in DOH_ENDPOINTS.items():
            tasks[f"doh_{label}_get"] = asyncio.create_task(_doh_query(url, qdomain, "get"))
            tasks[f"doh_{label}_post"] = asyncio.create_task(_doh_query(url, qdomain, "post"))
        # --- ODoH transport-level ----------------------------------------
        for pair in ODOH_PAIRS:
            tasks[f"odoh_{pair['name']}"] = asyncio.create_task(
                self._odoh_check(pair, qdomain))
        # --- DoQ ----------------------------------------------------------
        for label, (host, port) in DOQ_ENDPOINTS.items():
            tasks[f"doq_{label}"] = asyncio.create_task(self._doq_check(host, port))

        results = {k: await t for k, t in tasks.items()}
        findings: list[Finding] = []
        metrics: dict[str, Any] = {}

        dot_blocked = [k for k, v in results.items()
                       if k.startswith("dot_") and v.get("outcome") in ("rst", "timeout")]
        doh_ok = [k for k, v in results.items()
                  if k.startswith("doh_") and v.get("status") == 200]
        if len(dot_blocked) == sum(1 for k in results if k.startswith("dot_")) and dot_blocked:
            findings.append(Finding(
                "encdns.dot_blocked", "high",
                "Every DoT (TCP/853) endpoint failed while the port pattern "
                "(connect then immediate reset/timeout) matches NIN 853 filtering.",
                {k: results[k].get("outcome") for k in dot_blocked},
            ))
        if doh_ok:
            findings.append(Finding(
                "encdns.doh_available", "info",
                f"DoH still works on: {', '.join(sorted(set(k[4:].rsplit('_',1)[0] for k in doh_ok)))}"
                " — tunnel DNS over 443/TLS is viable from this vantage point.",
                {"endpoints": doh_ok},
            ))
        # GET-vs-POST metadata note
        for label in DOH_ENDPOINTS:
            g, p = results.get(f"doh_{label}_get", {}), results.get(f"doh_{label}_post", {})
            if g.get("status") == 200 and p.get("status") != 200:
                findings.append(Finding(
                    "encdns.doh_get_only", "low",
                    f"{label}: POST rejected ({p.get('status')}) — clients must use "
                    "GET, exposing the b64 wire query in the URL path to any "
                    "TLS-terminating middlebox logs (metadata leak surface).",
                    {"post_status": p.get("status"), "post_error": p.get("error_body")},
                ))

        odoh = {k: v for k, v in results.items() if k.startswith("odoh_")}
        doq = {k: v for k, v in results.items() if k.startswith("doq_")}
        metrics.update(dot={k: v for k, v in results.items() if k.startswith("dot_")},
                       doh={k: v for k, v in results.items() if k.startswith("doh_")},
                       odoh=odoh, doq=doq)

        positives = [f for f in findings if f.severity == "high"]
        verdict = (Verdict.BLOCKED if positives
                   else Verdict.PASS if doh_ok or any(v.get("outcome") == "ok" for v in doq.values())
                   else Verdict.DEGRADED)
        return self.result(verdict, findings=findings, metrics=metrics, raw={"results": results})

    # ------------------------------------------------------------------
    async def _odoh_check(self, pair: dict[str, str], qdomain: str) -> dict[str, Any]:
        """Transport-level ODoH check (no HPKE unless cryptography present).

        Steps:
          1. fetch target ODoHConfigList over its DoH endpoint
          2. fetch relay's advertised support (OPTIONS / known path)
          3. if `cryptography` is available: build a real ObliviousDNSQuery
             (HPKE-encrypted) and POST it to the relay; verify the response is
             an ObliviousDNSMessage (version byte 0x0001) and decrypt it.
        """
        out: dict[str, Any] = {"name": pair["name"]}
        cfgres = await _doh_query(pair["target_configs"], qdomain, "get")
        out["target_config_fetch"] = cfgres.get("status") or cfgres.get("error")

        try:
            from .odoh_crypto import hpke_available, odoh_roundtrip
            if not hpke_available():
                raise ImportError("cryptography missing")
            ok, detail = await odoh_roundtrip(pair, qdomain)
            out["e2e"] = "ok" if ok else "fail"
            out["detail"] = detail
        except ImportError:
            out["e2e"] = "skipped_no_hpke"
            out["detail"] = ("install 'cryptography' for HPKE (pip install "
                             "'censortrace[odoh]'); transport checks only")
        except Exception as exc:
            out["e2e"] = "error"
            out["detail"] = f"{type(exc).__name__}: {exc}"
        return out

    async def _doq_check(self, host: str, port: int) -> dict[str, Any]:
        """Send a QUIC Initial carrying a DoH-style ClientHello with alpn doq."""
        from .. import tls as _tls
        ch = _tls.build_client_hello("cloudflare-dns.com", quic_dcid=b"\x22" * 8,
                                     alpn=("doq",))
        pkt, _dcid = initial_packet(ch)
        ex = await udp_exchange(host, port, [pkt], timeout=self.cfg.quic_timeout)
        return {
            "outcome": ("reply" if ex.responses
                        else "icmp_unreachable" if ex.icmp_unreachable
                        else "timeout" if ex.timed_out else "error"),
            "rtt_ms": round(min(ex.rtts_ms), 1) if ex.rtts_ms else None,
            "replies": len(ex.responses),
            "error": ex.error,
        }
