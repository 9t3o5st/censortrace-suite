"""ECH (Encrypted Client Hello) DPI prober.

Question answered: *does the ISP's middlebox react to the mere presence of the
encrypted_client_hello extension (codepoint 0xFE0D, or draft 0xFF03)?*

Design — differential black-box measurement, three arms run concurrently:

  A. control     : normal ClientHello (real SNI, no ECH)        -> baseline
  B. ech_outer   : ECH extension with a syntactically-valid but *random*
                   ECHConfig payload + real outer SNI           -> tests
                   presence-based rules while remaining server-reachable
  C. ech_grease  : ECH with an unknown config_id / old codepoint -> some DPI
                   whitelists exact byte patterns; we vary them
  D. ech_innerless: ECH with outer SNI = decoy ("example.com")   -> if this
                   passes while A is blocked, blocking is SNI-keyword based,
                   not ECH-extension based.

Verdict logic:
  * B/C get RST/timeout while A succeeds  -> ECH-targeted interference (BLOCKED)
  * all arms fail identically             -> domain-level block, ECH irrelevant
  * all arms succeed                      -> PASS (ECH tolerated by DPI)
  * B succeeds, A fails                   -> weird; flag as DEGRADED for review

Note on correctness: we intentionally do NOT complete the ECH crypto handshake.
A well-formed-but-unusable ECHClientHello still traverses the DPI pipeline in
full, which is exactly what a *presence*-based measurement needs.  Servers
reject it with an alert — that is our "passed the DPI" signal, distinct from
an injected RST or silent drop.
"""

from __future__ import annotations

import asyncio
import os
from typing import Any

from .. import tls
from ..config import ProbeConfig
from ..core import CensorshipProbe, Finding, ProbeResult, Verdict, register


def _ech_payload(config_id: int = 0x2A, enc_len: int = 32, pad: bool = True) -> bytes:
    """Build a structurally-plausible ECHClientHello(outer) body.

    struct {
      ECHType outer(1);                 == 0x01
      uint8 config_id;                  (arbitrary)
      opaque enc<1..2^16-1>;            (KEM ciphertext-looking blob)
      ECHClientHelloInner inner<0..2^16-1>;
    } ECHClientHelloOuter;

    Middleboxes pattern-match the *extension header*, so the exact contents
    only need to look right length-wise.
    """
    enc = os.urandom(enc_len)
    inner = b"" if not pad else os.urandom(16)
    return (
        bytes([0x01, config_id])
        + len(enc).to_bytes(2, "big") + enc
        + len(inner).to_bytes(2, "big") + inner
    )


@register
class ECHProbe(CensorshipProbe):
    name = "ech"
    description = "Detect DPI interference keyed on the encrypted_client_hello extension"

    async def run(self) -> ProbeResult:
        cfg = self.cfg
        try:
            ips = list(cfg.target_ips) or await tls.resolve(cfg.domain, cfg.tcp_timeout)
        except Exception as exc:
            return self.result(Verdict.ERROR, error=f"resolution failed: {exc}")
        if not ips:
            return self.result(Verdict.ERROR, error="no A records")
        ip = ips[0]

        # --- four concurrent arms ----------------------------------------
        ch_plain = tls.build_client_hello(cfg.domain)
        ch_ech = tls.build_client_hello(cfg.domain, with_ech=True,
                                        ech_payload=_ech_payload())
        ch_ech_old = tls.build_client_hello(cfg.domain, with_ech=True,
                                            ech_old_codepoint=True,
                                            ech_payload=_ech_payload(config_id=0xFF))
        ch_ech_decoy = tls.build_client_hello(cfg.domain, sni="example.com",
                                              with_ech=True,
                                              ech_payload=_ech_payload())

        async def attempt(name: str, hello: bytes) -> tuple[str, dict[str, Any]]:
            r = await tls.tls_handshake_attempt(ip, cfg.tls_port, None, hello,
                                                timeout=cfg.tls_timeout)
            return name, r

        done = await asyncio.gather(*(
            attempt(n, h) for n, h in (
                ("control", ch_plain),
                ("ech_current_codepoint", ch_ech),
                ("ech_draft_codepoint", ch_ech_old),
                ("ech_decoy_sni", ch_ech_decoy),
            )
        ))
        arms = dict(done)
        metrics = {n: {"outcome": r["outcome"], "rtt_ms": round(r["elapsed_ms"], 1)}
                   for n, r in arms.items()}
        findings: list[Finding] = []

        def bad(o: str) -> bool:
            return o in ("rst", "timeout", "eof")

        ctrl = arms["control"]["outcome"]
        ech_cur = arms["ech_current_codepoint"]["outcome"]
        ech_old = arms["ech_draft_codepoint"]["outcome"]
        ech_decoy = arms["ech_decoy_sni"]["outcome"]

        if not bad(ctrl) and (bad(ech_cur) or bad(ech_old)):
            findings.append(Finding(
                "ech.extension_dropped", "high",
                "Connection survives without ECH but is killed when the "
                "encrypted_client_hello extension is present "
                f"(current cp: {ech_cur}, draft cp: {ech_old}). "
                "Evidence of presence-based ECH filtering.",
                {"arms": metrics},
            ))
            verdict = Verdict.BLOCKED
        elif bad(ctrl) and not bad(ech_decoy):
            findings.append(Finding(
                "ech.decoy_sni_bypass", "info",
                "Real-SNI handshake blocked but ECH+decoy-SNI passed: the DPI "
                "rule keys on the plaintext SNI keyword, not on ECH itself.",
                {"arms": metrics},
            ))
            verdict = Verdict.PASS
        elif bad(ctrl) and bad(ech_cur) and bad(ech_old):
            findings.append(Finding(
                "ech.inconclusive_domain_block", "medium",
                "All arms failed identically — domain-level blocking masks any "
                "ECH-specific behaviour. Test from a clean path to separate.",
                {"arms": metrics},
            ))
            verdict = Verdict.BLOCKED
        elif ctrl != "ok" and ech_cur == "ok":
            findings.append(Finding(
                "ech.anomaly", "low",
                "Control failed while ECH succeeded — unusual; possible "
                "intermittent DPI statefulness.",
                {"arms": metrics},
            ))
            verdict = Verdict.DEGRADED
        else:
            verdict = Verdict.PASS

        raw = {n: {"response_hex": r["response_hex"][:96], "error": r["error"]}
               for n, r in arms.items()}
        return self.result(verdict, findings=findings, metrics=metrics, raw=raw)
