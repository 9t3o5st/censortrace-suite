"""DNS poisoning / hijack probe with Iran-NIN specific heuristics.

Method (mirrors CensorTrace whitepaper §3):
  1. Query the *system/ISP* resolver (UDP+TCP) for A and AAAA.
  2. Query clean control resolvers (8.8.8.8 / 1.1.1.1 / OpenDNS) concurrently.
  3. Diff the answer sets against:
       - known blockpage sinks 10.10.34.34/.35/.36 (+ IPv6 d0::11)
       - transaction-ID mismatch (forged answers racing the real one)
       - implausibly low TTLs (cache-busting forged records)
       - divergence from control answers / NXDOMAIN injection
"""

from __future__ import annotations

import asyncio
from typing import Any

from .. import dns
from ..config import ProbeConfig
from ..core import CensorshipProbe, Finding, ProbeResult, Verdict, register
from ..heuristics import classify_dns_answers


@register
class DNSProbe(CensorshipProbe):
    name = "dns"
    description = "DNS poisoning: ISP vs control resolvers, NIN blockpage IPs"

    def __init__(self, config: ProbeConfig) -> None:
        super().__init__(config)
        self.cfg: ProbeConfig = config

    # -- helpers ----------------------------------------------------------
    async def _query(self, server: str, qtype: int) -> dict[str, Any]:
        try:
            resp = await dns.query_udp(server, self.cfg.domain, qtype,
                                       timeout=self.cfg.dns_timeout)
        except Exception as exc:
            return {"server": server, "error": f"{type(exc).__name__}: {exc}"}
        tid_mismatch = bool(resp.flags & 0x8000)
        return {
            "server": server,
            "rcode": resp.rcode,
            "ips": resp.ips(),
            "ttls": [a.ttl for a in resp.answers],
            "answers": [
                {"name": a.name, "type": a.rtype, "ttl": a.ttl, "rdata": a.rdata}
                for a in resp.answers
            ],
            "tid_mismatch": tid_mismatch,
            "truncated": resp.truncated,
        }

    async def run(self) -> ProbeResult:
        cfg = self.cfg
        findings: list[Finding] = []
        metrics: dict[str, Any] = {}

        # System resolver discovery without extra deps: read /etc/resolv.conf
        system_servers = _system_resolvers() or ["192.168.1.1"]

        tasks = []
        for s in system_servers:
            tasks.append(("isp", s, asyncio.create_task(self._query(s, dns.TYPE_A))))
            tasks.append(("isp6", s, asyncio.create_task(self._query(s, dns.TYPE_AAAA))))
        for s in cfg.control_resolvers:
            tasks.append(("control", s, asyncio.create_task(self._query(s, dns.TYPE_A))))

        isp_results: dict[str, Any] = {}
        control_ips: set[str] = set()
        for kind, server, task in tasks:
            r = await task
            if kind == "control":
                if not r.get("error"):
                    control_ips.update(r.get("ips", []))
            else:
                isp_results.setdefault(server, []).append(r)

        raw = {"isp": isp_results, "control_ips": sorted(control_ips)}
        metrics["control_answer_count"] = len(control_ips)

        for server, results in isp_results.items():
            merged_ips = [ip for r in results for ip in r.get("ips", [])]
            merged_ttls = [t for r in results for t in r.get("ttls", [])]
            rcode = next((r["rcode"] for r in results if "rcode" in r), 0)
            verdicts = classify_dns_answers(
                {"ips": merged_ips, "ttls": merged_ttls, "rcode": rcode},
                control_ips if control_ips else None,
            )
            if verdicts["poisoned_blockpage"]:
                findings.append(Finding(
                    "dns.blockpage_ip", "high",
                    f"Resolver {server} returned known Iranian blockpage IP(s): "
                    f"{', '.join(verdicts['blockpage_ips'])}",
                    {"resolver": server, "answers": merged_ips},
                ))
            if any(r.get("tid_mismatch") for r in results):
                findings.append(Finding(
                    "dns.tid_mismatch", "high",
                    f"Answer from {server} had a transaction ID that does not "
                    "match the query — classic off-path forged response.",
                    {"resolver": server},
                ))
            if verdicts["zero_ttl"]:
                findings.append(Finding(
                    "dns.low_ttl", "medium",
                    f"{server}: forged-looking record TTL(s) {merged_ttls} (<5s).",
                    {"ttls": merged_ttls},
                ))
            if verdicts["divergent"] and not verdicts["poisoned_blockpage"]:
                findings.append(Finding(
                    "dns.divergent", "medium",
                    f"{server}: answers diverge from control resolvers "
                    f"(ISP={merged_ips or f'NXDOMAIN rcode={rcode}'}, "
                    f"control={sorted(control_ips)})",
                    {"isp": merged_ips, "control": sorted(control_ips)},
                ))

        positives = [f for f in findings if f.severity == "high"]
        verdict = (
            Verdict.POISONED if positives
            else Verdict.DEGRADED if findings
            else Verdict.PASS if control_ips or any(
                not r.get("error") for rs in isp_results.values() for r in rs)
            else Verdict.ERROR
        )
        return self.result(verdict, findings=findings, metrics=metrics, raw=raw)


def _system_resolvers() -> list[str]:
    try:
        with open("/etc/resolv.conf") as fh:
            return [
                line.split()[1] for line in fh
                if line.strip().startswith("nameserver") and len(line.split()) > 1
            ][:2]
    except OSError:
        return []
