"""Central configuration: timeouts, resolvers and Iran-specific indicators.

All heuristics used by the probes are declared here so they can be audited,
tuned per-vantage-point, or overridden from the CLI / a config file.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# --------------------------------------------------------------------------
# Timeouts (seconds)
# --------------------------------------------------------------------------
DNS_TIMEOUT = 3.0
TCP_CONNECT_TIMEOUT = 5.0
TLS_TIMEOUT = 8.0
QUIC_TIMEOUT = 6.0
HTTP_TIMEOUT = 10.0


# --------------------------------------------------------------------------
# Iran / NIN specific indicators
# --------------------------------------------------------------------------
#: Known Iranian state blockpage / filtering resolver answers.
#: 10.10.34.34/.35/.36 are the classic internal blockpage sinks handed out by
#: censored resolvers; d0::11 is the IPv6 counterpart seen in NIN traces.
IRAN_BLOCKPAGE_IPv4 = ("10.10.34.34", "10.10.34.35", "10.10.34.36")
IRAN_BLOCKPAGE_IPv6 = ("d0::11", "fd00::")
IRAN_BLOCKPAGE_IPS = IRAN_BLOCKPAGE_IPv4 + IRAN_BLOCKPAGE_IPv6

#: Fingerprint of DPI-injected TCP RST packets observed behind Iranian ISPs.
#: Injected RSTs typically arrive with a *lower TTL than the legit path*
#: (injected mid-stream by the middlebox rather than the endpoint) and an
#: all-zero window / zero sequence against the live connection.
IRAN_RST_TTL_DELTA_MAX = 8      # injected if ttl(legit) - ttl(rst) >= this
IRAN_RST_WINDOW_SUSPECT = (0,)  # DPI boxes commonly emit window=0 RSTs

#: Hostnames whose resolution to blockpage IPs confirms DNS poisoning.
BLOCKPAGE_HOSTNAME_HINTS = ("blockpage", "filter", "khabar", "faraja")

# --------------------------------------------------------------------------
# Resolvers / encrypted DNS endpoints
# --------------------------------------------------------------------------
CONTROL_RESOLVERS = ("8.8.8.8", "1.1.1.1", "208.67.222.222")
ISP_RESOLVER_PLACEHOLDER = "auto"  # read from system resolver

DOT_ENDPOINTS = {
    "cloudflare": ("1.1.1.1", 853),
    "google": ("8.8.8.8", 853),
    "quad9": ("9.9.9.9", 853),
}

DOH_ENDPOINTS = {
    "cloudflare": "https://cloudflare-dns.com/dns-query",
    "google": "https://dns.google/dns-query",
    "mosdns-odoh": "https://odoh.mosdns.net:8443/.well-known/odohconfiguration",
}

#: Public ODoH relay/target pairs (relay obscures client IP from the target).
ODOH_PAIRS = [
    {
        "name": "cloudflare-relay -> quad9",
        "proxy": "https://odoh.cloudflare-dns.com/dns-query",
        "target_configs": "https://odoh.dns.quad9.net/.well-known/odohconfigs",
    },
    {
        "name": "mosdns relay -> dns.google",
        "proxy": "https://odoh.mosdns.net:8443/dns-query",
        "target_configs": "https://odoh.dns.google/dns-query.odohconfig",
    },
]

DOQ_ENDPOINTS = {
    "cloudflare": ("162.159.61.11", 853),   # cloudflare-dns.com DoQ
    "quad9": ("9.9.9.9", 853),
}

#: Targets that historically serve HTTP/3 (Alt-Svc advertising).
QUIC_TEST_TARGETS = {
    "cloudflare": ("1.1.1.1", "cloudflare.com"),
    "google": ("142.250.185.78", "www.google.com"),
    "facebook": ("157.240.22.14", "www.facebook.com"),
}

#: Speed-test asset for throttling ratio measurement.
THROTTLE_ASSET = "/npm/jquery@3.6.0/dist/jquery.min.js"
THROTTLE_CDN_HTTP = "http://cdn.jsdelivr.net" + THROTTLE_ASSET
THROTTLE_CDN_HTTPS = "https://cdn.jsdelivr.net" + THROTTLE_ASSET

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0",
]


@dataclass
class ProbeConfig:
    """Runtime configuration handed to every probe."""

    domain: str = "youtube.com"
    tls_port: int = 443
    control_resolvers: tuple[str, ...] = CONTROL_RESOLVERS
    dns_timeout: float = DNS_TIMEOUT
    tcp_timeout: float = TCP_CONNECT_TIMEOUT
    tls_timeout: float = TLS_TIMEOUT
    quic_timeout: float = QUIC_TIMEOUT
    http_timeout: float = HTTP_TIMEOUT
    max_concurrency: int = 12
    #: Optional pre-resolved target IPs; probes fall back to system resolver.
    target_ips: tuple[str, ...] = ()
    extra: dict = field(default_factory=dict)


#: Fallback decoy SNI values for the fake-SNI evasion probe (used when
#: heuristics.FAKE_SNI_CANDIDATES is not imported by the caller).
FAKE_SNI_CANDIDATES = ("www.google.com", "www.microsoft.com", "example.com")
