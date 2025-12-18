from __future__ import annotations

# --- Standard Library Imports ---
import argparse
import binascii
import importlib
import os
import platform
import random
import socket
import struct
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

# --- Dependency Check & Third-Party Imports ---
def ensure_dependencies() -> None:
    """Ensure required packages are available; prompt user if missing."""
    missing = []
    for mod in ("requests", "colorama"):
        try:
            importlib.import_module(mod)
        except ImportError:
            missing.append(mod)
    if missing:
        print(
            "Missing required packages: "
            f"{', '.join(missing)}\n"
            "Install with: pip install " + " ".join(missing)
        )
        sys.exit(1)

ensure_dependencies()

import requests
from colorama import Fore, Style, init

__version__ = "0.2.0"

# --- Constants ---
DEFAULT_DOMAIN = "youtube.com"
DEFAULT_TLS_PORT = 443
DEFAULT_FAKE_DNS_SERVER = "1.1.1.0:53"

DNS_TIMEOUT = 2.0
HTTP_TIMEOUT = 3.0
TLS_TIMEOUT = 4.0
THROTTLE_TIMEOUT = 10.0
THROTTLE_CONCURRENCY = 2

SPEED_URL_HTTP = "http://cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.min.js"
SPEED_URL_HTTPS = "https://cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.min.js"

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0",
]

# --- Global var for Fake DNS (set in main) ---
FAKE_DNS_SERVER: Tuple[str, int] = ("1.1.1.0", 53)

# --- Classes ---
@dataclass
class TestResult:
    name: str
    status: str  # PASS, WARN, FAIL
    detail: str

class Console:
    def __init__(self, use_color: bool = True, quiet: bool = False) -> None:
        init(autoreset=True)
        self.use_color = use_color
        self.quiet = quiet

    def info(self, msg: str) -> None:
        if not self.quiet:
            print(self._fmt("[INFO] ", Fore.BLUE) + msg)

    def ok(self, msg: str) -> None:
        if not self.quiet:
            print(self._fmt("[OK] ", Fore.GREEN) + msg)

    def warn(self, msg: str) -> None:
        if not self.quiet:
            print(self._fmt("[WARN] ", Fore.YELLOW) + msg)

    def fail(self, msg: str) -> None:
        if not self.quiet:
            print(self._fmt("[FAIL] ", Fore.RED) + msg)

    def filtered(self, msg: str) -> None:
        if not self.quiet:
            print(self._fmt("[FILTERED] ", Fore.MAGENTA) + msg)

    def section(self, title: str) -> None:
        if not self.quiet:
            print(f"\n=== {title} ===")

    def _fmt(self, text: str, color: str) -> str:
        if not self.use_color:
            return text
        return f"{color}{text}{Style.RESET_ALL}"

# --- DNS Helper Functions ---

def build_dns_query(domain: str, qtype: int = 1) -> bytes:
    """Build a minimal DNS query for the given domain and qtype."""
    tid = random.randint(0, 0xFFFF)
    flags = 0x0100  # recursion desired
    qdcount = 1
    ancount = nscount = arcount = 0
    header = struct.pack("!HHHHHH", tid, flags, qdcount, ancount, nscount, arcount)

    labels = domain.strip('.').split('.')
    qname = b''.join(bytes([len(l)]) + l.encode('ascii') for l in labels) + b'\x00'
    qtype_bytes = struct.pack("!H", qtype)
    qclass = struct.pack("!H", 1)  # IN

    return header + qname + qtype_bytes + qclass

def parse_dns_response(data: bytes) -> list[str]:
    """Parse a DNS response and extract all A/AAAA answers as IP strings."""
    if len(data) < 12:
        return []
    try:
        tid, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", data[:12])
        offset = 12
        # Skip questions
        for _ in range(qdcount):
            while offset < len(data) and data[offset] != 0:
                offset += data[offset] + 1
            offset += 5  # null + qtype(2) + qclass(2)
        ips = []
        for _ in range(ancount):
            if offset + 10 > len(data): break
            # Handle compression pointer
            if data[offset] & 0xC0 == 0xC0:
                offset += 2
            else:
                while offset < len(data) and data[offset] != 0:
                    offset += data[offset] + 1
                offset += 1
            
            atype, aclass, ttl, rdlength = struct.unpack("!HHIH", data[offset:offset+10])
            offset += 10
            if offset + rdlength > len(data): break
            rdata = data[offset:offset+rdlength]
            offset += rdlength

            if atype == 1 and rdlength == 4:
                ips.append(".".join(str(b) for b in rdata))
            elif atype == 28 and rdlength == 16:
                ip6 = ":".join(f"{rdata[i]<<8|rdata[i+1]:x}" for i in range(0,16,2))
                ips.append(ip6)
        return ips
    except Exception:
        return []

def dig_style_dns_query(console: Console, domain: str, server: tuple, timeout: float, qtype: int = 1):
    """Perform a dig-style DNS query and print all sections and details."""
    console.section(f"[dig-style] DNS Query to {server[0]}:{server[1]} (type {qtype})")
    query = build_dns_query(domain, qtype)

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(query, server)
            data, _ = sock.recvfrom(2048)
    except Exception as exc:
        console.fail(f"DNS query failed: {exc}")
        return

    # Print raw hex
    console.info("Raw DNS response (hex):")
    print(binascii.hexlify(data).decode())

    if len(data) < 12:
        console.fail("Response too short.")
        return

    tid, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", data[:12])
    console.info(f"Transaction ID: 0x{tid:04x}")
    console.info(f"Flags: 0x{flags:04x}")
    console.info(f"Questions: {qdcount}, Answers: {ancount}, Authority: {nscount}, Additional: {arcount}")

    # Flags breakdown
    qr = (flags >> 15) & 1
    opcode = (flags >> 11) & 0xF
    aa = (flags >> 10) & 1
    tc = (flags >> 9) & 1
    rd = (flags >> 8) & 1
    ra = (flags >> 7) & 1
    rcode = flags & 0xF
    console.info(f"QR: {qr}, OPCODE: {opcode}, AA: {aa}, TC: {tc}, RD: {rd}, RA: {ra}, RCODE: {rcode}")

    offset = 12

    def parse_name(data, offset):
        labels = []
        orig = offset
        jumped = False
        while True:
            if offset >= len(data):
                return ("<truncated>", offset+1)
            length = data[offset]
            if length == 0:
                offset += 1
                break
            if (length & 0xC0) == 0xC0:
                if not jumped:
                    orig = offset+2
                    jumped = True
                ptr = ((length & 0x3F) << 8) | data[offset+1]
                label, _ = parse_name(data, ptr)
                labels.append(label)
                offset += 2
                break
            else:
                offset += 1
                labels.append(data[offset:offset+length].decode(errors="replace"))
                offset += length
        return (".".join(labels), orig if jumped else offset)

    # Skip questions for printing RRs
    for _ in range(qdcount):
        name, offset = parse_name(data, offset)
        offset += 4

    def print_rr(section, count):
        nonlocal offset
        for i in range(count):
            name, offset = parse_name(data, offset)
            if offset+10 > len(data):
                print(f"  [truncated RR]")
                return
            rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[offset:offset+10])
            offset += 10
            rdata = data[offset:offset+rdlength]
            offset += rdlength

            if rtype == 1 and rdlength == 4:
                rdata_str = ".".join(str(b) for b in rdata)
            elif rtype == 28 and rdlength == 16:
                rdata_str = ":".join(f"{rdata[i]<<8|rdata[i+1]:x}" for i in range(0,16,2))
            elif rtype == 5:  # CNAME
                cname, _ = parse_name(data, offset-rdlength)
                rdata_str = cname
            else:
                rdata_str = binascii.hexlify(rdata).decode()
            print(f"  {section} RR {i+1}: {name} type={rtype} class={rclass} ttl={ttl} rdata={rdata_str}")

    print_rr("Answer", ancount)
    print_rr("Authority", nscount)
    print_rr("Additional", arcount)

# --- Test Functions ---

def dns_query_udp(domain: str, server: Tuple[str, int], timeout: float, qtype: int = 1) -> List[str]:
    query = build_dns_query(domain, qtype)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(query, server)
        data, _ = sock.recvfrom(2048)
    
    if getattr(sys, '_export_packets', None):
        with open(sys._export_packets, 'a') as f:
            f.write(f"\n--- DNS UDP Query ({domain}) ---\n")
            f.write(query.hex() + "\n")
            f.write(f"--- DNS UDP Response ({domain}) ---\n")
            f.write(data.hex() + "\n")
    return parse_dns_response(data)

def dns_query_tcp(domain: str, server: Tuple[str, int], timeout: float, qtype: int = 1) -> List[str]:
    query = build_dns_query(domain, qtype)
    msg = struct.pack("!H", len(query)) + query
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        sock.connect(server)
        sock.sendall(msg)
        resp_len = sock.recv(2)
        if not resp_len: return []
        resp_len = struct.unpack("!H", resp_len)[0]
        data = b""
        while len(data) < resp_len:
            chunk = sock.recv(resp_len - len(data))
            if not chunk: break
            data += chunk

    if getattr(sys, '_export_packets', None):
        with open(sys._export_packets, 'a') as f:
            f.write(f"\n--- DNS TCP Query ({domain}) ---\n")
            f.write(msg.hex() + "\n")
            f.write(f"--- DNS TCP Response ({domain}) ---\n")
            f.write(data.hex() + "\n")
    return parse_dns_response(data)

def dns_query_doh(domain: str, doh_url: str, timeout: float, qtype: int = 1) -> List[str]:
    import base64
    query = build_dns_query(domain, qtype)
    b64 = base64.urlsafe_b64encode(query).rstrip(b"=").decode()
    headers = {"accept": "application/dns-message"}
    resp = requests.get(f"{doh_url}?dns={b64}", headers=headers, timeout=timeout)
    if resp.status_code == 200:
        return parse_dns_response(resp.content)
    return []

def dns_query_dot(domain: str, server: Tuple[str, int], timeout: float, qtype: int = 1) -> List[str]:
    import ssl
    query = build_dns_query(domain, qtype)
    msg = struct.pack("!H", len(query)) + query
    context = ssl.create_default_context()
    with socket.create_connection(server, timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=server[0]) as ssock:
            ssock.sendall(msg)
            resp_len = ssock.recv(2)
            if not resp_len: return []
            resp_len = struct.unpack("!H", resp_len)[0]
            data = b""
            while len(data) < resp_len:
                chunk = ssock.recv(resp_len - len(data))
                if not chunk: break
                data += chunk
    return parse_dns_response(data)

def dns_multi_protocol_test(console: Console, domain: str, timeout: float, servers: List[Tuple[str, int]], doh_urls: List[str], dot_servers: List[Tuple[str, int]]) -> TestResult:
    console.section("DNS Multi-Protocol Test")
    filtering_ips = ["10.10.34.34", "10.10.34.35", "10.10.34.36", "d0::11"]
    
    console.info("Known Iranian DNS filtering addresses:")
    for ip in filtering_ips:
        console.info(f"  {ip}  (used for censorship/hijacking)")
    
    results = {}
    
    # UDP/TCP tests
    for server in servers:
        try:
            results[f"UDP@{server[0]}:{server[1]}"] = dns_query_udp(domain, server, timeout)
            results[f"TCP@{server[0]}:{server[1]}"] = dns_query_tcp(domain, server, timeout)
        except Exception as exc:
            results[f"UDP@{server[0]}:{server[1]}"] = [f"ERR:{exc}"]
            results[f"TCP@{server[0]}:{server[1]}"] = [f"ERR:{exc}"]
            
    # DoH tests
    for doh_url in doh_urls:
        try:
            results[f"DoH@{doh_url}"] = dns_query_doh(domain, doh_url, timeout)
        except Exception as exc:
            results[f"DoH@{doh_url}"] = [f"ERR:{exc}"]
            
    # DoT tests
    for dot_server in dot_servers:
        try:
            results[f"DoT@{dot_server[0]}:{dot_server[1]}"] = dns_query_dot(domain, dot_server, timeout)
        except Exception as exc:
            results[f"DoT@{dot_server[0]}:{dot_server[1]}"] = [f"ERR:{exc}"]
            
    # Analysis
    all_ips = set()
    suspicious = False
    
    for proto, ips in results.items():
        for ip in ips:
            if not ip.startswith("ERR:"):
                all_ips.add(ip)
        
        found = [ip for ip in ips if ip in filtering_ips]
        if found:
            suspicious = True
            console.fail(f"{proto}: Suspicious filtering IP(s) detected: {found}")
        elif any(ip.startswith("ERR:") for ip in ips):
            console.warn(f"{proto}: Error: {ips}")
        else:
            console.ok(f"{proto}: {ips}")

    if suspicious:
        return TestResult("DNS-Multi", "FAIL", "Suspicious DNS answers detected")
    if not all_ips:
        return TestResult("DNS-Multi", "WARN", "No DNS answers received")
    return TestResult("DNS-Multi", "PASS", "No hijack detected")

def http_censorship_check(console: Console, domain: str, timeout: float, host_header: str = None, sni: str = None, ip: str = None, use_https: bool = False) -> TestResult:
    label = "HTTPS" if use_https else "HTTP"
    console.section(f"{label} Censorship Check")
    scheme = "https" if use_https else "http"
    target = ip if ip else domain
    url = f"{scheme}://{target}"
    headers = {"User-Agent": random.choice(USER_AGENTS)}
    if host_header:
        headers["Host"] = host_header

    try:
        if use_https:
            import urllib3
            from requests.adapters import HTTPAdapter
            from urllib3.util.ssl_ import create_urllib3_context
            
            class SNIAdapter(HTTPAdapter):
                def __init__(self, sni_hostname=None, **kwargs):
                    self.sni_hostname = sni_hostname
                    super().__init__(**kwargs)
                def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
                    context = create_urllib3_context()
                    pool_kwargs["ssl_context"] = context
                    if self.sni_hostname:
                        pool_kwargs["server_hostname"] = self.sni_hostname
                    return super().init_poolmanager(connections, maxsize, block, **pool_kwargs)
            
            session = requests.Session()
            if sni:
                session.mount(url, SNIAdapter(sni_hostname=sni))
            resp = session.get(url, timeout=timeout, headers=headers, verify=True)
        else:
            resp = requests.get(url, timeout=timeout, headers=headers)
        
        console.ok(f"{label} request succeeded with status {resp.status_code}.")
        return TestResult(label, "PASS", f"Status {resp.status_code}")
    except requests.exceptions.Timeout:
        console.fail("Connection timed out.")
        return TestResult(label, "FAIL", "Timeout")
    except requests.exceptions.ConnectionError as exc:
        message = str(exc).lower()
        if "reset" in message:
            console.filtered("Connection was reset (RST observed).")
            return TestResult(label, "FAIL", "RST observed")
        console.warn(f"Connection error: {exc}")
        return TestResult(label, "WARN", f"Connection error: {exc}")
    except Exception as exc:
        console.warn(f"Unexpected {label} error: {exc}")
        return TestResult(label, "WARN", f"Error: {exc}")

def tcp_reset_probe(console: Console, domain: str, port: int, timeout: float) -> TestResult:
    console.section("TCP Reset Probe")
    try:
        candidates = socket.getaddrinfo(domain, port, socket.AF_INET, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        console.warn(f"DNS resolution failed for {domain}: {exc}")
        return TestResult("TCP", "WARN", f"Resolution failed: {exc}")

    for family, socktype, proto, _, sockaddr in candidates:
        with socket.socket(family, socktype, proto) as sock:
            sock.settimeout(timeout)
            try:
                sock.connect(sockaddr)
                console.ok(f"TCP handshake to {sockaddr[0]}:{sockaddr[1]} completed.")
                return TestResult("TCP", "PASS", "Handshake completed")
            except ConnectionResetError:
                console.filtered("Connection was reset during handshake (RST observed).")
                return TestResult("TCP", "FAIL", "RST observed")
            except socket.timeout:
                console.fail("Connection attempt timed out.")
                return TestResult("TCP", "FAIL", "Timeout")
            except OSError as exc:
                console.warn(f"TCP probe error: {exc}")
                continue
    return TestResult("TCP", "WARN", "No reachable addresses")

def _download_speed(url: str, label: str, timeout: float, headers: Optional[Dict[str, str]] = None) -> Tuple[str, float, int, Optional[str]]:
    start = time.time()
    bytes_read = 0
    try:
        with requests.get(url, stream=True, timeout=timeout, headers=headers) as resp:
            resp.raise_for_status()
            for chunk in resp.iter_content(chunk_size=65536):
                if not chunk: continue
                bytes_read += len(chunk)
        duration = max(time.time() - start, 1e-6)
        kbps = (bytes_read / 1024) / duration
        return label, kbps, bytes_read, None
    except Exception as exc:
        return label, 0.0, bytes_read, str(exc)

def throttling_check(console: Console, timeout: float, concurrency: int = THROTTLE_CONCURRENCY) -> TestResult:
    console.section("Throttling Check (HTTP vs HTTPS)")
    headers = {"User-Agent": random.choice(USER_AGENTS)}
    tasks = [(SPEED_URL_HTTP, "HTTP"), (SPEED_URL_HTTPS, "HTTPS")]
    results = {}
    
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        future_map = {executor.submit(_download_speed, url, label, timeout, headers): label for url, label in tasks}
        for future in as_completed(future_map):
            label = future_map[future]
            results[label] = future.result()

    http, https = results.get("HTTP"), results.get("HTTPS")
    if not http or not https:
        console.warn("Throttling check failed to execute both tests.")
        return TestResult("Throttle", "WARN", "Incomplete tests")

    for label, kbps, bytes_read, err in (http, https):
        if err: console.warn(f"{label}: Error: {err}")
        else: console.info(f"{label}: {kbps:.2f} KB/s ({bytes_read} bytes)")

    if http[1] > 0 and https[1] > 0:
        ratio = http[1] / https[1]
        if ratio > 1.5:
            console.fail(f"HTTP is {ratio:.1f}x faster than HTTPS; likely throttled")
            return TestResult("Throttle", "FAIL", f"HTTP {ratio:.1f}x faster")
        elif ratio < 0.67:
            console.warn(f"HTTPS is {1/ratio:.1f}x faster than HTTP (unexpected)")
            return TestResult("Throttle", "WARN", f"HTTPS {1/ratio:.1f}x faster")
        else:
            console.ok(f"No significant throttling (ratio {ratio:.1f}x).")
            return TestResult("Throttle", "PASS", f"Ratio {ratio:.1f}x")
    return TestResult("Throttle", "WARN", "Speed test incomplete or failed")

def run_traceroute(domain: str, tcp: bool = False, max_hops: int = 20, timeout: float = 2.0) -> str:
    system = platform.system().lower()
    if system == "windows":
        if tcp: return "TCP traceroute not supported on Windows by default."
        cmd = ["tracert", "-h", str(max_hops), domain]
    else:
        cmd = ["traceroute", "-m", str(max_hops), "-w", str(timeout), domain]
        if tcp: cmd.insert(1, "--tcp")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout*max_hops)
        return result.stdout
    except Exception as exc:
        return f"Traceroute error: {exc}"

def run_ping(domain: str, count: int = 4, timeout: float = 2.0) -> str:
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", str(count), "-w", str(int(timeout*1000)), domain]
    else:
        cmd = ["ping", "-c", str(count), "-W", str(int(timeout)), domain]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout*count+2)
        return result.stdout
    except Exception as exc:
        return f"Ping error: {exc}"

def run_tcping(domain: str, port: int = 80, count: int = 4, timeout: float = 2.0) -> str:
    if platform.system().lower() == "windows":
        return "TCP ping not supported on Windows by default."
    cmd = ["hping3", "-S", "-p", str(port), "-c", str(count), domain]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout*count+2)
        return result.stdout
    except Exception as exc:
        return f"TCPing error: {exc}"

def summarize(console: Console, results: List[TestResult]) -> None:
    console.section("Summary Report")
    passes = sum(1 for r in results if r.status == "PASS")
    fails = sum(1 for r in results if r.status == "FAIL")
    warns = sum(1 for r in results if r.status == "WARN")
    
    for r in results:
        if r.status == "PASS": console.ok(f"{r.name}: {r.detail}")
        elif r.status == "FAIL": console.fail(f"{r.name}: {r.detail}")
        else: console.warn(f"{r.name}: {r.detail}")

    overall = "PASS" if fails == 0 else "FAIL"
    if overall == "PASS" and warns > 0: overall = "WARN"
    
    console.section("Overall Grade")
    color_map = {"PASS": Fore.GREEN, "WARN": Fore.YELLOW, "FAIL": Fore.RED}
    msg = f"Network Health: {overall} ({passes} pass, {warns} warn, {fails} fail)"
    print(f"{color_map.get(overall, '')}{msg}{Style.RESET_ALL}")

# --- Argument Parsing & Main ---

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="CensorTrace CLI - Censorship & hijacking diagnostic tool")
    parser.add_argument("--domain", default=DEFAULT_DOMAIN, help="Target domain (default: youtube.com)")
    parser.add_argument("--host-header", default=None, help="Custom Host header")
    parser.add_argument("--sni", default=None, help="Custom SNI for HTTPS")
    parser.add_argument("--http-ip", default=None, help="Direct IP for HTTP(S)")
    parser.add_argument("--tls-port", type=int, default=DEFAULT_TLS_PORT, help="TLS port")
    parser.add_argument("--dns-timeout", type=float, default=DNS_TIMEOUT)
    parser.add_argument("--http-timeout", type=float, default=HTTP_TIMEOUT)
    parser.add_argument("--tls-timeout", type=float, default=TLS_TIMEOUT)
    parser.add_argument("--throttle-timeout", type=float, default=THROTTLE_TIMEOUT)
    parser.add_argument("--throttle-concurrency", type=int, default=THROTTLE_CONCURRENCY)
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("--fake-dns-server", default=DEFAULT_FAKE_DNS_SERVER, help="Fake DNS server")
    parser.add_argument("--quiet", action="store_true", help="Suppress output except errors/JSON")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    parser.add_argument("--traceroute", action="store_true", help="Run UDP traceroute")
    parser.add_argument("--traceroute-tcp", action="store_true", help="Run TCP traceroute")
    parser.add_argument("--ping", action="store_true", help="Run ICMP ping")
    parser.add_argument("--tcping", action="store_true", help="Run TCP ping")
    parser.add_argument("--export-packets", default=None, help="Export packets to file")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser.parse_args()

def main():
    args = parse_args()
    console = Console(use_color=not args.no_color, quiet=args.quiet)

    # Packet Export Setup
    if args.export_packets:
        sys._export_packets = args.export_packets
        with open(args.export_packets, 'w') as f:
            f.write(f"# CensorTrace Packet Export - {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
    else:
        sys._export_packets = None

    # Safety/Admin Check
    if sys.stdin and sys.stdin.isatty():
        console.section("Safety Notice")
        if os.name == "nt":
            try:
                import ctypes
                is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            except: is_admin = False
        else:
            is_admin = (os.geteuid() == 0) if hasattr(os, "geteuid") else False
        
        if is_admin:
            console.warn("Running as root/admin. Only test networks you have permission to test.")
        console.info("Tests run locally. No data sent to external servers.")

    # Parse Fake DNS
    try:
        host, port = args.fake_dns_server.split(":")
        global FAKE_DNS_SERVER
        FAKE_DNS_SERVER = (host, int(port))
    except:
        sys.exit("Invalid --fake-dns-server format. Use host:port")

    dns_servers = [FAKE_DNS_SERVER, ("8.8.8.8", 53), ("1.1.1.1", 53)]
    doh_urls = ["https://cloudflare-dns.com/dns-query", "https://dns.google/dns-query"]
    dot_servers = [("1.1.1.1", 853), ("8.8.8.8", 853)]

    # Main Loop
    while True:
        domain = args.domain
        
        # Interactive Prompt
        if sys.stdin and sys.stdin.isatty() and (not args.domain or args.domain == DEFAULT_DOMAIN):
            try:
                user_input = input(f"Enter target domain [{DEFAULT_DOMAIN}] (or Ctrl+C to exit): ").strip()
                if user_input: domain = user_input
            except (EOFError, KeyboardInterrupt):
                print("\nExiting.")
                break
        
        if sys.stdin and sys.stdin.isatty():
            console.info("Press Enter to start...")
            try: input()
            except: break

        results = []
        
        # 1. DNS Tests
        results.append(dns_multi_protocol_test(console, domain, args.dns_timeout, dns_servers, doh_urls, dot_servers))
        
        # Optional Dig-Style Diagnostic
        if sys.stdin and sys.stdin.isatty():
            try:
                dig = input("\nShow dig-style DNS details? (y/N): ").strip().lower()
                if dig == 'y':
                    dig_style_dns_query(console, domain, dns_servers[0], args.dns_timeout)
            except: pass

        # 2. HTTP/HTTPS Censorship
        results.append(http_censorship_check(console, domain, args.http_timeout, args.host_header, args.sni, args.http_ip, False))
        results.append(http_censorship_check(console, domain, args.http_timeout, args.host_header, args.sni, args.http_ip, True))

        # 3. TCP Reset
        results.append(tcp_reset_probe(console, domain, args.tls_port, args.tls_timeout))

        # 4. Throttling
        results.append(throttling_check(console, args.throttle_timeout, args.throttle_concurrency))

        # 5. Traceroute/Ping
        if args.traceroute:
            console.section("Traceroute (UDP)")
            results.append(TestResult("Traceroute-UDP", "INFO", run_traceroute(domain, tcp=False)[:5000]))
        if args.traceroute_tcp:
            console.section("Traceroute (TCP)")
            results.append(TestResult("Traceroute-TCP", "INFO", run_traceroute(domain, tcp=True)[:5000]))
        if args.ping:
            console.section("ICMP Ping")
            results.append(TestResult("Ping", "INFO", run_ping(domain)[:5000]))
        if args.tcping:
            console.section("TCP Ping")
            results.append(TestResult("TCPing", "INFO", run_tcping(domain)[:5000]))

        # Output
        if args.json:
            import json
            print(json.dumps([{"name": r.name, "status": r.status, "detail": r.detail} for r in results], indent=2))
        else:
            summarize(console, results)

        # Loop Control
        if sys.stdin and sys.stdin.isatty():
            try:
                if input("\nTest another domain? (y/N): ").strip().lower() != 'y':
                    break
            except: break
        else:
            break

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("\nInterrupted by user.")
