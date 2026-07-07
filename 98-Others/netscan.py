import argparse
import ipaddress
import json
import re
import socket
import ssl
import sys

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

import requests
import urllib3
from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TLS_PORTS = {443}
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def main():
    args = parse_args()
    try:
        check_args(args)
    except ValueError as e:
        sys.exit(f"Error: {e}")

    cidr = args.cidr or detect_local_cidr()
    if cidr is None:
        sys.exit("Error: cannot auto-detect local network, use --cidr")

    network = ipaddress.ip_network(cidr, strict=False)
    hosts = [str(ip) for ip in network.hosts()]
    ports = args.ports

    print(f"[*] Target   : {network} ({len(hosts)} hosts)")
    print(f"[*] Ports    : {', '.join(str(p) for p in ports)}")
    print(f"[*] Timeout  : {args.timeout}s | Workers: {args.workers}")
    print("[*] Phase 1: discovery ...")

    open_map = discover(hosts, ports, args.timeout, args.workers)
    if not open_map:
        print("[-] No host responding on the given ports.")
        return

    print(f"[+] {len(open_map)} host(s) with at least one open port.")
    print("[*] Phase 2: enrichment ...")

    results = enrich(open_map, args.timeout, args.workers)
    results.sort(key=lambda r: ipaddress.ip_address(r["ip"]))

    report_console(results)
    if args.output:
        export_json(results, args.output)
        print(f"\n[+] Results written to {args.output}")


def parse_args():
    parser = argparse.ArgumentParser(description="netscan.py - web host discovery on ports 80/443")
    parser.add_argument("--cidr", help="Target network in CIDR (default: auto-detect local /24)")
    parser.add_argument("--ports", default="80,443", help="Comma-separated ports (default: 80,443)")
    parser.add_argument("--timeout", type=float, default=1.5, help="Per-connection timeout in seconds")
    parser.add_argument("--workers", type=int, default=100, help="Number of concurrent threads")
    parser.add_argument("-o", "--output", help="Write results to a JSON file")
    args = parser.parse_args()
    args.ports = parse_ports(args.ports)
    return args


def parse_ports(raw):
    ports = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        ports.append(int(part))
    return ports


def check_args(args):
    if args.cidr:
        try:
            ipaddress.ip_network(args.cidr, strict=False)
        except ValueError:
            raise ValueError(f"invalid CIDR: {args.cidr}")
    if not args.ports:
        raise ValueError("no valid port provided")
    for p in args.ports:
        if not 0 < p < 65536:
            raise ValueError(f"port out of range: {p}")
    if args.timeout <= 0:
        raise ValueError("timeout must be > 0")
    if args.workers < 1:
        raise ValueError("workers must be >= 1")


def detect_local_cidr():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()
    return f"{local_ip}/24"


def discover(hosts, ports, timeout, workers):
    """Return {ip: [open_ports]} for hosts answering on any target port."""
    open_map = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(scan_port, ip, port, timeout): (ip, port)
            for ip in hosts
            for port in ports
        }
        for future in as_completed(futures):
            ip, port = futures[future]
            if future.result():
                open_map.setdefault(ip, []).append(port)
    for ip in open_map:
        open_map[ip].sort()
    return open_map


def scan_port(ip, port, timeout):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def enrich(open_map, timeout, workers):
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(build_result, ip, ports, timeout): ip
            for ip, ports in open_map.items()
        }
        return [future.result() for future in as_completed(futures)]


def build_result(ip, ports, timeout):
    result = {"ip": ip, "ports": {}}
    for port in ports:
        entry = probe_http(ip, port, timeout)
        if port in TLS_PORTS:
            entry["tls"] = get_tls_cert(ip, port, timeout)
        result["ports"][str(port)] = entry
    return result


def probe_http(ip, port, timeout):
    scheme = "https" if port in TLS_PORTS else "http"
    url = f"{scheme}://{ip}:{port}/"
    entry = {"url": url, "status": None, "server": None, "title": None,
             "redirects": [], "error": None}
    try:
        resp = requests.get(url, timeout=timeout, verify=False, allow_redirects=True)
    except requests.exceptions.RequestException as e:
        entry["error"] = str(e)
        return entry

    first = resp.history[0] if resp.history else resp
    entry["status"] = resp.status_code
    entry["server"] = first.headers.get("Server")
    entry["title"] = extract_title(resp.text)
    entry["redirects"] = [
        {"status": h.status_code, "location": h.headers.get("Location")}
        for h in resp.history
    ]
    return entry


def extract_title(html):
    match = TITLE_RE.search(html or "")
    if not match:
        return None
    return re.sub(r"\s+", " ", match.group(1)).strip() or None


def get_tls_cert(ip, port, timeout):
    tls = {"tls_version": None, "subject_cn": None, "san": [], "issuer": None,
           "not_before": None, "not_after": None, "error": None}
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as tls_sock:
                tls["tls_version"] = tls_sock.version()
                der = tls_sock.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError) as e:
        tls["error"] = str(e)
        return tls

    if not der:
        tls["error"] = "no certificate presented"
        return tls

    try:
        cert = x509.load_der_x509_certificate(der)
    except ValueError as e:
        tls["error"] = f"cannot parse certificate: {e}"
        return tls

    tls["subject_cn"] = _name_cn(cert.subject)
    tls["issuer"] = _name_cn(cert.issuer)
    tls["san"] = _get_san(cert)
    tls["not_before"] = _iso(cert.not_valid_before_utc)
    tls["not_after"] = _iso(cert.not_valid_after_utc)
    return tls


def _name_cn(name):
    attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return attrs[0].value if attrs else None


def _get_san(cert):
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    except x509.ExtensionNotFound:
        return []
    return ext.value.get_values_for_type(x509.DNSName)


def _iso(value):
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat()


def report_console(results):
    print("\n" + "=" * 60)
    for result in results:
        print(f"\n[HOST] {result['ip']}")
        for port, entry in result["ports"].items():
            if entry.get("error") and entry.get("status") is None:
                print(f"  [{port}] connection ok, HTTP error: {entry['error']}")
                _print_tls(entry.get("tls"))
                continue
            print(f"  [{port}] HTTP {entry['status']}  {entry['url']}")
            if entry.get("server"):
                print(f"        Server : {entry['server']}")
            if entry.get("title"):
                print(f"        Title  : {entry['title']}")
            for redir in entry.get("redirects", []):
                print(f"        {redir['status']} -> {redir['location']}")
            _print_tls(entry.get("tls"))
    print("\n" + "=" * 60)


def _print_tls(tls):
    if not tls:
        return
    if tls.get("error"):
        print(f"        TLS    : error ({tls['error']})")
        return
    print(f"        TLS    : {tls.get('tls_version')} | CN={tls.get('subject_cn')} | issuer={tls.get('issuer')}")
    if tls.get("san"):
        print(f"        SAN    : {', '.join(tls['san'])}")
    print(f"        Valid  : {tls.get('not_before')} -> {tls.get('not_after')}")


def export_json(results, path):
    payload = {
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "hosts": results,
    }
    with open(path, "w") as f:
        json.dump(payload, f, indent=2)


if __name__ == "__main__":
    main()
