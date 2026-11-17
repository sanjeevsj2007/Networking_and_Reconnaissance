#!/usr/bin/env python3
"""
Task 3 - Networking & Reconnaissance
====================================
Learn core networking concepts and practice BASIC reconnaissance using only
the Python standard library.

Concepts covered
----------------
* IP addresses  - IPv4/IPv6, public vs private, loopback (ipaddress module)
* DNS           - name -> IP resolution, record types (A, AAAA, MX, NS, TXT)
* Ports         - 0-65535; well-known ports 0-1023; TCP vs UDP
* Protocols     - HTTP, HTTPS, SSH, FTP, SMTP, DNS, etc.
* Recon         - WHOIS, DNS lookups, HTTP headers, light TCP connect checks

ETHICS & LEGALITY
-----------------
Passive recon (DNS, WHOIS, public HTTP headers) uses public information.
Port probing touches the target directly, so ONLY do it against systems you
own or have written permission to test. Safe practice targets:
    * 127.0.0.1                (your own machine)
    * your Task 2 lab VMs      (e.g. Metasploitable on the internal network)
    * scanme.nmap.org          (the Nmap project explicitly allows light scans)

Usage
-----
    python task3_networking_recon.py learn
    python task3_networking_recon.py ip 192.168.1.10
    python task3_networking_recon.py dns example.com
    python task3_networking_recon.py whois example.com
    python task3_networking_recon.py headers https://example.com
    python task3_networking_recon.py ports scanme.nmap.org --yes
    python task3_networking_recon.py full example.com
"""

import argparse
import ipaddress
import shutil
import socket
import ssl
import subprocess
import sys
import urllib.request
from concurrent.futures import ThreadPoolExecutor

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "MS-RPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 8080: "HTTP-alt", 8443: "HTTPS-alt",
}

SAFE_DEFAULTS = {"127.0.0.1", "localhost", "scanme.nmap.org"}


# --------------------------------------------------------------------------
# 1. Concepts
# --------------------------------------------------------------------------
LESSON = """\
NETWORKING FUNDAMENTALS
=======================
IP ADDRESS  Numeric label of a host. IPv4 = 4 bytes (192.168.1.5),
            IPv6 = 128 bits. Private ranges (10.0.0.0/8, 172.16.0.0/12,
            192.168.0.0/16) are not routable on the internet.
DNS         The 'phonebook of the internet': turns example.com into an IP.
            Records: A (IPv4), AAAA (IPv6), MX (mail), NS (name servers),
            TXT (SPF/verification), CNAME (alias).
PORT        A 16-bit number identifying a service on a host. IP gets the
            packet to the machine; the port gets it to the application.
TCP / UDP   TCP = reliable, connection-oriented (3-way handshake:
            SYN -> SYN/ACK -> ACK). UDP = fast, connectionless (DNS, VoIP).
PROTOCOLS   Rules for communication: HTTP/HTTPS (web), SSH (secure shell),
            FTP (files), SMTP (mail), DNS (names).
OSI/TCP-IP  Application > Transport > Internet > Link: each layer wraps
            data from the one above.

RECON PHASES
============
Passive : no direct contact with target (WHOIS, DNS, search engines)
Active  : touches the target (port probes, banner grabbing) - needs consent
"""


def cmd_learn(_):
    print(LESSON)
    print("WELL-KNOWN PORTS USED IN THIS SCRIPT")
    for port, name in sorted(COMMON_PORTS.items()):
        print(f"  {port:>5}  {name}")


# --------------------------------------------------------------------------
# 2. IP analysis
# --------------------------------------------------------------------------
def cmd_ip(args):
    try:
        ip = ipaddress.ip_address(args.address)
    except ValueError:
        sys.exit(f"[!] '{args.address}' is not a valid IP address")
    print(f"Address    : {ip}")
    print(f"Version    : IPv{ip.version}")
    print(f"Private    : {ip.is_private}")
    print(f"Loopback   : {ip.is_loopback}")
    print(f"Multicast  : {ip.is_multicast}")
    print(f"Global     : {ip.is_global}")
    try:
        print(f"Reverse DNS: {socket.gethostbyaddr(str(ip))[0]}")
    except OSError:
        print("Reverse DNS: (none)")


# --------------------------------------------------------------------------
# 3. DNS
# --------------------------------------------------------------------------
def resolve_ips(domain):
    try:
        infos = socket.getaddrinfo(domain, None)
    except socket.gaierror as e:
        sys.exit(f"[!] Could not resolve {domain}: {e}")
    return sorted({i[4][0] for i in infos})


def cmd_dns(args):
    print(f"== DNS: {args.domain} ==")
    for ip in resolve_ips(args.domain):
        kind = "AAAA" if ":" in ip else "A"
        print(f"  {kind:<5} {ip}")

    tool = shutil.which("dig")
    if tool:
        for rtype in ("MX", "NS", "TXT"):
            out = subprocess.run([tool, "+short", rtype, args.domain],
                                 capture_output=True, text=True).stdout.strip()
            print(f"  {rtype}:")
            print("    " + (out.replace("\n", "\n    ") if out else "(none)"))
    elif shutil.which("nslookup"):
        for rtype in ("MX", "NS", "TXT"):
            out = subprocess.run(["nslookup", f"-type={rtype}", args.domain],
                                 capture_output=True, text=True).stdout
            print(f"  --- {rtype} ---\n{out.strip()}")
    else:
        print("  (install 'dig' or 'nslookup' to see MX/NS/TXT records)")


# --------------------------------------------------------------------------
# 4. WHOIS (raw protocol on TCP/43 - nice demo of a simple protocol)
# --------------------------------------------------------------------------
def whois_query(server, query):
    with socket.create_connection((server, 43), timeout=10) as s:
        s.sendall((query + "\r\n").encode())
        data = b""
        while chunk := s.recv(4096):
            data += chunk
    return data.decode(errors="replace")


def cmd_whois(args):
    print(f"== WHOIS: {args.domain} ==")
    try:
        text = whois_query("whois.iana.org", args.domain)
        refer = next((l.split(":", 1)[1].strip() for l in text.splitlines()
                      if l.lower().startswith("refer:")), None)
        if refer:
            text = whois_query(refer, args.domain)
    except OSError as e:
        sys.exit(f"[!] WHOIS failed: {e}")
    keys = ("domain name", "registrar", "creation date", "updated date",
            "expir", "name server", "status", "org")
    shown = [l for l in text.splitlines() if any(l.lower().strip().startswith(k) for k in keys)]
    print("\n".join(shown[:25]) or text[:1500])


# --------------------------------------------------------------------------
# 5. HTTP headers & TLS
# --------------------------------------------------------------------------
def cmd_headers(args):
    url = args.url if "://" in args.url else "https://" + args.url
    print(f"== HTTP headers: {url} ==")
    req = urllib.request.Request(url, method="HEAD",
                                 headers={"User-Agent": "learning-recon/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            print(f"Status: {r.status} {r.reason}")
            for k, v in r.getheaders():
                print(f"  {k}: {v}")
            interesting = ["Strict-Transport-Security", "Content-Security-Policy",
                           "X-Frame-Options", "X-Content-Type-Options"]
            missing = [h for h in interesting if r.headers.get(h) is None]
            if missing:
                print("\nMissing security headers:", ", ".join(missing))
    except Exception as e:
        sys.exit(f"[!] Request failed: {e}")

    host = url.split("://", 1)[1].split("/")[0].split(":")[0]
    if url.startswith("https"):
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=10) as s:
                with ctx.wrap_socket(s, server_hostname=host) as t:
                    cert = t.getpeercert()
                    print(f"\nTLS version : {t.version()}")
                    print(f"Cert expires: {cert.get('notAfter')}")
                    issuer = dict(x[0] for x in cert.get("issuer", ()))
                    print(f"Issuer      : {issuer.get('organizationName', '?')}")
        except Exception as e:
            print(f"\nTLS check failed: {e}")


# --------------------------------------------------------------------------
# 6. Light TCP connect check (ACTIVE - consent required)
# --------------------------------------------------------------------------
def probe(host, port, timeout=1.0):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return port, True
    except OSError:
        return port, False


def cmd_ports(args):
    host = args.host
    if host not in SAFE_DEFAULTS and not args.yes:
        print(f"[!] '{host}' is not a pre-approved practice target.")
        print("    Port probing is ACTIVE recon. Only proceed if you own it or have")
        print("    written permission. Re-run with --yes to confirm.")
        sys.exit(1)

    print(f"== TCP connect check on {host} ({len(COMMON_PORTS)} common ports) ==")
    ip = resolve_ips(host)[0]
    print(f"Resolved to {ip}\n")
    with ThreadPoolExecutor(max_workers=10) as ex:   # modest concurrency
        results = sorted(ex.map(lambda p: probe(ip, p), COMMON_PORTS))
    open_ports = [p for p, ok in results if ok]
    for p in open_ports:
        print(f"  {p:>5}/tcp  OPEN   {COMMON_PORTS[p]}")
    if not open_ports:
        print("  No common ports open (or they are filtered).")
    print("\nNote: a connect check shows reachable ports only; real tools "
          "like Nmap give far deeper results.")


# --------------------------------------------------------------------------
def cmd_full(args):
    """Passive recon bundle: DNS + WHOIS + headers (no port probing)."""
    ns = argparse.Namespace(domain=args.domain, url=args.domain)
    for fn in (cmd_dns, cmd_whois, cmd_headers):
        fn(ns)
        print()


def main():
    p = argparse.ArgumentParser(description="Networking & reconnaissance basics")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("learn", help="print networking concepts").set_defaults(fn=cmd_learn)

    a = sub.add_parser("ip", help="analyse an IP address"); a.add_argument("address"); a.set_defaults(fn=cmd_ip)
    d = sub.add_parser("dns", help="DNS lookups"); d.add_argument("domain"); d.set_defaults(fn=cmd_dns)
    w = sub.add_parser("whois", help="WHOIS registration data"); w.add_argument("domain"); w.set_defaults(fn=cmd_whois)
    h = sub.add_parser("headers", help="HTTP headers + TLS info"); h.add_argument("url"); h.set_defaults(fn=cmd_headers)

    pt = sub.add_parser("ports", help="TCP connect check (needs authorization)")
    pt.add_argument("host")
    pt.add_argument("--yes", action="store_true", help="I am authorized to test this host")
    pt.set_defaults(fn=cmd_ports)

    f = sub.add_parser("full", help="passive recon bundle"); f.add_argument("domain"); f.set_defaults(fn=cmd_full)

    args = p.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
