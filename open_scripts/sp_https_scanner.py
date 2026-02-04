# MIT License – Copyright (c) 2025 Menny Levinski

"""
Mini HTTPS security scanner (port 443 only).

Checks:
- Reachability
- Latency
- TLS version
- Cipher suite
- Certificate issuer / subject / expiration
"""

import socket
import ssl
import time
import re
from urllib.parse import urlparse


def check_transmission_port(url: str, timeout: int = 4):
    parsed = urlparse(url)
    host = parsed.hostname
    port = 443  # HTTPS only

    start_time = time.time()

    try:
        # TCP connection
        sock = socket.create_connection((host, port), timeout)
        latency = (time.time() - start_time) * 1000  # ms

        context = ssl.create_default_context()
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            tls_version = ssock.version()
            cipher = ssock.cipher()  # (cipher_name, protocol, key_bits)

            cert = ssock.getpeercert()
            issuer = dict(x[0] for x in cert.get("issuer", ()))
            subject = dict(x[0] for x in cert.get("subject", ()))
            expires = cert.get("notAfter")

        sock.close()

        return {
            "host": host,
            "port": port,
            "reachable": True,
            "latency_ms": round(latency, 2),
            "tls_version": tls_version,
            "cipher": cipher,
            "certificate": {
                "issuer": issuer,
                "subject": subject,
                "expires": expires
            },
            "error": None,
        }

    except Exception as e:
        return {
            "host": host,
            "port": port,
            "reachable": False,
            "latency_ms": None,
            "tls_version": None,
            "cipher": None,
            "certificate": None,
            "error": str(e),
        }


def is_valid_host(host: str) -> bool:
    if not host:
        return False

    # IPv4
    ipv4_pattern = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
    if ipv4_pattern.match(host):
        return all(0 <= int(octet) <= 255 for octet in host.split("."))

    # IPv6 (basic check)
    if ":" in host:
        return True

    # Hostname
    hostname_pattern = re.compile(
        r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z]{2,})+$"
    )
    return bool(hostname_pattern.match(host))


def print_certificate_info(cert):
    if not cert:
        print("certificate: None")
        return

    print("certificate:")
    print("  issuer:")
    for k, v in cert.get("issuer", {}).items():
        print(f"    {k}: {v}")

    print("  subject:")
    for k, v in cert.get("subject", {}).items():
        print(f"    {k}: {v}")

    print(f"  expires: {cert.get('expires')}")


def print_result_vertical(result: dict):
    print("\n--- HTTPS Transmission Check (Port 443) ---")
    print(f"host: {result['host']}")
    print(f"port: {result['port']}")
    print(f"reachable: {result['reachable']}")

    if result["latency_ms"] is not None:
        print(f"latency_ms: {result['latency_ms']}")

    if result["tls_version"]:
        print(f"tls_version: {result['tls_version']}")

    if result["cipher"]:
        name, protocol, bits = result["cipher"]
        print("cipher:")
        print(f"  name: {name}")
        print(f"  protocol: {protocol}")
        print(f"  key_bits: {bits}")

    print_certificate_info(result["certificate"])

    if result["error"]:
        print(f"error: {result['error']}")


# --- CLI ---
if __name__ == "__main__":
    while True:
        test_url = input("Enter URL to check (e.g., https://example.com): ").strip()
        if not test_url:
            test_url = "https://example.com"

        if "://" not in test_url:
            test_url = "https://" + test_url

        host = urlparse(test_url).hostname
        if not is_valid_host(host):
            print(f"[ERROR] Invalid host: {host}\n")
            continue

        result = check_transmission_port(test_url)
        print_result_vertical(result)
        break

    input("\nPress Enter to exit...")
