# MIT License – Copyright (c) 2025 Menahem Levinski

"""
HTTPS security scanner (port 443 only).

Checks:
- Reachability
- Latency
- TLS version
- Supported TLS versions
- Cipher suite
- ALPN
- Certificate trust
- Certificate issuer / subject
- Certificate validity
- Hostname validation
- SAN
- SHA-256 fingerprint
- RSA key strength
- Self-signed certificate
- Deprecated TLS versions
- Weak cipher suites
"""

import socket
import ssl
import time
import re
import hashlib
import warnings
from datetime import datetime, timezone
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa

warnings.filterwarnings(
    "ignore",
    message=r"ssl\.TLSVersion\.TLSv1(_1)? is deprecated",
    category=DeprecationWarning
)

def check_tls_protocol_support(host: str, timeout: int = 4):
    supported_versions = []

    versions = [
        ("TLSv1.0", ssl.TLSVersion.TLSv1),
        ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
        ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
        ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
    ]

    for version_name, version in versions:

        sock = None

        try:
            context = ssl.SSLContext(
                ssl.PROTOCOL_TLS_CLIENT
            )

            context.minimum_version = version
            context.maximum_version = version

            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            # Allow legacy TLS protocols for capability testing.
            if version in (
                ssl.TLSVersion.TLSv1,
                ssl.TLSVersion.TLSv1_1,
            ):
                context.set_ciphers(
                    "DEFAULT:@SECLEVEL=0"
                )

            sock = socket.create_connection(
                (host, 443),
                timeout=timeout
            )

            with context.wrap_socket(
                sock,
                server_hostname=host
            ) as tls_sock:

                negotiated = tls_sock.version()

                if negotiated in (
                    version_name,
                    "TLSv1" if version_name == "TLSv1.0"
                    else version_name
                ):
                    supported_versions.append(
                        version_name
                    )

        except (ssl.SSLError, OSError):
            pass

        finally:

            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass

    return supported_versions


def check_transmission_port(url: str, timeout: int = 4):

    parsed = urlparse(url)
    host = parsed.hostname
    port = 443

    result = {
        "host": host,
        "port": port,
        "reachable": False,
        "latency_ms": None,
        "tls_version": None,
        "supported_tls_versions": [],
        "cipher": None,
        "alpn": None,
        "certificate": None,
        "findings": [],
        "verdict": "SECURE",
        "error": None,
    }

    if not host:
        result["error"] = "Invalid host"
        return result

    # DNS resolution
    try:
        addresses = socket.getaddrinfo(
            host,
            port,
            type=socket.SOCK_STREAM
        )

        ips = []

        for item in addresses:
            ip = item[4][0]

            if ip not in ips:
                ips.append(ip)

        result["resolved_ips"] = ips

    except socket.gaierror:
        result["error"] = (
            f"DNS resolution failed for {host}"
        )
        return result

    # TLS connection
    sock = None

    try:

        context = ssl.create_default_context()

        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED

        context.set_alpn_protocols(
            ["h2", "http/1.1"]
        )

        start_time = time.perf_counter()

        sock = socket.create_connection(
            (host, port),
            timeout=timeout
        )

        result["latency_ms"] = round(
            (time.perf_counter() - start_time) * 1000,
            2
        )

        try:

            # Normal secure TLS connection
            with context.wrap_socket(
                sock,
                server_hostname=host
            ) as ssock:

                result["reachable"] = True

                result["tls_version"] = (
                    ssock.version()
                )

                result["cipher"] = (
                    ssock.cipher()
                )

                result["alpn"] = (
                    ssock.selected_alpn_protocol()
                )

                cert_der = ssock.getpeercert(
                    binary_form=True
                )

                cert_obj = (
                    x509.load_der_x509_certificate(
                        cert_der
                    )
                )

                result["certificate_obj"] = cert_obj

                result["certificate_trusted"] = True
                result["hostname_valid"] = True

                result["fingerprint"] = (
                    hashlib.sha256(cert_der)
                    .hexdigest()
                    .upper()
                )

        except ssl.SSLCertVerificationError as e:

            # Certificate validation failed.
            result["reachable"] = False
            result["certificate_trusted"] = False
            result["ssl_error"] = str(e)

            error_text = str(e).lower()

            if (
                "self-signed certificate" in error_text
                or "unable to get local issuer certificate"
                in error_text
                or "unable to get issuer certificate"
                in error_text
            ):
                result["findings"].append(
                    "Certificate chain is not trusted"
                )

            # Diagnostic connection.
            diagnostic_context = (
                ssl.create_default_context()
            )

            diagnostic_context.check_hostname = False
            diagnostic_context.verify_mode = ssl.CERT_NONE

            try:
                diagnostic_context.set_ciphers(
                    "DEFAULT:@SECLEVEL=0"
                )
            except ssl.SSLError:
                pass

            diagnostic_sock = None

            try:

                diagnostic_sock = socket.create_connection(
                    (host, port),
                    timeout=timeout
                )

                with diagnostic_context.wrap_socket(
                    diagnostic_sock,
                    server_hostname=host
                ) as ssock:

                    result["tls_version"] = (
                        ssock.version()
                    )

                    result["cipher"] = (
                        ssock.cipher()
                    )

                    result["alpn"] = (
                        ssock.selected_alpn_protocol()
                    )

                    cert_der = ssock.getpeercert(
                        binary_form=True
                    )

                    cert_obj = (
                        x509.load_der_x509_certificate(
                            cert_der
                        )
                    )

                    result["certificate_obj"] = cert_obj

                    result["fingerprint"] = (
                        hashlib.sha256(cert_der)
                        .hexdigest()
                        .upper()
                    )

            except (ssl.SSLError, OSError) as diagnostic_error:

                result["diagnostic_error"] = str(
                    diagnostic_error
                )

            finally:

                if diagnostic_sock is not None:
                    try:
                        diagnostic_sock.close()
                    except Exception:
                        pass

        except ssl.SSLError as e:

            # Normal TLS handshake failed.
            result["ssl_error"] = str(e)

            # Try a legacy-compatible diagnostic connection.
            legacy_sock = None

            try:

                legacy_context = ssl.SSLContext(
                    ssl.PROTOCOL_TLS_CLIENT
                )

                legacy_context.check_hostname = False
                legacy_context.verify_mode = ssl.CERT_NONE

                legacy_context.minimum_version = (
                    ssl.TLSVersion.TLSv1
                )

                legacy_context.maximum_version = (
                    ssl.TLSVersion.TLSv1_3
                )

                legacy_context.set_ciphers(
                    "DEFAULT:@SECLEVEL=0"
                )

                legacy_sock = socket.create_connection(
                    (host, port),
                    timeout=timeout
                )

                with legacy_context.wrap_socket(
                    legacy_sock,
                    server_hostname=host
                ) as ssock:

                    result["reachable"] = True

                    result["tls_version"] = (
                        ssock.version()
                    )

                    result["cipher"] = (
                        ssock.cipher()
                    )

                    result["alpn"] = (
                        ssock.selected_alpn_protocol()
                    )

                    cert_der = ssock.getpeercert(
                        binary_form=True
                    )

                    cert_obj = (
                        x509.load_der_x509_certificate(
                            cert_der
                        )
                    )

                    result["certificate_obj"] = cert_obj

                    result["fingerprint"] = (
                        hashlib.sha256(cert_der)
                        .hexdigest()
                        .upper()
                    )

            except (ssl.SSLError, OSError) as legacy_error:

                result["legacy_cipher_error"] = str(
                    legacy_error
                )

                result["findings"].append(
                    "TLS handshake failed, unsupported cipher"
                )

            finally:

                if legacy_sock is not None:
                    try:
                        legacy_sock.close()
                    except Exception:
                        pass

        finally:

            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass

    except (OSError, ssl.SSLError) as e:

        result["error"] = str(e)
        return result

    # Certificate information
    cert_obj = result.get(
        "certificate_obj"
    )

    if cert_obj:

        result["certificate"] = {}

        result["certificate"]["subject"] = (
            cert_obj.subject.rfc4514_string()
        )

        result["certificate"]["issuer"] = (
            cert_obj.issuer.rfc4514_string()
        )

        result["certificate"]["not_before"] = (
            cert_obj.not_valid_before_utc
        )

        result["certificate"]["not_after"] = (
            cert_obj.not_valid_after_utc
        )

        # RSA key strength
        public_key = cert_obj.public_key()

        if isinstance(public_key, rsa.RSAPublicKey):

            result["certificate"]["key_type"] = "RSA"
            result["certificate"]["key_bits"] = (
                public_key.key_size
            )

            if public_key.key_size < 2048:

                result["findings"].append(
                    f"Weak RSA key: "
                    f"{public_key.key_size} bits"
                )

        else:

            result["certificate"]["key_type"] = (
                type(public_key).__name__
            )

        # SAN
        try:

            san_ext = (
                cert_obj.extensions
                .get_extension_for_class(
                    x509.SubjectAlternativeName
                )
            )

            san = (
                san_ext.value.get_values_for_type(
                    x509.DNSName
                )
            )

            result["certificate"]["san"] = san

        except x509.ExtensionNotFound:

            result["certificate"]["san"] = []

        # Self-signed
        result["certificate"]["self_signed"] = (
            cert_obj.subject == cert_obj.issuer
        )

        if result["certificate"]["self_signed"]:

            result["findings"].append(
                "Self-signed certificate"
            )

        # Certificate validity
        not_before = (
            cert_obj.not_valid_before_utc
        )

        not_after = (
            cert_obj.not_valid_after_utc
        )

        now = datetime.now(
            timezone.utc
        )

        if now < not_before:

            result["findings"].append(
                "Certificate is not yet valid"
            )

        elif now >= not_after:

            result["findings"].append(
                "Certificate has expired"
            )

            result["certificate"]["days_remaining"] = 0

        else:

            days_remaining = (
                not_after - now
            ).days

            result["certificate"]["days_remaining"] = (
                days_remaining
            )

            if days_remaining <= 30:

                result["findings"].append(
                    f"Certificate expires in "
                    f"{days_remaining} days"
                )

        # Hostname validation
        if result.get("certificate_trusted"):

            result["hostname_valid"] = True

        else:

            hostname_valid = False

            san_names = result["certificate"].get(
                "san",
                []
            )

            host_lower = host.lower()

            for san_name in san_names:

                san_name = san_name.lower()

                if san_name == host_lower:

                    hostname_valid = True
                    break

                if san_name.startswith("*."):

                    suffix = san_name[1:]

                    if (
                        host_lower.endswith(suffix)
                        and host_lower.count(".")
                        == suffix.count(".")
                    ):

                        hostname_valid = True
                        break

            result["hostname_valid"] = (
                hostname_valid
            )

            if not hostname_valid:

                result["findings"].append(
                    "Certificate hostname does not "
                    "match the requested domain"
                )

    # TLS protocol support
    result["supported_tls_versions"] = (
        check_tls_protocol_support(
            host,
            timeout
        )
    )

    supported_versions = result.get(
        "supported_tls_versions",
        []
    )

    # Deprecated TLS
    if "TLSv1.0" in supported_versions:

        result["findings"].append(
            "Server supports deprecated TLSv1.0"
        )

    if "TLSv1.1" in supported_versions:

        result["findings"].append(
            "Server supports deprecated TLSv1.1"
        )

    # Cipher security
    cipher = result.get("cipher")

    if cipher:

        cipher_name = cipher[0].upper()

        if (
            "RC4" in cipher_name
            or "3DES" in cipher_name
            or "DES" in cipher_name
        ):

            result["findings"].append(
                f"Weak TLS cipher suite: {cipher[0]}"
            )

    # Verdict
    if result["findings"]:

        result["verdict"] = "WARNING"

    return result


def is_valid_host(host: str) -> bool:

    if not host:
        return False

    # IPv4
    ipv4_pattern = re.compile(
        r"^(?:\d{1,3}\.){3}\d{1,3}$"
    )

    if ipv4_pattern.match(host):

        return all(
            0 <= int(octet) <= 255
            for octet in host.split(".")
        )

    # IPv6
    if ":" in host:

        try:
            socket.inet_pton(
                socket.AF_INET6,
                host
            )
            return True
        except OSError:
            return False

    # Hostname
    hostname_pattern = re.compile(
        r"^(?=.{1,253}$)"
        r"(?:[A-Za-z0-9]"
        r"(?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
        r"\.)+"
        r"[A-Za-z]{2,63}$"
    )

    return bool(
        hostname_pattern.match(host)
    )


def print_certificate_info(result: dict):

    cert = result.get("certificate")

    if not cert:
        print("certificate: None")
        return

    print("certificate:")

    print(
        f"  subject: "
        f"{cert.get('subject', 'Unknown')}"
    )

    print(
        f"  issuer: "
        f"{cert.get('issuer', 'Unknown')}"
    )

    print(
        f"  valid_from: "
        f"{cert.get('not_before', 'Unknown')}"
    )

    print(
        f"  valid_to: "
        f"{cert.get('not_after', 'Unknown')}"
    )

    if "days_remaining" in cert:

        print(
            f"  days_remaining: "
            f"{cert['days_remaining']}"
        )

    print(
        f"  hostname_validation: "
        f"{'Passed' if result.get('hostname_valid') is True else 'Failed' if result.get('hostname_valid') is False else 'Not Tested'}"
    )

    if cert.get("san"):

        print(
            f"  san: "
            f"{', '.join(cert['san'])}"
        )

    if cert.get("key_type"):

        print(
            f"  key_type: "
            f"{cert['key_type']}"
        )

    if cert.get("key_bits"):

        print(
            f"  key_bits: "
            f"{cert['key_bits']}"
        )

    print(
        f"  self_signed: "
        f"{cert.get('self_signed', False)}"
    )

    fingerprint = result.get(
        "fingerprint"
    )

    if fingerprint:

        print(
            f"  sha256_fingerprint: "
            f"{fingerprint}"
        )


def print_result_vertical(result: dict):

    print(
        "\n--- HTTPS Transmission Check (Port 443) ---"
    )

    print(
        f"host: {result['host']}"
    )

    print(
        f"port: {result['port']}"
    )

    print(
        f"reachable: {result['reachable']}"
    )

    if result.get("resolved_ips"):

        print(
            f"resolved_ips: "
            f"{', '.join(result['resolved_ips'])}"
        )

    if result.get("latency_ms") is not None:

        print(
            f"latency_ms: "
            f"{result['latency_ms']}"
        )

    if result.get("tls_version"):

        print(
            f"tls_version: "
            f"{result['tls_version']}"
        )

    supported = result.get(
        "supported_tls_versions",
        []
    )

    print(
        f"supported_tls_versions: "
        f"{', '.join(supported) or 'None'}"
    )

    if result.get("cipher"):

        name, protocol, bits = result["cipher"]

        print("cipher:")

        print(
            f"  name: {name}"
        )

        print(
            f"  protocol: {protocol}"
        )

        print(
            f"  key_bits: {bits}"
        )

    print(
        f"alpn: "
        f"{result.get('alpn') or 'None'}"
    )

    if result.get("certificate_trusted") is not None:

        print(
            f"certificate_trusted: "
            f"{result.get('certificate_trusted')}"
        )

    print_certificate_info(result)

    print("\nsecurity_assessment:")

    findings = result.get(
        "findings",
        []
    )

    if findings:

        for finding in findings:

            print(
                f"  finding: {finding}"
            )

    else:

        print(
            "  no security findings."
        )

    print(
        f"\nverdict: {result.get('verdict', 'UNKNOWN')}"
    )

    print(
        "\nnote: Certificate revocation status "
        "is not checked by this scanner."
    )

    if result.get("error"):

        print(
            f"\nerror: {result['error']}"
        )

    elif result.get("ssl_error"):

        print(
            f"\nssl_error: {result['ssl_error']}"
        )


# --- CLI ---
if __name__ == "__main__":

    while True:

        test_url = input(
            "Enter URL to check "
            "(e.g., https://example.com): "
        ).strip()

        if not test_url:

            test_url = "https://example.com"

        if "://" not in test_url:

            test_url = (
                "https://" + test_url
            )

        parsed = urlparse(test_url)

        host = parsed.hostname

        if not is_valid_host(host):

            print(
                f"[ERROR] Invalid host: {host}\n"
            )

            continue

        result = check_transmission_port(
            test_url
        )

        print_result_vertical(
            result
        )

        break

    input(
        "\nPress Enter to exit..."
    )
