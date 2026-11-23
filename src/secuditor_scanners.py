# Secuditor Scanners – Copyright (c) 2026 Menahem Levinski

import os
import sys
import re
import stat
import time
import contextlib
import hashlib
import html
import sqlite3
import textwrap
import ipaddress
import ctypes
import json
import subprocess
import glob
import platform
import math
import psutil
import socket
import ssl
import winreg
import xml.etree.ElementTree as ET
import win32gui, win32con, win32process, win32clipboard, win32security

from urllib.parse import urlparse, quote
from ctypes import wintypes
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448
from functools import lru_cache

try:
    import certifi
except ImportError:
    certifi = None

RISK_THRESHOLD = 60

# ===== Load data =====
import secuditor_modules

_ssl_inspection_cache = {}
_suspicious_proxy_cache = None


def clear_audit_caches():
    """Clear all scanner-level audit caches so subsequent audits rerun fresh and caches serve only scoring."""
    global _ssl_inspection_cache, _suspicious_proxy_cache
    _ssl_inspection_cache.clear()
    _suspicious_proxy_cache = None
    SuspiciousProcesses._cache = None
    SuspiciousProcesses.is_microsoft_signed.cache_clear()
    SensitivePaths._cache = None
    WebBrowserScanner._cache = None
from secuditor_utilities import (
    resource_path,
    _system_exe,
    _safe_subproc_env,
    _subproc_kwargs_hide_window,
    _run_check_output,
)

with open(resource_path("data/sec.json"), "r", encoding="utf-8") as f:
    SEC = json.load(f)

# --- Data for Suspicious Processes ---
SUSPICIOUS_CMD_PATTERNS = SEC["suspicious_cmd_patterns"]
SUSPICIOUS_PARENTS = SEC["suspicious_parents"]
SUSPICIOUS_REMOTE_PORTS = set(SEC["suspicious_remote_ports"])
SYSTEM_PATH_PREFIXES = SEC["system_path_prefixes"]
SUSPICIOUS_EXECUTABLE_LOCATIONS = SEC["suspicious_executable_locations"]
APPLICATIONS_PATH_PREFIXES = SEC["applications_path_prefixes"]
LEGIT_NETWORK_APPLICATIONS = set(SEC["legit_network_applications"])
KNOWN_SYSTEM_PROCESSES = set(SEC["known_system_processes"])
SPECIAL_SYSTEM_PID = set(SEC["special_system_pid"])
LOLBINS = set(SEC["lolbins"])

# --- Data for Sensitive Paths ---
SENSITIVE_PATH_TEMPLATES = SEC["sensitive_path_templates"]
DEFAULT_COPY_SEARCH = SEC["default_copy_search"]
SENSITIVE_PATTERNS = SEC["sensitive_patterns"]
WEBROOT_SENSITIVE_PATTERNS = SEC.get(
    "webroot_sensitive_patterns",
    ["*.config", "*.php", "*.js", "*.asp", "*.aspx"],
)
KNOWN_BENIGN_FILES = {f.lower() for f in SEC.get("known_benign_files", [])}

# --- Data for SSL/TLS Interception ---
LEGIT_ISSUERS = SEC["legit_issuers"]
PUBLIC_CAS = SEC["public_cas"]

# --- Data for Web Browser Scanner ---
BROWSER_HIGH_RISK_PERMISSIONS = set(
    SEC.get(
        "browser_high_risk_permissions",
        [
            "debugger",
            "nativeMessaging",
            "proxy",
            "webRequest",
            "webRequestBlocking",
            "cookies",
            "clipboardRead",
            "management",
            "scripting",
            "downloads",
        ],
    )
)
BROWSER_BROAD_HOST_PATTERNS = set(
    SEC.get(
        "browser_broad_host_patterns",
        ["<all_urls>", "*://*/*", "http://*/*", "https://*/*"],
    )
)
BROWSER_INSECURE_FLAGS = tuple(
    f.lower()
    for f in SEC.get(
        "browser_insecure_flags",
        [
            "--disable-web-security",
            "--ignore-certificate-errors",
            "--remote-debugging-port",
            "--load-extension",
            "--no-sandbox",
            "--allow-running-insecure-content",
            "--start-debugger-server",
        ],
    )
)


# ===== Shared Diagram Formatting Helpers =====
def _normalize_diagram_text(value, default="Unknown"):
    """Collapse newlines and repeated whitespace into a single clean line."""
    if value is None:
        text = ""
    else:
        text = " ".join(str(value).replace("\r", " ").replace("\n", " ").split())
    return text or default


def _short_text(value, max_len=28, default="Unknown"):
    """Flatten newlines/whitespace and truncate long values for clean diagram rendering."""
    text = _normalize_diagram_text(value, default=default)
    if max_len > 3 and len(text) > max_len:
        return text[: max_len - 3].rstrip() + "..."
    return text[:max_len]


def _wrap_diagram_detail(prefix_token, value, indent="    ", max_width=78, default="Unknown"):
    """Wrap a diagram detail line cleanly onto row(s) below the flow diagram without truncation."""
    text = _normalize_diagram_text(value, default=default)
    initial_indent = f"{indent}{prefix_token}"
    subsequent_indent = f"{indent}{' ' * len(prefix_token)}"
    wrapped = textwrap.wrap(
        text,
        width=max_width,
        initial_indent=initial_indent,
        subsequent_indent=subsequent_indent,
        break_long_words=True,
        break_on_hyphens=False,
    )
    return wrapped or [initial_indent + default]


def _extract_short_issuer(issuer_dn, fallback=None, max_len=22):
    """Extract O= or CN= from an RFC 4514 DN string for compact box labels."""
    raw = str(issuer_dn or "").strip()
    if raw:
        parts = re.split(r"(?<!\\),", raw)
        parsed = {}
        for part in parts:
            if "=" in part:
                k, v = part.split("=", 1)
                key = k.strip().upper()
                val = v.replace(r"\,", ",").strip()
                if key and val and key not in parsed:
                    parsed[key] = val
        chosen = parsed.get("O") or parsed.get("CN") or parsed.get("OU") or raw
    else:
        chosen = fallback or "Unknown"
    return _short_text(chosen, max_len=max_len, default="Unknown")


# ===== Check for SSL interception =====
class SSLInspection:

    @staticmethod
    def _host_matches_pattern(host: str, pattern: str) -> bool:
        """Match a hostname against a certificate CN/SAN pattern including wildcards."""
        h = (host or "").strip().lower().rstrip(".")
        p = (pattern or "").strip().lower().rstrip(".")
        if not h or not p:
            return False
        if h == p:
            return True
        if p.startswith("*."):
            base = p[2:]
            if base and h.endswith("." + base) and h.count(".") == base.count(".") + 1:
                return True
        return False

    @staticmethod
    def _extract_issuer_fields(cert) -> list[str]:
        """Extract O, CN, and OU attribute values from a certificate issuer."""
        fields = []
        for oid in (
            NameOID.ORGANIZATION_NAME,
            NameOID.COMMON_NAME,
            NameOID.ORGANIZATIONAL_UNIT_NAME,
        ):
            try:
                for attr in cert.issuer.get_attributes_for_oid(oid):
                    val = str(attr.value or "").strip()
                    if val:
                        fields.append(val)
            except Exception:
                continue
        return fields

    @staticmethod
    def _matches_issuer_list(fields: list[str], candidates: list[str]):
        """Match any candidate CA/vendor against issuer RDN values using token boundaries."""
        for token in candidates or ():
            tok = str(token or "").strip()
            if not tok:
                continue
            pattern = re.compile(rf"(?<!\w){re.escape(tok)}(?!\w)", re.IGNORECASE)
            for field in fields:
                if pattern.search(field):
                    return tok
        return None

    @staticmethod
    def _fetch_peer_cert(host: str, port: int, context: ssl.SSLContext, connect_host=None):
        """Connect, perform TLS handshake, and return (DER bytes, negotiated TLS version, peer IP)."""
        target = connect_host or host
        with socket.create_connection((target, port), timeout=5) as sock:
            peer_ip = None
            try:
                peer_ip = sock.getpeername()[0]
            except OSError:
                peer_ip = None
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                return ssock.getpeercert(binary_form=True), ssock.version(), peer_ip

    def _verify_public_chain(self, host: str, port: int, expected_fingerprint=None, connect_host=None):
        """
        Verify certificate chain against public WebPKI roots (certifi).

        Returns:
            True if trusted by Mozilla/certifi roots (and matching expected_fingerprint when given),
            False if certificate/hostname verification fails against certifi,
            None if certifi is unavailable, a transient socket error occurred, or the leaf
                 certificate changed between verification stages.
        """
        if certifi is None:
            return None
        try:
            public_ctx = ssl.create_default_context(cafile=certifi.where())
            public_ctx.check_hostname = True
            public_ctx.verify_mode = ssl.CERT_REQUIRED
            pub_der, _, _ = self._fetch_peer_cert(host, port, public_ctx, connect_host=connect_host)
            if expected_fingerprint is not None:
                pub_fp = hashlib.sha256(pub_der).hexdigest()
                if pub_fp != expected_fingerprint:
                    return None
            return True
        except ssl.SSLCertVerificationError:
            return False
        except Exception:
            return None

    def check_ssl_inspection(self, host="www.google.com", port=443, use_cache=True):
        global _ssl_inspection_cache

        cache_key = (str(host or "").strip().lower(), port)
        if (
            use_cache
            and cache_key in _ssl_inspection_cache
            and not secuditor_modules.run_all_clicked
            and not secuditor_modules.single_check
        ):
            return _ssl_inspection_cache[cache_key]

        try:
            # --- Stage 1: Verify against Windows OS trust store first ---
            os_ctx = ssl.create_default_context()
            os_ctx.check_hostname = True
            os_ctx.verify_mode = ssl.CERT_REQUIRED

            os_trusted = True
            verify_error = None
            peer_ip = None
            try:
                der, tls_version, peer_ip = self._fetch_peer_cert(host, port, os_ctx)
            except ssl.SSLCertVerificationError as verify_exc:
                os_trusted = False
                verify_error = getattr(verify_exc, "verify_message", None) or str(verify_exc)
                # Fallback unverified fetch only to extract certificate metadata for reporting
                raw_ctx = ssl.create_default_context()
                raw_ctx.check_hostname = False
                raw_ctx.verify_mode = ssl.CERT_NONE
                der, tls_version, peer_ip = self._fetch_peer_cert(host, port, raw_ctx)

            fingerprint_stage1 = hashlib.sha256(der).hexdigest()

            # --- Stage 2: Check whether an OS-trusted cert also chains to a public WebPKI root ---
            public_trusted = (
                self._verify_public_chain(
                    host,
                    port,
                    expected_fingerprint=fingerprint_stage1,
                    connect_host=peer_ip,
                )
                if os_trusted
                else False
            )

            cert = x509.load_der_x509_certificate(der)
            issuer = cert.issuer.rfc4514_string()
            subject = cert.subject.rfc4514_string()
            cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            common_name = cn_attrs[0].value if cn_attrs else ""

            try:
                san = cert.extensions.get_extension_for_class(
                    x509.SubjectAlternativeName
                ).value.get_values_for_type(x509.DNSName)
            except x509.ExtensionNotFound:
                san = []

            not_before = cert.not_valid_before_utc
            not_after = cert.not_valid_after_utc

            fingerprint = cert.fingerprint(hashes.SHA256()).hex()
            sig_hash_algo = cert.signature_hash_algorithm
            if sig_hash_algo is not None:
                sig_algo = sig_hash_algo.name.lower()
            else:
                sig_algo = cert.signature_algorithm_oid._name.lower()

            key_type = "Unknown"
            key_bits = None
            key_strength = "Unknown"

            try:
                public_key = cert.public_key()

                if isinstance(public_key, rsa.RSAPublicKey):
                    key_type = "RSA"
                    key_bits = public_key.key_size
                    if key_bits < 2048:
                        key_strength = "Weak"
                    elif key_bits < 4096:
                        key_strength = "Moderate"
                    else:
                        key_strength = "Strong"

                elif isinstance(public_key, ec.EllipticCurvePublicKey):
                    key_type = "ECC"
                    key_bits = public_key.key_size
                    if key_bits < 256:
                        key_strength = "Weak"
                    elif key_bits < 384:
                        key_strength = "Moderate"
                    else:
                        key_strength = "Strong"

                elif isinstance(public_key, ed25519.Ed25519PublicKey):
                    key_type = "Ed25519"
                    key_bits = 256
                    key_strength = "Strong"

                elif isinstance(public_key, ed448.Ed448PublicKey):
                    key_type = "Ed448"
                    key_bits = 456
                    key_strength = "Strong"

                else:
                    key_type = type(public_key).__name__

            except Exception:
                pass

            # --- Detection & classification ---
            issuer_fields = self._extract_issuer_fields(cert)
            matched_legit_vendor = self._matches_issuer_list(issuer_fields, LEGIT_ISSUERS)

            triggers = []
            trust_mismatch = False
            public_check_inconclusive = False

            if not os_trusted:
                trust_mismatch = True
                triggers.append(
                    f"Untrusted certificate ({verify_error})" if verify_error else "Untrusted certificate"
                )
            elif public_trusted is False:
                trust_mismatch = True
                triggers.append("Non-public root CA")
            elif public_trusted is None:
                public_check_inconclusive = True

            validity_days = (not_after - not_before).days
            unusual_lifetime = validity_days <= 0 or validity_days > 825
            if unusual_lifetime:
                triggers.append("Unusual certificate lifetime")

            if san:
                host_matched = any(self._host_matches_pattern(host, s) for s in san)
            else:
                host_matched = bool(common_name) and self._host_matches_pattern(host, common_name)
            if not host_matched:
                triggers.append("CN/SAN mismatch")

            weak_sig = sig_algo in ("md5", "sha1")
            if weak_sig:
                triggers.append("Weak signature algorithm")

            inspected = trust_mismatch or (not host_matched)
            legit = False
            reason = None

            if inspected:
                if not os_trusted or not host_matched or weak_sig or unusual_lifetime:
                    verdict = "Suspicious"
                    reason = ", ".join(triggers)
                elif os_trusted and public_trusted is False and matched_legit_vendor:
                    legit = True
                    verdict = "Likely Legitimate"
                    reason = f"OS-trusted non-public CA matching {matched_legit_vendor} (name match)"
                else:
                    verdict = "Suspicious"
                    reason = ", ".join(triggers)
            elif triggers:
                verdict = "Suspicious"
                reason = ", ".join(triggers)
            elif public_check_inconclusive:
                verdict = "Unknown"
                reason = "Public CA verification unavailable"
            else:
                verdict = "Not Detected"

            ssl_result = {
                "host": host,
                "subject": subject,
                "issuer": issuer,
                "common_name": common_name or "N/A",
                "san": san,
                "valid_from": not_before.isoformat(),
                "valid_to": not_after.isoformat(),

                "fingerprint_sha256": fingerprint,
                "signature_algo": sig_algo,
                "tls_version": tls_version,

                "key_type": key_type,
                "key_bits": key_bits,
                "key_strength": key_strength,

                "ssl_interception_detected": inspected,
                "interception_legit": legit,
                "interception_reason": reason,
                "verdict": verdict
            }
            if use_cache:
                _ssl_inspection_cache[cache_key] = ssl_result
            return ssl_result

        except Exception as e:
            return {
                "error": str(e),
                "ssl_interception_detected": False,
                "interception_legit": False,
                "interception_reason": str(e),
                "verdict": "Unknown"
            }

    @staticmethod
    def _format_illustration(result):
        """Build a compact monospace flow diagram describing the TLS inspection state."""
        verdict = str(result.get("verdict") or "Unknown").strip()
        raw_host = result.get("host") or "www.google.com"
        target_str = f"{raw_host}:443" if ":" not in str(raw_host) else str(raw_host)
        target = _short_text(target_str, max_len=22, default="target:443")
        issuer = _extract_short_issuer(
            result.get("issuer"),
            fallback=result.get("common_name"),
            max_len=22,
        )
        raw_reason = (
            result.get("interception_reason")
            or result.get("error")
            or "Verification anomaly"
        )

        lines = ["Illustration:"]
        if verdict in ("None", "Not Detected"):
            prefix = "  [ This Host ] ===( Verified Direct TLS )===> "
            lines.append(f"{prefix}[ {target} ]")
            lines.append(f"{' ' * len(prefix)}CA: {issuer}")
        elif verdict == "Likely Legitimate":
            prefix = "  [ This Host ] --( Trusted )--> "
            lines.append(f"{prefix}[ MITM: {issuer} ] --( TLS )--> [ {target} ]")
            lines.append(f"{' ' * len(prefix)}└─ Authorized SSL/TLS inspection")
        elif verdict == "Suspicious":
            if result.get("ssl_interception_detected"):
                prefix = "  [ This Host ] --X (Untrusted / MITM) X--> "
                lines.append(f"{prefix}[ MITM: {issuer} ] --> [ {target} ]")
            else:
                prefix = "  [ This Host ] --! (Weak / Invalid Cert) !--> "
                lines.append(f"{prefix}[ {target} ]")
            lines.extend(_wrap_diagram_detail("└─ Alert: ", raw_reason, indent="    ", max_width=78))
        else:
            prefix = "  [ This Host ] --- X (Handshake Failed) ---> "
            lines.append(f"{prefix}[ {target} ]")
            lines.extend(_wrap_diagram_detail("└─ ", raw_reason, indent="    ", max_width=78))

        return "\n".join(lines)

    def show_ssl_inspection(self):
        report = [""]

        result = self.check_ssl_inspection("www.google.com", 443)

        verdict = result.get("verdict", "Unknown")

        # Verdict block (must be outside string)
        if not verdict or verdict in ("None", "Not Detected"):
            report.append("Analysis:\n  Verdict: Not Detected")
        else:
            report.append(f"Analysis:\n  Verdict: {verdict}")

        report.append(
            f"  SSL Interception Detected: {result.get('ssl_interception_detected')}\n"
            f"  Legit Inspection: {result.get('interception_legit')}\n"
            f"  Reason: {result.get('interception_reason')}"
        )

        report.append("–" * 50)
        report.append(self._format_illustration(result))
        report.append("–" * 50)

        report.append(
            "Session:\n"
            f"  Host: {result.get('host')}\n"
            f"  Subject: {result.get('subject')}\n"
            f"  Issuer: {result.get('issuer')}\n"
            f"  Common Name: {result.get('common_name')}\n"
            f"  SAN: {', '.join(result.get('san', []))}\n"
            f"  Valid From: {result.get('valid_from')}\n"
            f"  Valid To: {result.get('valid_to')}"
        )

        report.append("–" * 50)

        report.append(
            "Cryptography:\n"
            f"  Fingerprint (SHA256): {result.get('fingerprint_sha256')}\n"
            f"  Signature Algorithm: {result.get('signature_algo')}\n"
            f"  TLS Version: {result.get('tls_version')}\n"
            f"  Key Type: {result.get('key_type')}\n"
            f"  Key Bits: {result.get('key_bits')}\n"
            f"  Key Strength: {result.get('key_strength')}"
        )

        return "\n".join(report)

# ===== Check for Suspicious Proxy =====
class SuspiciousProxy:

    _KNOWN_TUNNEL_TOOLS = {
        "chisel", "ngrok", "frpc", "frps", "gost", "mitmdump",
        "mitmweb", "mitmproxy", "fiddler", "burpsuite", "socat",
        "plink", "proxifier", "tor", "stunnel",
    }
    _LOCALHOST_HOSTS = {"localhost", "127.0.0.1", "::1", "[::1]"}
    _TOR_PORTS = {9050, 9150}

    @staticmethod
    def _read_reg(hive, subkey, name, default=None):
        try:
            with winreg.OpenKey(hive, subkey) as key:
                val, _ = winreg.QueryValueEx(key, name)
                return val
        except OSError:
            return default

    @classmethod
    def _is_loopback_host(cls, host):
        if not host:
            return False
        cleaned = host.strip().lower()
        if cleaned in cls._LOCALHOST_HOSTS:
            return True
        try:
            return ipaddress.ip_address(cleaned.strip("[]")).is_loopback
        except ValueError:
            return False

    @staticmethod
    def _parse_proxy_endpoints(raw_value):
        """Parse Windows ProxyServer / WinHTTP / URL proxy strings into (scheme, host, port) tuples."""
        endpoints = []
        if not isinstance(raw_value, str) or not raw_value.strip():
            return endpoints

        default_ports = {"http": 80, "https": 443, "socks": 1080, "socks4": 1080, "socks5": 1080}

        for part in re.split(r"[;\s]+", raw_value.strip()):
            item = part.strip()
            if not item:
                continue

            scheme = "http"
            kv_match = re.match(r"^([a-zA-Z][a-zA-Z0-9+.-]*)=(.+)$", item)
            if kv_match:
                scheme = kv_match.group(1).strip().lower() or "http"
                item = kv_match.group(2).strip()
                if not item:
                    continue

            candidate = item if "://" in item else f"{scheme}://{item}"
            try:
                parsed = urlparse(candidate)
                host = (parsed.hostname or "").strip().lower()
                parsed_scheme = (parsed.scheme or scheme).lower()
                port = parsed.port
                if port is None:
                    port = default_ports.get(parsed_scheme)
                if host:
                    endpoints.append((parsed_scheme, host, port))
            except Exception:
                continue

        return endpoints

    @staticmethod
    def _is_public_ip(host):
        if not host:
            return False
        cleaned = host.strip("[]")
        try:
            ip_obj = ipaddress.ip_address(cleaned)
            return not (
                ip_obj.is_private
                or ip_obj.is_loopback
                or ip_obj.is_link_local
                or ip_obj.is_multicast
                or ip_obj.is_unspecified
            )
        except ValueError:
            return False

    @staticmethod
    def _is_ip_literal(host):
        if not host:
            return False
        try:
            ipaddress.ip_address(host.strip("[]"))
            return True
        except ValueError:
            return False

    @staticmethod
    def _get_authenticode_info(path):
        """Return (status, signer_subject) for an executable using PowerShell Get-AuthenticodeSignature."""
        if not path:
            return "Unknown", ""
        try:
            out = subprocess.check_output(
                [
                    _system_exe("powershell.exe"),
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "$s = Get-AuthenticodeSignature -LiteralPath $env:SECUDITOR_SIG_PATH; "
                    "[PSCustomObject]@{ Status = [string]$s.Status; "
                    "Signer = if ($s.SignerCertificate) { $s.SignerCertificate.Subject } else { '' } } | "
                    "ConvertTo-Json -Compress",
                ],
                env=_safe_subproc_env({"SECUDITOR_SIG_PATH": path}),
                text=True,
                timeout=5,
                stderr=subprocess.DEVNULL,
                **_subproc_kwargs_hide_window(),
            ).strip()
            if out:
                data = json.loads(out)
                return (data.get("Status") or "Unknown"), (data.get("Signer") or "")
        except Exception:
            pass
        return "Unknown", ""

    @classmethod
    def _find_listener_for_port(cls, port, target_host=None):
        """Find listening socket owner process on `port`."""
        if not port:
            return None
        try:
            conns = psutil.net_connections(kind="inet")
        except Exception:
            return None

        target_clean = (target_host or "").strip("[]").lower()
        for c in conns:
            if c.status != psutil.CONN_LISTEN or not c.laddr or c.laddr.port != port:
                continue
            lip = (c.laddr.ip or "").lower()
            if target_clean in ("127.0.0.1", "localhost"):
                if lip not in ("127.0.0.1", "0.0.0.0", "::", "::1"):
                    continue
            elif target_clean == "::1":
                if lip not in ("::1", "::", "0.0.0.0"):
                    continue

            pid = c.pid
            name, exe = "Unknown", ""
            if pid:
                try:
                    proc = psutil.Process(pid)
                    name = proc.name() or "Unknown"
                    exe = proc.exe() or ""
                except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                    pass

            sig_status, signer = cls._get_authenticode_info(exe)
            return {
                "pid": pid,
                "name": name,
                "path": exe,
                "signature": sig_status,
                "signer": signer,
            }
        return None

    @classmethod
    def _collect_wininet(cls):
        user_sub = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        policy_sub = r"Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings"

        def _clean_str(val):
            s = str(val).strip() if val is not None else ""
            return s or None

        hkcu_enable = cls._read_reg(winreg.HKEY_CURRENT_USER, user_sub, "ProxyEnable", 0)
        hkcu_server = _clean_str(cls._read_reg(winreg.HKEY_CURRENT_USER, user_sub, "ProxyServer"))
        hkcu_pac = _clean_str(cls._read_reg(winreg.HKEY_CURRENT_USER, user_sub, "AutoConfigURL"))
        hkcu_auto = bool(cls._read_reg(winreg.HKEY_CURRENT_USER, user_sub, "AutoDetect", 0))

        hklm_enable = cls._read_reg(winreg.HKEY_LOCAL_MACHINE, user_sub, "ProxyEnable", 0)
        hklm_server = _clean_str(cls._read_reg(winreg.HKEY_LOCAL_MACHINE, user_sub, "ProxyServer"))
        hklm_pac = _clean_str(cls._read_reg(winreg.HKEY_LOCAL_MACHINE, user_sub, "AutoConfigURL"))

        pol_per_user = cls._read_reg(winreg.HKEY_LOCAL_MACHINE, policy_sub, "ProxySettingsPerUser")
        pol_enable = cls._read_reg(winreg.HKEY_LOCAL_MACHINE, policy_sub, "ProxyEnable", 0)
        pol_server = _clean_str(cls._read_reg(winreg.HKEY_LOCAL_MACHINE, policy_sub, "ProxyServer"))
        pol_pac = _clean_str(cls._read_reg(winreg.HKEY_LOCAL_MACHINE, policy_sub, "AutoConfigURL"))

        manual = None
        raw_manual = ""
        if pol_per_user == 0:
            sources = [
                (hklm_enable, hklm_server, "[HKLM] "),
                (pol_enable, pol_server, "[Policy] "),
                (hkcu_enable, hkcu_server, ""),
            ]
            pac = hklm_pac or pol_pac or hkcu_pac
        else:
            sources = [
                (hkcu_enable, hkcu_server, ""),
                (hklm_enable, hklm_server, "[HKLM] "),
                (pol_enable, pol_server, "[Policy] "),
            ]
            pac = hkcu_pac or hklm_pac or pol_pac

        for enabled, server, prefix in sources:
            if enabled and server:
                manual = f"{prefix}{server}"
                raw_manual = server
                break

        return {
            "manual": manual,
            "raw_manual": raw_manual,
            "pac": pac,
            "autodetect": hkcu_auto,
            "policy_enforced": bool(pol_enable and (pol_server or pol_pac)) or (pol_per_user == 0),
        }

    @staticmethod
    def _collect_winhttp():
        try:
            out = _run_check_output(["netsh", "winhttp", "show", "proxy"], timeout=5)
            if "Direct access" in out:
                return "Direct Access", ""
            m = re.search(r"Proxy Server\(s\)\s*:\s*(.+)", out, re.IGNORECASE)
            if m:
                val = m.group(1).strip()
                return val, val
            return "Configured / Unknown", ""
        except Exception:
            return "Unable to determine", ""

    @classmethod
    def _collect_env_proxies(cls):
        vars_to_check = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY")
        found = {}

        for k in vars_to_check:
            val = os.environ.get(k) or os.environ.get(k.lower())
            if val and str(val).strip():
                found[k] = str(val).strip()

        for hive, subkey in (
            (winreg.HKEY_CURRENT_USER, r"Environment"),
            (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"),
        ):
            for k in vars_to_check:
                val = cls._read_reg(hive, subkey, k)
                if val and str(val).strip() and k not in found:
                    found[k] = str(val).strip()

        return found

    @staticmethod
    def _collect_portproxy_rules():
        rules = []
        try:
            out = _run_check_output(["netsh", "interface", "portproxy", "show", "all"], timeout=5)
            for line in out.splitlines():
                m = re.match(r"^\s*(\S+)\s+(\d+)\s+(\S+)\s+(\d+)\s*$", line)
                if m:
                    listen_ip, listen_port, conn_ip, conn_port = m.groups()
                    rules.append(f"{listen_ip}:{listen_port} -> {conn_ip}:{conn_port}")
        except Exception:
            pass
        return rules

    def check_suspicious_proxy(self):
        global _suspicious_proxy_cache

        if (
            _suspicious_proxy_cache is not None
            and not secuditor_modules.run_all_clicked
            and not secuditor_modules.single_check
        ):
            return _suspicious_proxy_cache

        try:
            wininet = self._collect_wininet()
            winhttp_display, winhttp_raw = self._collect_winhttp()
            env_proxies = self._collect_env_proxies()
            portproxy_rules = self._collect_portproxy_rules()

            endpoints = []
            if wininet["raw_manual"]:
                endpoints.extend(self._parse_proxy_endpoints(wininet["raw_manual"]))
            if winhttp_raw:
                endpoints.extend(self._parse_proxy_endpoints(winhttp_raw))
            for val in env_proxies.values():
                endpoints.extend(self._parse_proxy_endpoints(val))

            proxy_detected = bool(
                wininet["manual"]
                or wininet["pac"]
                or winhttp_raw
                or env_proxies
                or portproxy_rules
            )

            triggers = []
            high_risk_triggers = set()
            suspicious_locs = {p.lower() for p in SUSPICIOUS_EXECUTABLE_LOCATIONS}

            target_host = None
            target_port = None
            listener_info = None

            # Evaluate configured proxy endpoints
            for scheme, host, port in endpoints:
                if target_host is None:
                    target_host, target_port = host, port

                if scheme.startswith("socks") or port in self._TOR_PORTS:
                    msg = f"SOCKS/Tor proxy configured ({host}:{port or '?'})"
                    if msg not in triggers:
                        triggers.append(msg)
                        high_risk_triggers.add(msg)

                if self._is_public_ip(host):
                    msg = f"Public IP proxy target ({host})"
                    if msg not in triggers:
                        triggers.append(msg)
                        high_risk_triggers.add(msg)

                if self._is_loopback_host(host) and port:
                    info = self._find_listener_for_port(port, host)
                    if listener_info is None:
                        listener_info = info
                    if not info:
                        msg = f"Unowned/inactive local proxy on port {port}"
                        if msg not in triggers:
                            triggers.append(msg)
                    else:
                        proc_stem = os.path.splitext((info.get("name") or "").lower())[0]
                        proc_path_l = os.path.normcase(info.get("path") or "").lower()
                        sig = info.get("signature", "Unknown")

                        if proc_stem in self._KNOWN_TUNNEL_TOOLS:
                            msg = f"Tunnel/MITM tool listening on port {port} ({info.get('name')})"
                            if msg not in triggers:
                                triggers.append(msg)
                                high_risk_triggers.add(msg)

                        if proc_path_l and any(loc in proc_path_l for loc in suspicious_locs):
                            msg = f"Local proxy running from suspicious path ({info.get('name')})"
                            if msg not in triggers:
                                triggers.append(msg)
                                high_risk_triggers.add(msg)

                        if sig != "Valid":
                            msg = f"Untrusted/unsigned local proxy listener ({info.get('name')}: {sig})"
                            if msg not in triggers:
                                triggers.append(msg)
                                high_risk_triggers.add(msg)

            # Evaluate PAC URL
            pac_url = wininet["pac"]
            if pac_url:
                pac_lower = pac_url.lower()
                if pac_lower.startswith("file:") or pac_url.startswith("\\\\"):
                    msg = f"Local/UNC PAC script ({pac_url})"
                    triggers.append(msg)
                    high_risk_triggers.add(msg)
                else:
                    parsed_pac = urlparse(pac_url)
                    if parsed_pac.scheme.lower() == "http":
                        msg = f"Unencrypted HTTP PAC URL ({parsed_pac.hostname or pac_url})"
                        triggers.append(msg)
                        high_risk_triggers.add(msg)
                    if parsed_pac.hostname and self._is_ip_literal(parsed_pac.hostname):
                        msg = f"IP-literal PAC host ({parsed_pac.hostname})"
                        triggers.append(msg)
                        high_risk_triggers.add(msg)

            # Evaluate netsh portproxy rules
            if portproxy_rules:
                msg = f"Active netsh portproxy rule ({len(portproxy_rules)})"
                triggers.append(msg)
                high_risk_triggers.add(msg)

            # Check whether active proxy matches a legitimate enterprise / Microsoft signer
            legit = False
            legit_reason = None
            if listener_info and listener_info.get("signature") == "Valid":
                signer_l = (listener_info.get("signer") or "").lower()
                for vendor in LEGIT_ISSUERS:
                    if vendor.lower() in signer_l:
                        legit = True
                        legit_reason = f"Signed by {vendor}"
                        break
                if not legit and "microsoft" in signer_l:
                    legit = True
                    legit_reason = "Signed by Microsoft"

            if not legit and wininet["policy_enforced"] and not high_risk_triggers:
                legit = True
                legit_reason = "Enforced by system policy"

            if not proxy_detected and not triggers:
                verdict = "Not Detected"
                reason = None
            elif not triggers:
                verdict = "Likely Legitimate"
                reason = legit_reason or "Proxy configured with no suspicious indicators"
            elif legit and not high_risk_triggers:
                verdict = "Likely Legitimate"
                reason = legit_reason
            elif not triggers:
                verdict = "Unknown"
                reason = None
            else:
                verdict = "Suspicious"
                reason = ", ".join(triggers)

            env_summary = ", ".join(f"{k}={v}" for k, v in env_proxies.items()) if env_proxies else "None"

            _suspicious_proxy_cache = {
                "proxy_detected": proxy_detected,
                "proxy_legit": legit,
                "proxy_reason": reason,
                "verdict": verdict,
                "triggers": triggers,
                "wininet_manual": wininet["manual"] or "Disabled",
                "wininet_pac": pac_url or "None",
                "wininet_autodetect": wininet["autodetect"],
                "winhttp_proxy": winhttp_display,
                "env_proxy": env_summary,
                "portproxy_rules": portproxy_rules,
                "target_host": target_host or "N/A",
                "target_port": target_port if target_port is not None else "N/A",
                "owner_process": (
                    f"{listener_info.get('name')} (PID: {listener_info.get('pid')})"
                    if listener_info else "N/A"
                ),
                "owner_path": (listener_info.get("path") or "N/A") if listener_info else "N/A",
                "owner_signature": listener_info.get("signature", "N/A") if listener_info else "N/A",
                "owner_signer": (listener_info.get("signer") or "N/A") if listener_info else "N/A",
            }
            return _suspicious_proxy_cache

        except Exception as e:
            _suspicious_proxy_cache = {
                "error": str(e),
                "proxy_detected": False,
                "proxy_legit": False,
                "proxy_reason": str(e),
                "verdict": "Unknown",
                "triggers": [],
                "wininet_manual": "Unknown",
                "wininet_pac": "Unknown",
                "wininet_autodetect": False,
                "winhttp_proxy": "Unknown",
                "env_proxy": "Unknown",
                "portproxy_rules": [],
                "target_host": "N/A",
                "target_port": "N/A",
                "owner_process": "N/A",
                "owner_path": "N/A",
                "owner_signature": "N/A",
                "owner_signer": "N/A",
            }
            return _suspicious_proxy_cache

    @staticmethod
    def _format_illustration(result):
        """Build a compact monospace flow diagram describing the proxy routing state."""
        verdict = str(result.get("verdict") or "Unknown").strip()
        proxy_detected = bool(result.get("proxy_detected"))
        target_host = result.get("target_host")
        target_port = result.get("target_port")

        if target_host and target_host != "N/A":
            ep_raw = (
                f"{target_host}:{target_port}"
                if target_port not in (None, "", "N/A")
                else str(target_host)
            )
        elif result.get("portproxy_rules"):
            ep_raw = "PortProxy"
        elif result.get("wininet_pac") not in (None, "", "None", "Unknown"):
            ep_raw = "PAC Script"
        elif result.get("wininet_autodetect"):
            ep_raw = "WPAD AutoDetect"
        else:
            ep_raw = "Configured Proxy"

        endpoint = _short_text(ep_raw, max_len=24, default="Configured Proxy")
        owner = _short_text(result.get("owner_process") or "N/A", max_len=26, default="N/A")
        triggers = result.get("triggers") or []
        raw_reason = (
            result.get("proxy_reason")
            or (", ".join(str(t) for t in triggers) if triggers else "")
            or result.get("error")
            or "Check failed"
        )

        lines = ["Illustration:"]
        if verdict in ("None", "Not Detected") or (not proxy_detected and verdict not in ("Suspicious", "Unknown")):
            prefix = "  [ Local Apps ] ===( Direct Connection )===> "
            lines.append(f"{prefix}[ Internet ]")
            lines.append("                    No WinINet, WinHTTP, Env, or PortProxy active")
        elif verdict == "Likely Legitimate":
            prefix = "  [ Local Apps ] ---( Proxy )---> "
            lines.append(f"{prefix}[ {endpoint} ] ---> [ Internet ]")
            lines.append(f"{' ' * len(prefix)}└─ Owner: {owner} | Authorized")
        elif verdict == "Suspicious":
            prefix = "  [ Local Apps ] --! (Suspicious Proxy) !--> "
            lines.append(f"{prefix}[ {endpoint} ] ---> [ Internet ]")
            lines.extend(_wrap_diagram_detail("├─ Owner: ", owner, indent="    ", max_width=78, default="N/A"))
            lines.extend(_wrap_diagram_detail("└─ Alert: ", raw_reason, indent="    ", max_width=78))
        elif proxy_detected:
            prefix = "  [ Local Apps ] --? (Unverified Proxy) ?--> "
            lines.append(f"{prefix}[ {endpoint} ] ---> [ Internet ]")
            lines.append(f"{' ' * len(prefix)}└─ Owner: {owner}")
        else:
            prefix = "  [ Local Apps ] --- X (Check Failed) ---> "
            lines.append(f"{prefix}[ Internet ]")
            lines.extend(_wrap_diagram_detail("└─ ", raw_reason, indent="    ", max_width=78))

        return "\n".join(lines)

    def show_suspicious_proxy(self):
        report = [""]

        result = self.check_suspicious_proxy()
        verdict = result.get("verdict", "Unknown")

        if not verdict or verdict in ("None", "Not Detected"):
            report.append("Analysis:\n  Verdict: Not Detected")
        else:
            report.append(f"Analysis:\n  Verdict: {verdict}")

        triggers = result.get("triggers") or []
        report.append(
            f"  Proxy Detected: {result.get('proxy_detected')}\n"
            f"  Legit Proxy: {result.get('proxy_legit')}\n"
            f"  Reason: {result.get('proxy_reason')}\n"
            f"  Triggers: {', '.join(triggers) if triggers else 'None'}"
        )

        report.append("–" * 50)
        report.append(self._format_illustration(result))
        report.append("–" * 50)

        portproxy = result.get("portproxy_rules") or []
        report.append(
            "Configuration:\n"
            f"  WinINet Manual: {result.get('wininet_manual')}\n"
            f"  WinINet PAC: {result.get('wininet_pac')}\n"
            f"  AutoDetect (WPAD): {result.get('wininet_autodetect')}\n"
            f"  WinHTTP Proxy: {result.get('winhttp_proxy')}\n"
            f"  Env Proxy: {result.get('env_proxy')}\n"
            f"  PortProxy Rules: {', '.join(portproxy) if portproxy else 'None'}"
        )

        report.append("–" * 50)

        report.append(
            "Listener & Process:\n"
            f"  Target Host: {result.get('target_host')}\n"
            f"  Target Port: {result.get('target_port')}\n"
            f"  Owner Process: {result.get('owner_process')}\n"
            f"  Owner Path: {result.get('owner_path')}\n"
            f"  Owner Signature: {result.get('owner_signature')}\n"
            f"  Owner Signer: {result.get('owner_signer')}"
        )

        return "\n".join(report)

# ===== Sensitive Paths =====
class SensitivePaths:

    _cache = None
    _MAX_DISPLAY = 100

    _WEBROOT_MARKERS = (
        "\\inetpub\\wwwroot",
        "\\xampp\\htdocs",
        "\\www",
        "\\htdocs",
        "\\nginx\\html",
    )

    _CRED_KEY_NAMES = {
        "id_rsa", "id_dsa", "id_ed25519", "id_ecdsa", "authorized_keys",
        "credentials", ".git-credentials", ".netrc", ".npmrc", ".pypirc",
        "sitemanager.xml", "recentservers.xml", "sysprep.xml",
    }
    _CRED_KEY_EXTS = {".pem", ".key", ".ppk", ".pfx", ".p12", ".jks", ".keystore"}
    _VAULT_EXTS = {".kdbx"}
    _RDP_VPN_EXTS = {".rdp", ".ovpn"}
    _CONFIG_NAMES = {".env", "web.config", "appsettings.json", "config.php", "config.json", "config"}
    _DB_BACKUP_EXTS = {
        ".dit", ".mdf", ".ldf", ".ndf", ".edb", ".ad",
        ".bak", ".bkf", ".bkp", ".dump", ".dmp", ".sql",
        ".pst", ".ost", ".sqlite", ".sqlite3", ".db",
        ".ibd", ".myd", ".myi", ".frm", ".mdb", ".accdb", ".dbf",
    }
    _WEBROOT_EXTS = {".php", ".js", ".asp", ".aspx", ".config"}

    @staticmethod
    def _sys_drive():
        return os.environ.get("SystemDrive", "C:").rstrip("\\/") + "\\"

    @staticmethod
    def get_fixed_drives():
        drives = []
        DRIVE_FIXED = 3
        get_drive_type = None
        if os.name == "nt":
            try:
                k32 = ctypes.WinDLL(_system_exe("kernel32.dll"), use_last_error=True)
                get_drive_type = k32.GetDriveTypeW
                get_drive_type.argtypes = [wintypes.LPCWSTR]
                get_drive_type.restype = wintypes.UINT
            except Exception:
                get_drive_type = None
        for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            drive = f"{letter}:\\"
            if get_drive_type is not None:
                try:
                    if get_drive_type(drive) == DRIVE_FIXED:
                        drives.append(drive)
                except Exception:
                    continue
            elif os.path.exists(drive):
                drives.append(drive)
        return drives

    @classmethod
    def build_sensitive_paths(cls):
        paths = []
        seen = set()
        sys_drive = cls._sys_drive()
        fixed_drives = cls.get_fixed_drives() or [sys_drive]
        for tpl in SENSITIVE_PATH_TEMPLATES:
            if "{drive}" in tpl:
                for drive in fixed_drives:
                    p = tpl.format(drive=drive, sysdrive=sys_drive)
                    key = os.path.normcase(p)
                    if key not in seen:
                        seen.add(key)
                        paths.append(p)
            else:
                p = tpl.format(drive=sys_drive, sysdrive=sys_drive)
                key = os.path.normcase(p)
                if key not in seen:
                    seen.add(key)
                    paths.append(p)
        return paths

    @staticmethod
    def _is_symlink_or_junction(path_or_entry):
        """Return True for symlinks and NTFS mount points/junctions (safe for OneDrive cloud folders)."""
        try:
            if hasattr(path_or_entry, "is_symlink"):
                if path_or_entry.is_symlink():
                    return True
                is_junc = getattr(path_or_entry, "is_junction", None)
                if callable(is_junc) and is_junc():
                    return True
                st = path_or_entry.stat(follow_symlinks=False)
            else:
                if os.path.islink(path_or_entry):
                    return True
                is_junc = getattr(os.path, "isjunction", None)
                if callable(is_junc) and is_junc(path_or_entry):
                    return True
                st = os.lstat(path_or_entry)
            if getattr(st, "st_reparse_tag", 0) in (0xA0000003, 0xA000000C):
                return True
        except OSError:
            return True
        return False

    # --- Utility: Locale-independent, DENY-aware SID ACL check ---
    @staticmethod
    def inspect_acl(path):
        """
        Inspect a file's DACL by well-known Windows SIDs (no icacls subprocess).
        Returns (level, label):
          - ("exposed", "Exposed: Everyone" | "Exposed: Anonymous" | "Exposed: NULL DACL")
          - ("shared",  "Shared: Users" | "Shared: AuthUsers")
          - ("private", "Private" | "Protected")
        """
        try:
            sd = win32security.GetFileSecurity(path, win32security.DACL_SECURITY_INFORMATION)
            dacl = sd.GetSecurityDescriptorDacl()
            if dacl is None:
                return "exposed", "Exposed: NULL DACL"

            allow_types = {win32security.ACCESS_ALLOWED_ACE_TYPE}
            deny_types = {win32security.ACCESS_DENIED_ACE_TYPE}
            object_types = set()
            if hasattr(win32security, "ACCESS_ALLOWED_OBJECT_ACE_TYPE"):
                allow_types.add(win32security.ACCESS_ALLOWED_OBJECT_ACE_TYPE)
                object_types.add(win32security.ACCESS_ALLOWED_OBJECT_ACE_TYPE)
            if hasattr(win32security, "ACCESS_DENIED_OBJECT_ACE_TYPE"):
                deny_types.add(win32security.ACCESS_DENIED_OBJECT_ACE_TYPE)
                object_types.add(win32security.ACCESS_DENIED_OBJECT_ACE_TYPE)
            inherit_only = getattr(win32security, "INHERIT_ONLY_ACE", 0x8)

            denied_sids = set()
            exposed_label = None
            shared_label = None

            for i in range(dacl.GetAceCount()):
                try:
                    ace = dacl.GetAce(i)
                    ace_type, ace_flags = ace[0]
                    if ace_flags & inherit_only:
                        continue
                    sid = ace[4] if (ace_type in object_types and len(ace) >= 5) else ace[2]
                    sid_str = win32security.ConvertSidToStringSid(sid)
                except (TypeError, IndexError, win32security.error):
                    continue

                if ace_type in deny_types:
                    denied_sids.add(sid_str)
                    continue
                if ace_type not in allow_types or sid_str in denied_sids:
                    continue

                if sid_str == "S-1-1-0":
                    exposed_label = "Exposed: Everyone"
                elif sid_str == "S-1-5-7" and exposed_label is None:
                    exposed_label = "Exposed: Anonymous"
                elif sid_str == "S-1-5-32-545" and shared_label is None:
                    shared_label = "Shared: Users"
                elif sid_str == "S-1-5-11" and shared_label is None:
                    shared_label = "Shared: AuthUsers"

            if exposed_label:
                return "exposed", exposed_label
            if shared_label:
                return "shared", shared_label
            return "private", "Private"
        except win32security.error as we:
            if getattr(we, "winerror", None) == 5:
                return "private", "Protected"
            return "private", "Private"
        except Exception:
            return "private", "Private"

    @classmethod
    def has_everyone_permission(cls, path):
        """Backward-compatible wrapper returning True when Everyone/Anonymous/NULL DACL has access."""
        level, _ = cls.inspect_acl(path)
        return level == "exposed"

    @staticmethod
    def is_hidden(path):
        """Check Windows FILE_ATTRIBUTE_HIDDEN (not Unix leading-dot convention)."""
        try:
            st = os.lstat(path)
            hidden_flag = getattr(stat, "FILE_ATTRIBUTE_HIDDEN", 0x2)
            return bool(getattr(st, "st_file_attributes", 0) & hidden_flag)
        except OSError:
            return False

    @staticmethod
    def _inspect_rdp_file(path):
        """
        Read-only inspection of .rdp metadata (capped at 64 KB).
        Returns dict: {"skip": bool, "has_password": bool, "note": str}.
        Skips auto-generated Default.rdp files that contain no target/user/password.
        """
        info = {"skip": False, "has_password": False, "note": ""}
        base_l = os.path.basename(path).lower()
        try:
            with open(path, "rb") as fp:
                raw = fp.read(65536)
            if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
                text = raw.decode("utf-16", errors="ignore")
            else:
                text = raw.decode("utf-8", errors="ignore")
            text_l = text.lower()

            has_pwd = "password 51:b:" in text_l
            has_user = bool(re.search(r"(?m)^\s*username:s:\S+", text_l))
            has_addr = bool(re.search(r"(?m)^\s*full address:s:\S+", text_l))

            if has_pwd:
                info["has_password"] = True
                info["note"] = "Saved password"
            elif has_user and has_addr:
                info["note"] = "Target & username saved"
            elif has_user:
                info["note"] = "Username saved"
            elif has_addr:
                info["note"] = "Target host saved"
            elif base_l == "default.rdp":
                info["skip"] = True
        except (PermissionError, FileNotFoundError, OSError):
            pass
        return info

    @classmethod
    def _classify_file(cls, path, acl_level, acl_label, rdp_info=None):
        """Classify a matched sensitive file into (risk_tier, category, detail_note)."""
        base_l = os.path.basename(path).lower()
        _, ext_l = os.path.splitext(base_l)
        path_l = path.lower()

        # Determine category
        if (
            base_l in cls._CRED_KEY_NAMES
            or base_l.startswith("unattend")
            or ext_l in cls._CRED_KEY_EXTS
            or "\\.ssh\\" in path_l
            or "\\.aws\\credentials" in path_l
        ):
            category = "Credentials & Keys"
        elif ext_l in cls._VAULT_EXTS:
            category = "Password Vault"
        elif ext_l in cls._RDP_VPN_EXTS:
            category = "RDP Profile" if ext_l == ".rdp" else "VPN Profile"
        elif ext_l == ".env" or base_l in cls._CONFIG_NAMES or "\\.kube\\" in path_l or "\\.docker\\" in path_l:
            category = "Config & Secret"
        elif ext_l in cls._DB_BACKUP_EXTS or base_l in {"ntds.dit", "sam", "security", "system", "software"}:
            category = "Database & Backup"
        elif ext_l in cls._WEBROOT_EXTS:
            category = "Webroot File"
        else:
            category = "Sensitive File"

        note = (rdp_info or {}).get("note") or ""

        # Determine risk tier
        if acl_level == "exposed" or (rdp_info and rdp_info.get("has_password")):
            risk = "High"
        elif acl_level == "shared":
            risk = "Medium"
        elif category == "Credentials & Keys" or ext_l == ".env" or base_l == ".env":
            # Plaintext credential/key files even with Private ACL warrant Medium attention
            if base_l in {"ntds.dit", "sam", "security", "system", "software"}:
                risk = "Low"
            else:
                risk = "Medium"
        else:
            risk = "Low"

        return risk, category, note

    def _evaluate_match(self, path):
        """Evaluate a candidate file path; returns finding dict or None if skipped."""
        if self._is_symlink_or_junction(path) or not os.path.isfile(path):
            return None

        base_l = os.path.basename(path).lower()
        if base_l in KNOWN_BENIGN_FILES:
            return None

        rdp_info = None
        if base_l.endswith(".rdp"):
            rdp_info = self._inspect_rdp_file(path)
            if rdp_info.get("skip"):
                return None

        acl_level, acl_label = self.inspect_acl(path)
        risk, category, note = self._classify_file(path, acl_level, acl_label, rdp_info=rdp_info)
        return {
            "target": path,
            "risk": risk,
            "category": category,
            "acl": acl_label,
            "note": note,
        }

    # --- SENSITIVE TARGET SCAN ---
    def check_sensitive_targets(self):
        results = []
        SENSITIVE_PATHS = self.build_sensitive_paths()

        for p in SENSITIVE_PATHS:
            matches = glob.glob(p, recursive=False)
            if not matches and "*" not in p and "?" not in p:
                matches = [p]

            for m in matches:
                if not os.path.exists(m):
                    continue
                item = self._evaluate_match(m)
                if item is not None:
                    results.append(item)

        return results

    # --- SEARCH FOR STAGED COPIES ---
    def search_for_db_copies(self, search_dirs, max_depth=3):
        """
        Recursively scan directories for sensitive files.
        Scopes noisy web-code patterns strictly to webroot directories.
        """
        found = []
        sys_drive = self._sys_drive()
        users_prefix = os.path.normcase(os.path.join(sys_drive, "Users") + "\\")
        public_prefix = os.path.normcase(os.path.join(sys_drive, "Users", "Public"))

        base_patterns = tuple(p.lower() for p in SENSITIVE_PATTERNS)
        webroot_patterns = tuple(p.lower() for p in WEBROOT_SENSITIVE_PATTERNS)

        def _is_webroot_dir(dir_norm):
            return any(dir_norm.endswith(m) or (m + "\\") in dir_norm for m in self._WEBROOT_MARKERS)

        def safe_scan(base, depth, skip_user_profiles=True, active_patterns=base_patterns):
            if depth > max_depth:
                return
            try:
                with os.scandir(base) as entries:
                    for entry in entries:
                        try:
                            path = entry.path
                            path_norm = os.path.normcase(path)

                            # Skip user profiles only when walking broader root paths
                            if (
                                skip_user_profiles
                                and path_norm.startswith(users_prefix)
                                and not path_norm.startswith(public_prefix)
                            ):
                                continue

                            if self._is_symlink_or_junction(entry):
                                continue

                            if entry.is_file(follow_symlinks=False):
                                name_l = entry.name.lower()
                                if name_l in KNOWN_BENIGN_FILES:
                                    continue
                                for pat in active_patterns:
                                    if glob.fnmatch.fnmatch(name_l, pat):
                                        item = self._evaluate_match(path)
                                        if item is not None:
                                            found.append(item)
                                        break
                            elif entry.is_dir(follow_symlinks=False):
                                safe_scan(
                                    path,
                                    depth + 1,
                                    skip_user_profiles=skip_user_profiles,
                                    active_patterns=active_patterns,
                                )
                        except (PermissionError, FileNotFoundError, OSError):
                            continue

            except (PermissionError, FileNotFoundError):
                pass
            except Exception as e:
                print(f"[WARN] Could not scan {base}: {e}")

        expanded_dirs = []
        seen_dirs = set()
        for raw_base in search_dirs:
            if not raw_base:
                continue
            base = raw_base.format(sysdrive=sys_drive, drive=sys_drive) if "{" in raw_base else raw_base
            candidates = glob.glob(base) if ("*" in base or "?" in base) else [base]
            for candidate in candidates:
                if os.path.isdir(candidate) and not self._is_symlink_or_junction(candidate):
                    norm_dir = os.path.normcase(os.path.abspath(candidate))
                    if norm_dir not in seen_dirs:
                        seen_dirs.add(norm_dir)
                        expanded_dirs.append(candidate)

        for target_dir in expanded_dirs:
            target_norm = os.path.normcase(os.path.abspath(target_dir))
            skip_profiles = not target_norm.startswith(users_prefix)
            pats = (base_patterns + webroot_patterns) if _is_webroot_dir(target_norm) else base_patterns
            safe_scan(target_dir, 0, skip_user_profiles=skip_profiles, active_patterns=pats)

        # Deduplicate and sort
        seen = set()
        out = []
        for item in sorted(found, key=lambda x: x["target"].lower()):
            k = os.path.normcase(os.path.abspath(item["target"]))
            if k not in seen:
                seen.add(k)
                out.append(item)
        return out

    # --- MINIMAL REPORT ---
    @classmethod
    def minimal_report(cls, targets, copies):
        risk_rank = {"High": 0, "Medium": 1, "Low": 2}
        merged = {}

        for item in targets + copies:
            target = item["target"]
            key = os.path.normcase(os.path.abspath(target))
            cur_rank = risk_rank.get(item.get("risk"), 3)
            if key not in merged or cur_rank < risk_rank.get(merged[key].get("risk"), 3):
                merged[key] = item

        ordered = sorted(
            merged.values(),
            key=lambda x: (risk_rank.get(x.get("risk"), 3), x["target"].lower()),
        )

        if not ordered:
            return "No sensitive files detected"

        lines = ["", "Sensitive Files Detected:"]
        shown = ordered[: cls._MAX_DISPLAY]
        for item in shown:
            parts = [
                item.get("risk", "Low"),
                item.get("category", "Sensitive File"),
                item.get("acl", "Private"),
            ]
            if item.get("note"):
                parts.append(item["note"])
            lines.append(f"- {item['target']} ({' | '.join(parts)})")

        extra = len(ordered) - len(shown)
        if extra > 0:
            lines.append(f"... (+{extra} more)")

        return "\n".join(lines)

    # --- STRUCTURED CHECK ---
    def check_sensitive_paths(self, check_dirs=None):
        if check_dirs is None:
            check_dirs = DEFAULT_COPY_SEARCH

        if not (os.name == "nt" or platform.system().lower() == "windows"):
            return {"error": "[ERROR] This script is intended for Windows hosts.", "targets": [], "copies": []}

        targets = self.check_sensitive_targets()
        copies = self.search_for_db_copies(check_dirs)
        return {"targets": targets, "copies": copies}

    # --- ENTRY POINT ---
    def show_sensitive_paths(self, check_dirs=None, run_all_clicked=None, single_check=None):
        cls = type(self)

        if run_all_clicked is None:
            run_all_clicked = secuditor_modules.run_all_clicked
        if single_check is None:
            single_check = secuditor_modules.single_check

        if (
            check_dirs is None
            and cls._cache is not None
            and not run_all_clicked
            and not single_check
        ):
            return cls._cache

        result = self.check_sensitive_paths(check_dirs=check_dirs)
        if "error" in result:
            return result["error"]
        formatted = self.minimal_report(result["targets"], result["copies"])
        if check_dirs is None:
            cls._cache = formatted
        return formatted

# ===== Suspicious Processes =====
class SuspiciousProcesses:

    _cache = None

    # --- Get private connections ---
    @staticmethod
    def is_private_ip(ip):
        """Check if an IP is private or loopback"""
        try:
            addr = ipaddress.ip_address(ip)
            return addr.is_private or addr.is_loopback
        except ValueError:
            return True

    # --- Get exposed external ports ---
    @staticmethod
    def is_external(ip):
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip == "0.0.0.0" or ip == "::" or not (ip_obj.is_private or ip_obj.is_loopback)
        except ValueError:
            return False

    # --- Detect incoming activity ---
    @classmethod
    def detect_incoming_activity(cls, pid, conns):
        try:
            listen_ports = {
                c.laddr.port
                for c in conns
                if c.pid == pid and c.status == psutil.CONN_LISTEN and c.laddr
            }

            for c in conns:
                if c.pid != pid:
                    continue

                if c.status == psutil.CONN_LISTEN and c.laddr:
                    try:
                        lip = ipaddress.ip_address(str(c.laddr.ip).split("%", 1)[0])
                        if not lip.is_loopback:
                            return True
                    except ValueError:
                        if c.laddr.ip in ("0.0.0.0", "::"):
                            return True

                elif c.status == psutil.CONN_ESTABLISHED and c.raddr and c.laddr:
                    if c.laddr.port in listen_ports and cls.is_external(c.raddr.ip):
                        return True

        except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
            pass

        return False

    # --- Detect outgoing activity ---
    @classmethod
    def detect_outgoing_activity(cls, pid, conns):
        try:
            for c in conns:
                if c.pid == pid and c.status == psutil.CONN_ESTABLISHED:
                    if c.raddr and not cls.is_private_ip(c.raddr.ip):
                        return True
        except Exception:
            pass

        return False

    _last_clipboard_seq = None

    # --- Clipboard monitoring ---
    @classmethod
    def get_clipboard_events(cls):
        """
        Snapshot clipboard sequence changes without blocking or locking OpenClipboard().

        Returns:
            list of clipboard change events observed since the previous baseline.
        """
        events = []
        try:
            user32 = ctypes.WinDLL(_system_exe("user32.dll"), use_last_error=True)
            get_seq = user32.GetClipboardSequenceNumber
            get_seq.argtypes = []
            get_seq.restype = wintypes.DWORD
            seq = int(get_seq())
            if cls._last_clipboard_seq is None:
                # Establish baseline only; do not treat pre-existing clipboard content as a change
                cls._last_clipboard_seq = seq
            elif seq != cls._last_clipboard_seq:
                cls._last_clipboard_seq = seq
                events.append({
                    "timestamp": time.time(),
                    "size": 0,
                })
        except Exception:
            pass

        return events

    # --- Process privilege / module helpers ---
    _win_elevation_apis = None

    @classmethod
    def _get_win_elevation_apis(cls):
        if cls._win_elevation_apis is None:
            kernel32 = ctypes.WinDLL(_system_exe("kernel32.dll"), use_last_error=True)
            advapi32 = ctypes.WinDLL(_system_exe("advapi32.dll"), use_last_error=True)

            open_process = kernel32.OpenProcess
            open_process.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
            open_process.restype = wintypes.HANDLE

            close_handle = kernel32.CloseHandle
            close_handle.argtypes = [wintypes.HANDLE]
            close_handle.restype = wintypes.BOOL

            open_process_token = advapi32.OpenProcessToken
            open_process_token.argtypes = [
                wintypes.HANDLE,
                wintypes.DWORD,
                ctypes.POINTER(wintypes.HANDLE),
            ]
            open_process_token.restype = wintypes.BOOL

            get_token_info = advapi32.GetTokenInformation
            get_token_info.argtypes = [
                wintypes.HANDLE,
                wintypes.DWORD,
                wintypes.LPVOID,
                wintypes.DWORD,
                ctypes.POINTER(wintypes.DWORD),
            ]
            get_token_info.restype = wintypes.BOOL

            cls._win_elevation_apis = (
                open_process,
                open_process_token,
                get_token_info,
                close_handle,
            )
        return cls._win_elevation_apis

    @classmethod
    def is_process_elevated(cls, pid):
        """
        Return:
            True  - process has an elevated token
            False - process has a non-elevated token
            None  - elevation could not be determined
        """
        try:
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            TOKEN_QUERY = 0x0008
            TokenElevation = 20

            OpenProcess, OpenProcessToken, GetTokenInformation, CloseHandle = (
                cls._get_win_elevation_apis()
            )

            process_handle = OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION,
                False,
                int(pid),
            )

            if not process_handle:
                return None

            try:
                token_handle = wintypes.HANDLE()

                if not OpenProcessToken(
                    process_handle,
                    TOKEN_QUERY,
                    ctypes.byref(token_handle)
                ):
                    return None

                try:
                    elevation = wintypes.DWORD()
                    returned = wintypes.DWORD()

                    success = GetTokenInformation(
                        token_handle,
                        TokenElevation,
                        ctypes.byref(elevation),
                        ctypes.sizeof(elevation),
                        ctypes.byref(returned)
                    )

                    if not success:
                        return None

                    return elevation.value != 0

                finally:
                    CloseHandle(token_handle)

            finally:
                CloseHandle(process_handle)

        except Exception:
            return None

    @staticmethod
    def get_module_anomalies(proc, sig_status="Unknown"):
        """
        Identify unusual DLL/module locations for a process.

        Returns a list of anomalous module paths.
        """
        anomalies = []

        try:
            modules = proc.memory_maps()

            suspicious_locations = (
                "\\appdata\\roaming\\",
                "\\appdata\\local\\temp\\",
                "\\temp\\",
                "\\downloads\\",
                "\\desktop\\",
                "\\documents\\",
                "\\public\\",
                "\\programdata\\",
                "\\recycler\\",
                "\\$recycle.bin\\",
                "\\perflogs\\",
            )

            sys_root = os.environ.get("SystemRoot") or r"C:\Windows"
            win_module_prefixes = tuple(
                os.path.normcase(os.path.join(sys_root, sub)) + os.sep
                for sub in ("System32", "SysWOW64", "WinSxS")
            )

            for module in modules:
                path = getattr(module, "path", None)

                if not path:
                    continue

                path_lower = os.path.normcase(path).lower()

                # Skip normal Windows modules.
                if path_lower.startswith(win_module_prefixes):
                    continue

                # User-writable / suspicious module location.
                if any(location in path_lower for location in suspicious_locations):
                    anomalies.append(path)

        except (
            psutil.AccessDenied,
            psutil.NoSuchProcess,
            FileNotFoundError,
            OSError
        ):
            pass
        except Exception:
            pass

        return list(dict.fromkeys(anomalies))

    # --- Checks for Process Injection ---
    @staticmethod
    def check_process_injection_indicators(pid):
        """
        Identify private executable memory regions that may warrant
        investigation for process injection.

        Private executable memory alone is not proof of injection.
        This function collects indicators only; risk scoring and
        correlation with other findings belong in the main audit.

        Returns a list of diagnostic findings.
        """

        if os.name != "nt":
            return []

        PROCESS_QUERY_INFORMATION = 0x0400
        PROCESS_VM_READ = 0x0010

        MEM_COMMIT = 0x1000
        MEM_PRIVATE = 0x20000

        PAGE_NOACCESS = 0x01
        PAGE_EXECUTE = 0x10
        PAGE_EXECUTE_READ = 0x20
        PAGE_EXECUTE_READWRITE = 0x40
        PAGE_EXECUTE_WRITECOPY = 0x80

        PAGE_GUARD = 0x100
        PAGE_PROTECTION_MASK = 0xFF

        executable_protections = {
            PAGE_EXECUTE,
            PAGE_EXECUTE_READ,
            PAGE_EXECUTE_READWRITE,
            PAGE_EXECUTE_WRITECOPY,
        }

        protection_names = {
            PAGE_EXECUTE: "EXECUTE",
            PAGE_EXECUTE_READ: "EXECUTE_READ",
            PAGE_EXECUTE_READWRITE: "EXECUTE_READWRITE",
            PAGE_EXECUTE_WRITECOPY: "EXECUTE_WRITECOPY",
        }

        is_64bit = ctypes.sizeof(ctypes.c_void_p) == 8

        class MEMORY_BASIC_INFORMATION(ctypes.Structure):
            _fields_ = (
                [
                    ("BaseAddress", ctypes.c_void_p),
                    ("AllocationBase", ctypes.c_void_p),
                    ("AllocationProtect", wintypes.DWORD),
                ]
                + ([("PartitionId", wintypes.WORD)] if is_64bit else [])
                + [
                    ("RegionSize", ctypes.c_size_t),
                    ("State", wintypes.DWORD),
                    ("Protect", wintypes.DWORD),
                    ("Type", wintypes.DWORD),
                ]
            )

        kernel32 = ctypes.WinDLL(_system_exe("kernel32.dll"), use_last_error=True)

        kernel32.OpenProcess.argtypes = [
            wintypes.DWORD,
            wintypes.BOOL,
            wintypes.DWORD,
        ]
        kernel32.OpenProcess.restype = wintypes.HANDLE

        kernel32.VirtualQueryEx.argtypes = [
            wintypes.HANDLE,
            ctypes.c_void_p,
            ctypes.POINTER(MEMORY_BASIC_INFORMATION),
            ctypes.c_size_t,
        ]
        kernel32.VirtualQueryEx.restype = ctypes.c_size_t

        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL

        handle = kernel32.OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            False,
            int(pid),
        )

        if not handle:
            return []

        findings = []
        address = 0
        max_regions = 4096
        max_findings = 5
        truncated = False

        try:
            for _ in range(max_regions):
                mbi = MEMORY_BASIC_INFORMATION()

                queried = kernel32.VirtualQueryEx(
                    handle,
                    ctypes.c_void_p(address),
                    ctypes.byref(mbi),
                    ctypes.sizeof(mbi),
                )

                if not queried:
                    break

                protection = mbi.Protect & PAGE_PROTECTION_MASK
                has_guard = bool(mbi.Protect & PAGE_GUARD)

                is_executable = protection in executable_protections

                if (
                    mbi.State == MEM_COMMIT
                    and mbi.Type == MEM_PRIVATE
                    and is_executable
                    and not has_guard
                ):
                    if len(findings) >= max_findings:
                        truncated = True
                        break

                    protection_name = protection_names.get(
                        protection,
                        f"UNKNOWN (0x{protection:X})",
                    )

                    alloc_base = mbi.AllocationBase or 0
                    findings.append(
                        "Private executable memory candidate: "
                        f"address=0x{address:X}, "
                        f"allocation_base=0x{alloc_base:X}, "
                        f"size={mbi.RegionSize} bytes, "
                        f"protection={protection_name}"
                    )

                if not mbi.RegionSize:
                    break

                next_address = address + mbi.RegionSize

                if next_address <= address:
                    break

                address = next_address

            if findings and truncated:
                findings.append(
                    f"Additional regions may exist; "
                    f"report limited to {max_findings} candidates"
                )

        except (OSError, ValueError, ctypes.ArgumentError):
            pass

        finally:
            kernel32.CloseHandle(handle)

        return findings

    # --- Check valid Microsoft signature ---
    @staticmethod
    @lru_cache(maxsize=512)
    def is_microsoft_signed(exe_path):
        """Return True only when the executable has a valid Microsoft signature."""

        if not exe_path or not os.path.isfile(exe_path):
            return False

        try:
            command = (
                "$sig = Get-AuthenticodeSignature -LiteralPath $env:SECUDITOR_SIG_PATH; "
                "$publisher = ''; "
                "if ($sig.SignerCertificate) { "
                "$publisher = $sig.SignerCertificate.GetNameInfo("
                "[System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, "
                "$false) "
                "}; "
                "[PSCustomObject]@{Status=$sig.Status.ToString(); Publisher=$publisher} "
                "| ConvertTo-Json -Compress"
            )

            output = subprocess.check_output(
                [
                    _system_exe("powershell.exe"),
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    command,
                ],
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=10,
                env=_safe_subproc_env({"SECUDITOR_SIG_PATH": exe_path}),
                stderr=subprocess.DEVNULL,
                **_subproc_kwargs_hide_window()
            )

            data = json.loads(output)

            publisher = data.get("Publisher", "")
            status = data.get("Status", "")

            return (
                status == "Valid"
                and publisher.casefold() in {
                    "microsoft corporation",
                    "microsoft windows",
                    "microsoft windows publisher",
                    "microsoft windows component publisher",
                }
            )

        except (subprocess.SubprocessError, OSError, ValueError, TypeError):
            return False

    @staticmethod
    def _resolve_prefixes(prefixes):
        """Resolve canonical C:\\Windows / C:\\Program Files prefixes to runtime roots and normalize."""
        win_root = os.environ.get("SystemRoot") or r"C:\Windows"
        pf_x86 = os.environ.get("ProgramFiles(x86)") or r"C:\Program Files (x86)"
        pf = os.environ.get("ProgramFiles") or r"C:\Program Files"
        resolved = []
        for raw in prefixes:
            if not raw:
                continue
            low = raw.lower()
            if low.startswith("c:\\windows\\") or low == "c:\\windows":
                mapped = win_root + raw[len("c:\\windows"):]
            elif low.startswith("c:\\program files (x86)\\") or low == "c:\\program files (x86)":
                mapped = pf_x86 + raw[len("c:\\program files (x86)"):]
            elif low.startswith("c:\\program files\\") or low == "c:\\program files":
                mapped = pf + raw[len("c:\\program files"):]
            else:
                mapped = raw
            resolved.append(os.path.normcase(os.path.normpath(mapped)))
        return resolved

    @staticmethod
    def _path_matches_prefixes(normalized_path, normalized_prefixes):
        """Match an executable path against exact file paths or directory prefixes via commonpath."""
        for prefix in normalized_prefixes:
            if normalized_path == prefix:
                return True
            if prefix.endswith(".exe"):
                continue
            try:
                if os.path.commonpath([normalized_path, prefix]) == prefix:
                    return True
            except ValueError:
                continue
        return False

    @staticmethod
    def _compile_cmd_patterns(patterns):
        """Compile command-line patterns with token/path boundaries so substrings don't false-match."""
        compiled = []
        for raw in patterns:
            if not raw:
                continue
            pat = raw.strip().lower()
            if not pat:
                continue
            parts = pat.split()
            if pat.startswith("-"):
                escaped = r"\s+".join(re.escape(part) for part in parts)
                regex = re.compile(rf"(?:^|\s){escaped}(?=\s|$|=|:)")
            elif len(parts) > 1:
                first = re.escape(parts[0])
                if not parts[0].endswith((".exe", ".dll")) and not parts[0].startswith(("-", "/")):
                    first += r"(?:\.exe)?"
                rest = r"\s+".join(re.escape(part) for part in parts[1:])
                regex = re.compile(rf"(?:^|[\s\"'\\/(\[.]){first}\s+{rest}(?=$|[\s\"'();.,:\]])")
            else:
                token = re.escape(parts[0])
                if not parts[0].endswith((".exe", ".dll")):
                    token += r"(?:\.exe)?"
                regex = re.compile(rf"(?:^|[\s\"'\\/(\[.]){token}(?=$|[\s\"'();.,:\]])")
            compiled.append((pat, regex))
        return compiled

    # --- Indicator constants & helpers ---
    _win_fs_apis = None

    _CORE_PARENT_RULES = {
        "svchost.exe": frozenset({"services.exe"}),
        "services.exe": frozenset({"wininit.exe"}),
        "lsass.exe": frozenset({"wininit.exe"}),
        "lsaiso.exe": frozenset({"wininit.exe"}),
        "spoolsv.exe": frozenset({"services.exe"}),
        "smss.exe": frozenset({"system", "smss.exe"}),
        "taskhostw.exe": frozenset({"svchost.exe"}),
    }

    _TYPOSQUAT_TARGETS = (
        "svchost",
        "lsass",
        "csrss",
        "services",
        "winlogon",
        "wininit",
        "explorer",
        "spoolsv",
        "taskhostw",
        "runtimebroker",
        "smartscreen",
    )

    _TYPOSQUAT_EXCLUDE = frozenset({
        "sihost",
        "dllhost",
        "conhost",
        "dashost",
        "wudfhost",
        "shellhost",
        "searchhost",
        "fontdrvhost",
    })

    _DOUBLE_EXT_RE = re.compile(
        r"\.(?:pdf|docx?|xlsx?|pptx?|txt|rtf|jpe?g|png|gif|mp[34]|zip|rar|7z|iso)"
        r"\.(?:exe|scr|com|pif|bat|cmd|vbs|js|hta)$",
        re.IGNORECASE,
    )

    _MOTW_ZONE_RE = re.compile(r"(?im)^\s*ZoneId\s*=\s*([34])\b")

    _STARTUP_EXEC_EXTS = frozenset({
        ".exe", ".bat", ".cmd", ".vbs", ".js", ".ps1", ".scr", ".com", ".pif", ".hta",
    })

    _WINLOGON_DEFAULTS = frozenset({
        "explorer.exe", "explorer", "userinit.exe", "userinit",
    })

    @staticmethod
    def _extract_exec_name(cmd_str):
        if not isinstance(cmd_str, str):
            return ""
        s = cmd_str.strip()
        if not s:
            return ""
        m = re.match(r'^(?:"([^"]+)"|\'([^\']+)\'|(.+?\.exe)(?=\s|$)|(\S+))', s, re.IGNORECASE)
        if not m:
            return ""
        token = next((g for g in m.groups() if g), "").strip()
        return os.path.basename(token).lower() if token else ""

    @classmethod
    def _get_win_fs_apis(cls):
        if cls._win_fs_apis is None:
            kernel32 = ctypes.WinDLL(_system_exe("kernel32.dll"), use_last_error=True)

            get_file_attrs = kernel32.GetFileAttributesW
            get_file_attrs.argtypes = [wintypes.LPCWSTR]
            get_file_attrs.restype = wintypes.DWORD

            get_drive_type = kernel32.GetDriveTypeW
            get_drive_type.argtypes = [wintypes.LPCWSTR]
            get_drive_type.restype = wintypes.UINT

            cls._win_fs_apis = (get_file_attrs, get_drive_type)
        return cls._win_fs_apis

    @staticmethod
    def _levenshtein_distance(a, b):
        if a == b:
            return 0
        if abs(len(a) - len(b)) > 2:
            return 3
        prev = list(range(len(b) + 1))
        for i, ca in enumerate(a, 1):
            curr = [i] + [0] * len(b)
            row_min = i
            for j, cb in enumerate(b, 1):
                cost = 0 if ca == cb else 1
                val = min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost)
                curr[j] = val
                if val < row_min:
                    row_min = val
            if row_min > 2:
                return 3
            prev = curr
        return prev[-1]

    @classmethod
    def _find_typosquat_target(cls, stem):
        if not stem or stem in cls._TYPOSQUAT_EXCLUDE:
            return None
        for target in cls._TYPOSQUAT_TARGETS:
            max_dist = 1 if len(target) <= 6 else 2
            dist = cls._levenshtein_distance(stem, target)
            if 1 <= dist <= max_dist:
                return f"{target}.exe"
        return None

    @classmethod
    def _get_motw_zone(cls, path, cache):
        key = os.path.normcase(path)
        if key in cache:
            return cache[key]
        zone_id = None
        try:
            with open(f"{path}:Zone.Identifier", "r", encoding="utf-8", errors="ignore") as f:
                content = f.read(4096)
            m = cls._MOTW_ZONE_RE.search(content)
            if m:
                zone_id = m.group(1)
        except OSError:
            zone_id = None
        cache[key] = zone_id
        return zone_id

    @classmethod
    def _has_hidden_or_system_attr(cls, path, cache):
        key = os.path.normcase(path)
        if key in cache:
            return cache[key]
        flagged = False
        try:
            get_file_attrs, _ = cls._get_win_fs_apis()
            attrs = int(get_file_attrs(path))
            # 0xFFFFFFFF = INVALID_FILE_ATTRIBUTES; 0x2 = HIDDEN; 0x4 = SYSTEM
            if attrs != 0xFFFFFFFF and (attrs & (0x2 | 0x4)):
                flagged = True
        except Exception:
            flagged = False
        cache[key] = flagged
        return flagged

    @classmethod
    def _is_removable_drive(cls, path, cache):
        drive, _ = os.path.splitdrive(path)
        if len(drive) != 2 or drive[1] != ":":
            return False, ""
        drive_key = drive.upper()
        if drive_key not in cache:
            is_rem = False
            try:
                _, get_drive_type = cls._get_win_fs_apis()
                # 2 = DRIVE_REMOVABLE
                is_rem = int(get_drive_type(drive_key + "\\")) == 2
            except Exception:
                is_rem = False
            cache[drive_key] = is_rem
        return cache[drive_key], drive_key

    @classmethod
    def _preload_ifeo_execs(cls):
        ifeo_execs = set()
        ifeo_root = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
        for access in (
            winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
            winreg.KEY_READ | winreg.KEY_WOW64_32KEY,
        ):
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, ifeo_root, 0, access) as root_key:
                    i = 0
                    while True:
                        try:
                            subkey_name = winreg.EnumKey(root_key, i)
                            i += 1
                        except OSError:
                            break
                        if subkey_name.lower() == "yourimagefilenameherewithoutanyextension":
                            continue
                        try:
                            with winreg.OpenKey(root_key, subkey_name, 0, access) as sub_key:
                                val, _ = winreg.QueryValueEx(sub_key, "Debugger")
                                if isinstance(val, str) and val.strip():
                                    exe_name = cls._extract_exec_name(val)
                                    if exe_name:
                                        ifeo_execs.add(exe_name)
                        except OSError:
                            continue
            except OSError:
                continue
        return ifeo_execs

    @classmethod
    def _preload_startup_persistence(cls):
        startup_folder_execs = set()
        runonce_execs = set()
        winlogon_execs = set()

        # 1. RunOnce keys
        runonce_keys = [
            (
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
                winreg.KEY_READ,
            ),
            (
                winreg.HKEY_LOCAL_MACHINE,
                r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
                winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
            ),
            (
                winreg.HKEY_LOCAL_MACHINE,
                r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
                winreg.KEY_READ | winreg.KEY_WOW64_32KEY,
            ),
        ]
        for hive, reg_path, access in runonce_keys:
            try:
                with winreg.OpenKey(hive, reg_path, 0, access) as reg_key:
                    i = 0
                    while True:
                        try:
                            _, value, _ = winreg.EnumValue(reg_key, i)
                            i += 1
                            if isinstance(value, str):
                                exe_name = cls._extract_exec_name(value)
                                if exe_name:
                                    runonce_execs.add(exe_name)
                        except OSError:
                            break
            except OSError:
                continue

        # 2. Winlogon Shell & Userinit (excluding Windows defaults)
        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
                0,
                winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
            ) as wl_key:
                for val_name in ("Shell", "Userinit"):
                    try:
                        val, _ = winreg.QueryValueEx(wl_key, val_name)
                        if isinstance(val, str):
                            for part in val.split(","):
                                exe_name = cls._extract_exec_name(part)
                                if exe_name and exe_name not in cls._WINLOGON_DEFAULTS:
                                    winlogon_execs.add(exe_name)
                    except OSError:
                        continue
        except OSError:
            pass

        # 3. User & Common Startup folders (direct executables and .lnk targets)
        startup_dirs = []
        if os.environ.get("APPDATA"):
            startup_dirs.append(
                os.path.join(
                    os.environ["APPDATA"],
                    r"Microsoft\Windows\Start Menu\Programs\Startup",
                )
            )
        if os.environ.get("ProgramData"):
            startup_dirs.append(
                os.path.join(
                    os.environ["ProgramData"],
                    r"Microsoft\Windows\Start Menu\Programs\StartUp",
                )
            )

        lnk_files = []
        for sdir in startup_dirs:
            if not os.path.isdir(sdir):
                continue
            try:
                for entry in os.listdir(sdir):
                    full_path = os.path.join(sdir, entry)
                    if not os.path.isfile(full_path):
                        continue
                    ext = os.path.splitext(entry)[1].lower()
                    if ext == ".lnk":
                        lnk_files.append(full_path)
                    elif ext in cls._STARTUP_EXEC_EXTS:
                        startup_folder_execs.add(entry.lower())
            except OSError:
                continue

        if lnk_files:
            com_inited = False
            try:
                import pythoncom
                from win32com.shell import shell

                pythoncom.CoInitialize()
                com_inited = True
                for lnk_path in lnk_files:
                    try:
                        link = pythoncom.CoCreateInstance(
                            shell.CLSID_ShellLink,
                            None,
                            pythoncom.CLSCTX_INPROC_SERVER,
                            shell.IID_IShellLink,
                        )
                        # 0 = STGM_READ (strictly read-only)
                        link.QueryInterface(pythoncom.IID_IPersistFile).Load(lnk_path, 0)
                        target, _ = link.GetPath(shell.SLGP_RAWPATH)
                        if target:
                            exe_name = cls._extract_exec_name(target)
                            if exe_name:
                                startup_folder_execs.add(exe_name)
                    except Exception:
                        continue
            except Exception:
                pass
            finally:
                if com_inited:
                    try:
                        pythoncom.CoUninitialize()
                    except Exception:
                        pass

        return startup_folder_execs, runonce_execs, winlogon_execs

    @classmethod
    def _preload_wmi_subscription_execs(cls):
        wmi_execs = set()
        try:
            shell32 = ctypes.WinDLL(_system_exe("shell32.dll"), use_last_error=True)
            if not shell32.IsUserAnAdmin():
                return wmi_execs
        except Exception:
            return wmi_execs

        com_inited = False
        try:
            import pythoncom
            import win32com.client

            pythoncom.CoInitialize()
            com_inited = True
            wmi = win32com.client.GetObject(r"winmgmts:\\.\root\subscription")
            for consumer in wmi.ExecQuery(
                "SELECT ExecutablePath, CommandLineTemplate FROM CommandLineEventConsumer"
            ):
                for attr in ("ExecutablePath", "CommandLineTemplate"):
                    val = getattr(consumer, attr, None)
                    if isinstance(val, str) and val.strip():
                        exe_name = cls._extract_exec_name(val)
                        if exe_name:
                            wmi_execs.add(exe_name)
        except Exception:
            wmi_execs = set()
        finally:
            if com_inited:
                try:
                    pythoncom.CoUninitialize()
                except Exception:
                    pass
        return wmi_execs

    # --- Checks for Suspicious Processes ---
    def check_suspicious_processes(self):
        """
        Scan running processes for suspicious activity.
        Includes triggers from Scheduled Tasks and Registry Run keys.
        Returns a sorted list of deduplicated suspicious process tuples.
        """

        def strip_extension(name):
            if not name:
                return ""
            parts = name.split(".")
            if len(parts) == 1:
                return name.lower()
            return ".".join(parts[:-1]).lower()

        # --- Configs ---
        self_pid = os.getpid()

        clipboard_events = self.get_clipboard_events()

        suspicious_parents = {
            pname.lower(): [p.lower() for p in parents]
            for pname, parents in SUSPICIOUS_PARENTS.items()
        }

        compiled_cmd_patterns = self._compile_cmd_patterns(SUSPICIOUS_CMD_PATTERNS)

        legit_process = {p.lower() for p in LEGIT_NETWORK_APPLICATIONS}
        known_system = {p.lower() for p in KNOWN_SYSTEM_PROCESSES}
        suspicious_locations = {p.lower() for p in SUSPICIOUS_EXECUTABLE_LOCATIONS}
        system_prefixes = self._resolve_prefixes(SYSTEM_PATH_PREFIXES)
        application_prefixes = self._resolve_prefixes(APPLICATIONS_PATH_PREFIXES)

        results = []
        total = 0

        # --- Connections cache ---
        try:
            conns = psutil.net_connections(kind="inet")
        except Exception:
            conns = []

        # --- Signature cache ---
        signature_cache = {}

        # --- Visible windows cache ---
        visible_pids = set()

        try:
            def enum_windows(hwnd, _):
                if win32gui.IsWindowVisible(hwnd):
                    _, pid = win32process.GetWindowThreadProcessId(hwnd)
                    visible_pids.add(pid)

            win32gui.EnumWindows(enum_windows, None)

        except Exception:
            pass

        _extract_exec_name = self._extract_exec_name

        # --- Preload scheduled tasks executables ---
        scheduled_execs = set()
        try:
            raw_xml = subprocess.check_output(
                [_system_exe("schtasks"), "/query", "/xml", "ONE"],
                timeout=10,
                env=_safe_subproc_env(),
                stderr=subprocess.DEVNULL,
                **_subproc_kwargs_hide_window()
            )
            if raw_xml.startswith((b"\xff\xfe", b"\xfe\xff")):
                xml_text = raw_xml.decode("utf-16", errors="replace")
            else:
                try:
                    xml_text = raw_xml.decode("utf-8-sig")
                except UnicodeDecodeError:
                    xml_text = raw_xml.decode("mbcs", errors="replace")
            xml_text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", xml_text)
            try:
                root = ET.fromstring(xml_text)
                for elem in root.iter():
                    if elem.tag.rsplit("}", 1)[-1] == "Command" and elem.text:
                        exe_name = _extract_exec_name(elem.text)
                        if exe_name:
                            scheduled_execs.add(exe_name)
            except ET.ParseError:
                for match in re.finditer(
                    r"<Command\b[^>]*>(.*?)</Command>",
                    xml_text,
                    re.IGNORECASE | re.DOTALL,
                ):
                    exe_name = _extract_exec_name(html.unescape(match.group(1)))
                    if exe_name:
                        scheduled_execs.add(exe_name)
        except Exception:
            scheduled_execs = set()

        # --- Preload registry run key executables ---
        registry_execs = set()
        run_keys = [
            (
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                winreg.KEY_READ,
            ),
            (
                winreg.HKEY_LOCAL_MACHINE,
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
            ),
            (
                winreg.HKEY_LOCAL_MACHINE,
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                winreg.KEY_READ | winreg.KEY_WOW64_32KEY,
            ),
        ]
        for hive, path, access in run_keys:
            try:
                with winreg.OpenKey(hive, path, 0, access) as reg_key:
                    i = 0
                    while True:
                        try:
                            _, value, _ = winreg.EnumValue(reg_key, i)
                            i += 1
                            if not isinstance(value, str):
                                continue
                            exe_name = _extract_exec_name(value)
                            if exe_name:
                                registry_execs.add(exe_name)
                        except OSError:
                            break
            except Exception:
                continue

        # --- Preload IFEO, Startup/RunOnce/Winlogon, and WMI persistence ---
        ifeo_execs = self._preload_ifeo_execs()
        startup_folder_execs, runonce_execs, winlogon_execs = self._preload_startup_persistence()
        wmi_execs = self._preload_wmi_subscription_execs()

        motw_cache = {}
        hidden_attr_cache = {}
        drive_type_cache = {}

        process_name_counts = {}

        for proc in psutil.process_iter(['name']):
            try:
                pname = (proc.info.get("name") or "").lower()

                if pname:
                    process_name_counts[pname] = process_name_counts.get(pname, 0) + 1

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # --- Scan running processes ---
        is_frozen = getattr(sys, "frozen", False)
        parent_pid = os.getppid() if is_frozen else None
        try:
            self_path = os.path.normcase(psutil.Process(self_pid).exe()) if is_frozen else None
        except Exception:
            self_path = None

        scan_now = time.time()
        try:
            boot_grace = (scan_now - psutil.boot_time()) < 180
        except Exception:
            boot_grace = False

        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                # Skip Secuditor's own process (and its PyInstaller bootloader parent when frozen)
                if proc.pid == self_pid:
                    continue

                try:
                    path = proc.exe()
                    proc_path = os.path.normcase(path)
                except (psutil.AccessDenied, psutil.NoSuchProcess, FileNotFoundError):
                    path = None
                    proc_path = None

                if is_frozen and proc.pid == parent_pid and self_path and proc_path == self_path:
                    continue

                total += 1
                pname = (proc.info.get("name") or "").lower()
                cmdline = " ".join(proc.info.get('cmdline') or []).lower()
                risk = 0
                reasons = []

                normalized_path = os.path.normcase(os.path.abspath(path)) if path else None

                # --- Windows system path & application path checks ---
                is_windows_path = (
                    self._path_matches_prefixes(normalized_path, system_prefixes)
                    if normalized_path
                    else False
                )
                is_application_path = (
                    self._path_matches_prefixes(normalized_path, application_prefixes)
                    if normalized_path
                    else False
                )

                # --- System process impersonation ---
                try:
                    if (
                        pname in known_system
                        and path
                        and not is_windows_path
                    ):
                        risk += 20
                        reasons.append("Fake system process")

                except Exception:
                    pass

                # --- Suspicious remote port check ---
                try:
                    for c in conns:
                        if (
                            c.pid == proc.pid
                            and c.status == psutil.CONN_ESTABLISHED
                            and c.raddr
                        ):
                            remote_port = c.raddr.port

                            if remote_port in SUSPICIOUS_REMOTE_PORTS:
                                risk += 20
                                reasons.append(
                                    f"Suspicious remote port ({remote_port})"
                                )
                                break

                except Exception:
                    pass

                # --- Cmdline patterns ---
                matched_cmd_patterns = [
                    pat
                    for pat, regex in compiled_cmd_patterns
                    if regex.search(cmdline)
                ]

                if matched_cmd_patterns:
                    risk += 20

                    # Limit output to avoid huge reports
                    reasons.append(
                        f"Suspicious cmdline ({', '.join(matched_cmd_patterns[:3])})"
                    )

                # --- Parent process ---
                try:
                    parent = proc.parent()

                    if parent:
                        parent_name = (parent.name() or "").lower()
                        parent_list = suspicious_parents.get(pname, [])

                        if parent_name in parent_list or strip_extension(parent_name) in parent_list:
                            risk += 20
                            reasons.append(f"Odd parent: {parent_name}")

                        # --- Core Windows parent-tree anomaly ---
                        expected_parents = self._CORE_PARENT_RULES.get(pname)
                        if expected_parents and parent_name and parent_name not in expected_parents:
                            try:
                                if parent.create_time() <= proc.create_time() + 1.0:
                                    risk += 20
                                    reasons.append(f"Unexpected system parent: {parent_name}")
                            except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                                pass

                except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                    pass

                # --- Scheduled task trigger ---
                pname_stem = strip_extension(pname)
                if pname in scheduled_execs or pname_stem in scheduled_execs:
                    risk += 10
                    reasons.append("Found in scheduled tasks")

                # --- Registry Run key trigger ---
                if pname in registry_execs or pname_stem in registry_execs:
                    risk += 10
                    reasons.append("Found in registry Run keys")

                # --- Startup folder / RunOnce / Winlogon persistence ---
                startup_sources = []
                if pname in startup_folder_execs or pname_stem in startup_folder_execs:
                    startup_sources.append("Startup")
                if pname in runonce_execs or pname_stem in runonce_execs:
                    startup_sources.append("RunOnce")
                if pname in winlogon_execs or pname_stem in winlogon_execs:
                    startup_sources.append("Winlogon")
                if startup_sources:
                    risk += 10
                    reasons.append(
                        f"Found in startup persistence ({', '.join(startup_sources)})"
                    )

                # --- WMI event subscription persistence ---
                if pname in wmi_execs or pname_stem in wmi_execs:
                    risk += 10
                    reasons.append("Found in WMI event subscription")

                # --- Execution from NTFS Alternate Data Stream (ADS) ---
                if path:
                    stripped_ads = path[4:] if path.startswith("\\\\?\\") else path
                    if len(stripped_ads) > 2 and ":" in stripped_ads[2:]:
                        risk += 30
                        reasons.append("Executed from NTFS Alternate Data Stream")

                # --- Execution from removable drive ---
                if path:
                    is_removable, rem_drive = self._is_removable_drive(path, drive_type_cache)
                    if is_removable:
                        risk += 10
                        reasons.append(f"Executed from removable drive ({rem_drive})")

                # --- Multiple process instances ---
                instance_count = process_name_counts.get(pname, 1)

                if instance_count > 1:

                    risk += 10
                    reasons.append(
                        f"Multiple instances running ({instance_count})"
                    )

                # --- Suspicious child process tracking ---
                try:
                    children = proc.children()
                    if len(children) > 3:
                        risk += 10
                        reasons.append("Multiple child processes")
                except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                    pass

                # --- Unexpected network listener binding ---
                try:
                    listening_sockets = {
                        (c.laddr.ip, c.laddr.port)
                        for c in conns
                        if (
                            c.pid == proc.pid
                            and c.status == psutil.CONN_LISTEN
                            and c.laddr
                        )
                    }

                    wildcard_listeners = [
                        (ip, port)
                        for ip, port in listening_sockets
                        if ip in ("0.0.0.0", "::")
                    ]

                    if wildcard_listeners:
                        risk += 10
                        ports = ", ".join(
                            str(port)
                            for _, port in sorted(wildcard_listeners)
                        )
                        reasons.append(
                            f"Wildcard network listener ({ports})"
                        )

                except (OSError, AttributeError, TypeError):
                    pass

                # --- Non-verified-system process checks ---
                is_verified_system = (
                    bool(path)
                    and pname in known_system
                    and is_windows_path
                    and self.is_microsoft_signed(path)
                )
                is_protected_system_no_path = (
                    not path
                    and (proc.pid in SPECIAL_SYSTEM_PID or pname in known_system)
                )

                # --- Deleted / ghost executable on disk ---
                if (
                    not is_verified_system
                    and path
                    and len(path) >= 3
                    and path[1] == ":"
                    and "\\windowsapps\\" not in normalized_path
                ):
                    try:
                        os.stat(path)
                    except FileNotFoundError:
                        risk += 30
                        reasons.append("Deleted executable on disk")
                    except OSError:
                        pass

                # --- IFEO Debugger persistence ---
                if (
                    not is_verified_system
                    and (pname in ifeo_execs or pname_stem in ifeo_execs)
                    and not (path and self.is_microsoft_signed(path))
                ):
                    risk += 30
                    reasons.append("Found in IFEO Debugger persistence")

                if not is_verified_system and not is_protected_system_no_path:

                    # --- Digital signature validation ---
                    sig_status = "Unknown"

                    if path:
                        try:
                            # Normalize path for Windows 10/11 consistency
                            path_key = os.path.normcase(os.path.realpath(path))

                            # Cached
                            if path_key in signature_cache:
                                sig_status = signature_cache[path_key]

                            # PowerShell validation
                            else:
                                try:
                                    sig_status = subprocess.check_output(
                                        [
                                            _system_exe("powershell.exe"),
                                            "-NoProfile",
                                            "-NonInteractive",
                                            "-Command",
                                            "(Get-AuthenticodeSignature -LiteralPath $env:SECUDITOR_SIG_PATH).Status",
                                        ],
                                        env=_safe_subproc_env({"SECUDITOR_SIG_PATH": path}),
                                        text=True,
                                        timeout=10,
                                        stderr=subprocess.DEVNULL,
                                        **_subproc_kwargs_hide_window()
                                    ).strip()

                                    if not sig_status:
                                        sig_status = "Unknown"

                                except Exception:
                                    sig_status = "Unknown"

                                signature_cache[path_key] = sig_status

                            # Signature scoring
                            if sig_status == "Valid":
                                risk -= 10
                                reasons.append("Valid digital signature")

                            elif sig_status in ["NotSigned", "HashMismatch", "NotTrusted"]:
                                risk += 20
                                reasons.append("Invalid digital signature")

                            else:
                                risk += 10
                                reasons.append("Unknown signature status")

                        except Exception:
                            reasons.append("Signature validation failed")

                    # --- Elevated administrator process detection ---
                    try:
                        elevated = self.is_process_elevated(proc.pid)

                        if elevated is True:
                            reasons.append("Elevated administrator process")
                            # Informational only
                            risk += 0

                    except Exception:
                        pass

                    # --- DLL / Module anomalies ---
                    if sig_status != "Valid":
                        try:
                            module_anomalies = self.get_module_anomalies(proc, sig_status)

                            if module_anomalies:
                                risk += 10

                                # Limit output to avoid huge reports.
                                module_names = [
                                    os.path.basename(path)
                                    for path in module_anomalies[:3]
                                ]

                                reasons.append(
                                    f"DLL/Module anomalies ({', '.join(module_names)})"
                                )

                        except Exception:
                            pass

                    # --- Process age anomaly ---
                    if not boot_grace and sig_status != "Valid" and (
                        not is_application_path or proc.pid not in visible_pids
                    ):
                        try:
                            create_time = proc.create_time()
                            uptime = scan_now - create_time

                            if 0 <= uptime < 120:
                                risk += 10
                                reasons.append("Recently spawned process")
                        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                            pass

                    # --- Process memory inspection ---
                    try:
                        injection_findings = self.check_process_injection_indicators(proc.pid)

                        if injection_findings:
                            if sig_status != "Valid":
                                risk += 10
                            reasons.append(
                                "Private executable memory detected"
                            )

                    except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                        pass

                    # Traffic checks (using cached connections)
                    try:
                        incoming = self.detect_incoming_activity(proc.pid, conns)
                        outgoing = self.detect_outgoing_activity(proc.pid, conns)

                        if incoming and outgoing:
                            risk += 20
                            reasons.append("Inbound + outbound communications")
                        else:
                            if incoming:
                                risk += 10
                                reasons.append("Inbound traffic detected")

                            if outgoing:
                                risk += 10
                                reasons.append("Outbound traffic detected")

                    except Exception:
                        pass

                    # --- Multi-port behavior (listening ports only) ---
                    try:
                        pid_ports = {
                            c.laddr.port
                            for c in conns
                            if (
                                c.pid == proc.pid
                                and c.status == psutil.CONN_LISTEN
                                and c.laddr
                            )
                        }

                        if (
                            len(pid_ports) > 3
                            and not (
                                pname in legit_process
                                and is_application_path
                                and sig_status == "Valid"
                            )
                        ):
                            risk += 10
                            reasons.append(f"Multiple listening ports ({len(pid_ports)})")

                    except Exception:
                        pass

                    # External peer count
                    try:
                        external_peers = {
                            c.raddr.ip
                            for c in conns
                            if c.pid == proc.pid
                            and c.status == psutil.CONN_ESTABLISHED
                            and c.raddr
                            and not self.is_private_ip(c.raddr.ip)
                        }

                        if (
                            len(external_peers) >= 10
                            and not (
                                pname in legit_process
                                and is_application_path
                                and sig_status == "Valid"
                            )
                        ):
                            risk += 10
                            reasons.append(f"{len(external_peers)} external peers")

                    except Exception:
                        pass

                    # --- Network correlation (per process) ---
                    try:
                        external_conns = sum(
                            1
                            for c in conns
                            if (
                                c.pid == proc.pid
                                and c.raddr
                                and not self.is_private_ip(c.raddr.ip)
                            )
                        )

                        if (
                            external_conns > 3
                            and not (
                                pname in legit_process
                                and is_application_path
                                and sig_status == "Valid"
                            )
                        ):
                            risk += 10
                            reasons.append(f"{external_conns} active external connections")

                    except Exception:
                        pass

                    # --- Clipboard + Network correlation ---
                    try:
                        external_conns = sum(
                            1
                            for c in conns
                            if (
                                c.pid == proc.pid
                                and c.raddr
                                and not self.is_private_ip(c.raddr.ip)
                            )
                        )

                        recent_clipboard = any(
                            scan_now - e["timestamp"] < 30
                            for e in clipboard_events
                        )

                        if (
                            recent_clipboard
                            and external_conns > 0
                            and not (
                                pname in legit_process
                                and is_application_path
                                and sig_status == "Valid"
                            )
                        ):
                            risk += 10
                            reasons.append("Clipboard and network activity")

                    except Exception:
                        pass

                    # --- Suspicious executable location ---
                    try:
                        if path:
                            path_lower = os.path.normcase(path).lower()

                            if any(location in path_lower for location in suspicious_locations) and sig_status != "Valid":
                                risk += 10
                                reasons.append("Executable in suspicious location")

                    except (psutil.AccessDenied, psutil.NoSuchProcess, FileNotFoundError, OSError):
                        pass

                    # --- Invisible / Background activity ---
                    try:
                        if proc.pid not in visible_pids and (sig_status != "Valid"):
                            risk += 10
                            reasons.append("Background activity")

                    except Exception:
                        pass

                    # --- Entropy (inline, fast, safe) ---
                    if path and not is_windows_path and sig_status != "Valid":
                        try:
                            with open(path, "rb") as f:
                                data = f.read(1024 * 1024)
                            if data:
                                freq = [0] * 256
                                length = len(data)
                                for b in data:
                                    freq[b] += 1
                                entropy = 0.0
                                for c in freq:
                                    if c:
                                        p = c / length
                                        entropy -= p * math.log2(p)
                                if entropy >= 7.5:
                                    risk += 10
                                    reasons.append(f"High entropy ({entropy:.2f})")
                        except (PermissionError, FileNotFoundError, OSError):
                            pass

                    # --- Small executable ---
                    if path:
                        try:
                            if os.path.exists(path) and os.path.getsize(path) < 50_000:
                                risk += 10
                                reasons.append("Suspiciously small executable")
                        except (psutil.AccessDenied, FileNotFoundError, OSError):
                            pass

                    # --- System process typosquatting / double extension ---
                    if sig_status != "Valid" and not is_windows_path and pname not in known_system:
                        if self._DOUBLE_EXT_RE.search(pname):
                            risk += 30
                            reasons.append("Masqueraded double extension")
                        else:
                            typo_target = self._find_typosquat_target(pname_stem)
                            if typo_target:
                                risk += 30
                                reasons.append(
                                    f"System process typosquatting (similar to {typo_target})"
                                )

                    # --- Mark-of-the-Web (Zone.Identifier) ---
                    if path and sig_status != "Valid" and not is_windows_path:
                        zone_id = self._get_motw_zone(path, motw_cache)
                        if zone_id in ("3", "4"):
                            risk += 20
                            reasons.append(
                                f"Downloaded executable (Mark-of-the-Web, ZoneId={zone_id})"
                            )

                    # --- Hidden / system-attributed binary outside Windows ---
                    if path and sig_status != "Valid" and not is_windows_path:
                        if self._has_hidden_or_system_attr(path, hidden_attr_cache):
                            risk += 10
                            reasons.append("Hidden/system executable attribute")

                # --- LOLBins trigger ---
                if pname in LOLBINS:
                    has_traffic_reason = any(
                        r in reasons
                        for r in (
                            "Outbound traffic detected",
                            "Inbound traffic detected",
                            "Inbound + outbound communications",
                        )
                    )
                    if not has_traffic_reason:
                        try:
                            incoming = self.detect_incoming_activity(proc.pid, conns)
                            outgoing = self.detect_outgoing_activity(proc.pid, conns)
                            if incoming and outgoing:
                                risk += 20
                                reasons.append("Inbound + outbound communications")
                                has_traffic_reason = True
                            elif incoming:
                                risk += 10
                                reasons.append("Inbound traffic detected")
                                has_traffic_reason = True
                            elif outgoing:
                                risk += 10
                                reasons.append("Outbound traffic detected")
                                has_traffic_reason = True
                        except Exception:
                            pass

                    # Only increase risk when combined with suspicious behavior
                    if (
                        any(r.startswith("Suspicious cmdline") for r in reasons)
                        or has_traffic_reason
                    ):
                        reasons.append("Potential LOLBin Execution")
                        risk += 20

                # Reduce risk for verified native Windows system processes
                if proc.pid in SPECIAL_SYSTEM_PID:
                    risk = max(risk - 20, 0)
                    reasons.append("Special system process")

                elif pname in known_system and is_windows_path:
                    try:
                        exe_path = proc.exe()
                    except (psutil.Error, OSError):
                        exe_path = ""

                    if self.is_microsoft_signed(exe_path):
                        risk = max(risk - 20, 0)
                        reasons.append("Windows system process")

                risk = max(risk, 0)

                if risk >= RISK_THRESHOLD:
                    results.append((
                        pname,
                        proc.pid,
                        risk,
                        path or "Unknown",
                        list(reasons),
                        True,
                    ))

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # --- Deduplicate by name ---
        unique_results = {}

        for pname, pid, risk, path, reasons, flag in results:
            if pname not in unique_results or risk > unique_results[pname][0]:
                unique_results[pname] = (risk, pid, path, reasons, flag)

        deduped = [
            (name, pid, risk, path, reasons, flag)
            for name, (risk, pid, path, reasons, flag) in unique_results.items()
        ]

        deduped.sort(key=lambda x: -x[2])
        return deduped

    @staticmethod
    def _risk_tier(risk):
        if risk >= 90:
            return "High"
        if risk >= 60:
            return "Medium"
        if risk >= 30:
            return "Low"
        return "Very Low"

    @classmethod
    def _format_suspicious_processes(cls, deduped):
        """Format detected suspicious processes as Option 3 compact tree cards."""
        if not deduped:
            return "No suspicious activity detected"

        tier_order = ("High", "Medium", "Low", "Very Low")
        tier_counts = {t: 0 for t in tier_order}
        for _, _, risk, _, _, _ in deduped:
            tier_counts[cls._risk_tier(risk)] += 1

        summary_parts = [f"{t}: {tier_counts[t]}" for t in tier_order if tier_counts[t] > 0]
        header = f"Suspicious Processes Detected: {len(deduped)}"
        if summary_parts:
            header += f"  ({' | '.join(summary_parts)})"

        sep = "–" * 50
        lines = ["", header, sep]

        for idx, (name, pid, risk, path, reasons, _flag) in enumerate(deduped):
            tier = cls._risk_tier(risk)
            lines.append(f"[ {tier} | Risk {risk} ] {name} (PID: {pid})")
            lines.append(f"  ├─ Path: {path}")
            lines.append("  └─ Findings:")

            if isinstance(reasons, str):
                reason_items = [r.strip() for r in reasons.split(",") if r.strip()]
            elif isinstance(reasons, (list, tuple)):
                reason_items = [str(r).strip() for r in reasons if str(r).strip()]
            else:
                reason_items = []

            if reason_items:
                for item in reason_items:
                    lines.append(f"       • {item}")
            else:
                lines.append("       • None")

            if idx != len(deduped) - 1:
                lines.append(sep)

        return "\n".join(lines)

    def show_suspicious_processes(self, run_all_clicked=None, single_check=None):
        cls = type(self)

        if run_all_clicked is None:
            run_all_clicked = secuditor_modules.run_all_clicked
        if single_check is None:
            single_check = secuditor_modules.single_check

        if (
            cls._cache is not None
            and not run_all_clicked
            and not single_check
        ):
            return cls._cache

        deduped = self.check_suspicious_processes()
        cls._cache = self._format_suspicious_processes(deduped)
        return cls._cache


# ===== Web Browser Scanner =====
class WebBrowserScanner:
    """
    Read-only security, configuration, extension, and privacy/permissions scanner
    for installed Windows web browsers (Brave, Chrome, Edge, Firefox, Opera, Opera GX, Vivaldi).
    Never reads saved passwords, cookies, history, or bookmarks.
    """

    _cache = None

    _OFFICIAL_UPDATE_HOSTS = {
        "clients2.google.com",
        "edge.microsoft.com",
        "addons.mozilla.org",
        "extension-updates.opera.com",
        "autoupdate.opera.com",
        "go-updater.brave.com",
        "componentupdater.brave.com",
        "update.vivaldi.com",
    }

    _CHROMIUM_PERM_LABELS = {
        "media_stream_camera": "Camera",
        "media_stream_mic": "Microphone",
        "geolocation": "Location",
        "notifications": "Notifications",
        "clipboard": "Clipboard",
        "popups": "Pop-ups",
        "automatic_downloads": "Auto-Downloads",
        "usb_chooser_data": "USB",
        "serial_chooser_data": "Serial",
    }

    _FIREFOX_PERM_LABELS = {
        "camera": "Camera",
        "microphone": "Microphone",
        "geo": "Location",
        "desktop-notification": "Notifications",
        "popup": "Pop-ups",
        "clipboard": "Clipboard",
    }

    @staticmethod
    def _is_symlink_or_junction(path_or_entry) -> bool:
        try:
            if hasattr(path_or_entry, "is_symlink"):
                if path_or_entry.is_symlink():
                    return True
                is_junc = getattr(path_or_entry, "is_junction", None)
                if callable(is_junc) and is_junc():
                    return True
                st = path_or_entry.stat(follow_symlinks=False)
            else:
                if os.path.islink(path_or_entry):
                    return True
                is_junc = getattr(os.path, "isjunction", None)
                if callable(is_junc) and is_junc(path_or_entry):
                    return True
                st = os.lstat(path_or_entry)
            if getattr(st, "st_reparse_tag", 0) in (0xA0000003, 0xA000000C):
                return True
        except OSError:
            return True
        return False

    @classmethod
    def _read_json_safe(cls, file_path, max_bytes=8 * 1024 * 1024):
        if not file_path or cls._is_symlink_or_junction(file_path):
            return None
        try:
            if not os.path.isfile(file_path) or os.path.getsize(file_path) > max_bytes:
                return None
            with open(file_path, "r", encoding="utf-8", errors="replace") as fp:
                data = json.load(fp)
            return data if isinstance(data, dict) else None
        except Exception:
            return None

    @staticmethod
    def _read_reg_dict(hive, subkey):
        values = {}
        try:
            with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as k:
                idx = 0
                while True:
                    try:
                        name, val, _ = winreg.EnumValue(k, idx)
                        values[name] = val
                        idx += 1
                    except OSError:
                        break
        except OSError:
            pass
        return values

    @staticmethod
    def _read_reg_subkey_values(hive, subkey):
        items = []
        try:
            with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as k:
                idx = 0
                while True:
                    try:
                        _, val, _ = winreg.EnumValue(k, idx)
                        if isinstance(val, str) and val.strip():
                            items.append(val.strip())
                        idx += 1
                    except OSError:
                        break
        except OSError:
            pass
        return items

    @staticmethod
    def _read_reg_subkey_names(hive, subkey):
        names = []
        try:
            with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as k:
                idx = 0
                while True:
                    try:
                        names.append(winreg.EnumKey(k, idx))
                        idx += 1
                    except OSError:
                        break
        except OSError:
            pass
        return names

    @staticmethod
    def _browser_specs():
        local_app = os.environ.get("LOCALAPPDATA") or os.path.join(
            os.path.expanduser("~"), "AppData", "Local"
        )
        roaming_app = os.environ.get("APPDATA") or os.path.join(
            os.path.expanduser("~"), "AppData", "Roaming"
        )
        specs = [
            {
                "name": "Brave",
                "engine": "chromium",
                "user_data": os.path.join(local_app, "BraveSoftware", "Brave-Browser", "User Data"),
                "policy_key": r"SOFTWARE\Policies\BraveSoftware\Brave",
                "ext_reg_key": r"SOFTWARE\BraveSoftware\Brave-Browser\Extensions",
                "proc_names": {"brave.exe"},
            },
            {
                "name": "Google Chrome",
                "engine": "chromium",
                "user_data": os.path.join(local_app, "Google", "Chrome", "User Data"),
                "policy_key": r"SOFTWARE\Policies\Google\Chrome",
                "ext_reg_key": r"SOFTWARE\Google\Chrome\Extensions",
                "proc_names": {"chrome.exe"},
            },
            {
                "name": "Microsoft Edge",
                "engine": "chromium",
                "user_data": os.path.join(local_app, "Microsoft", "Edge", "User Data"),
                "policy_key": r"SOFTWARE\Policies\Microsoft\Edge",
                "ext_reg_key": r"SOFTWARE\Microsoft\Edge\Extensions",
                "proc_names": {"msedge.exe"},
            },
            {
                "name": "Mozilla Firefox",
                "engine": "firefox",
                "user_data": os.path.join(roaming_app, "Mozilla", "Firefox", "Profiles"),
                "policy_key": r"SOFTWARE\Policies\Mozilla\Firefox",
                "ext_reg_key": r"SOFTWARE\Mozilla\Firefox\Extensions",
                "proc_names": {"firefox.exe"},
            },
            {
                "name": "Opera",
                "engine": "chromium",
                "user_data": os.path.join(roaming_app, "Opera Software", "Opera Stable"),
                "policy_key": r"SOFTWARE\Policies\Opera Software",
                "ext_reg_key": r"SOFTWARE\Opera Software\Extensions",
                "proc_names": {"opera.exe"},
            },
            {
                "name": "Opera GX",
                "engine": "chromium",
                "user_data": os.path.join(roaming_app, "Opera Software", "Opera GX Stable"),
                "policy_key": r"SOFTWARE\Policies\Opera Software",
                "ext_reg_key": r"SOFTWARE\Opera Software\Extensions",
                "proc_names": {"opera.exe"},
            },
            {
                "name": "Vivaldi",
                "engine": "chromium",
                "user_data": os.path.join(local_app, "Vivaldi", "User Data"),
                "policy_key": r"SOFTWARE\Policies\Vivaldi",
                "ext_reg_key": r"SOFTWARE\Vivaldi\Extensions",
                "proc_names": {"vivaldi.exe"},
            },
        ]
        return sorted(specs, key=lambda s: s["name"].lower())

    @classmethod
    def _collect_running_flags(cls):
        """Map lowercase process image name -> set of insecure CLI flags observed on running browsers."""
        flags_by_proc = {}
        try:
            for proc in psutil.process_iter(["name", "cmdline"]):
                try:
                    pname = (proc.info.get("name") or "").lower()
                    if not pname:
                        continue
                    cmdline = proc.info.get("cmdline") or []
                    if not cmdline:
                        continue
                    matched = set()
                    for arg in cmdline[1:]:
                        arg_l = str(arg or "").strip().lower()
                        for bad_flag in BROWSER_INSECURE_FLAGS:
                            if arg_l == bad_flag or arg_l.startswith(bad_flag + "="):
                                matched.add(bad_flag)
                    if matched:
                        flags_by_proc.setdefault(pname, set()).update(matched)
                except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                    continue
        except Exception:
            pass
        return flags_by_proc

    @classmethod
    def _discover_chromium_profiles(cls, user_data_dir, max_profiles=10):
        profiles = []
        if not user_data_dir or not os.path.isdir(user_data_dir) or cls._is_symlink_or_junction(user_data_dir):
            return profiles

        # Opera Stable / GX stores Preferences directly in root user_data_dir
        if os.path.isfile(os.path.join(user_data_dir, "Preferences")):
            profiles.append((os.path.basename(user_data_dir), user_data_dir))
            return profiles

        try:
            with os.scandir(user_data_dir) as entries:
                candidates = []
                for entry in entries:
                    if cls._is_symlink_or_junction(entry):
                        continue
                    if not entry.is_dir(follow_symlinks=False):
                        continue
                    name = entry.name
                    if name == "Default" or name.startswith("Profile "):
                        if os.path.isfile(os.path.join(entry.path, "Preferences")):
                            candidates.append((name, entry.path))
                candidates.sort(key=lambda x: (0 if x[0] == "Default" else 1, x[0].lower()))
                profiles.extend(candidates[:max_profiles])
        except OSError:
            pass
        return profiles

    @classmethod
    def _discover_firefox_profiles(cls, profiles_dir, max_profiles=10):
        profiles = []
        if not profiles_dir or not os.path.isdir(profiles_dir) or cls._is_symlink_or_junction(profiles_dir):
            return profiles
        try:
            with os.scandir(profiles_dir) as entries:
                candidates = []
                for entry in entries:
                    if cls._is_symlink_or_junction(entry):
                        continue
                    if not entry.is_dir(follow_symlinks=False):
                        continue
                    has_marker = any(
                        os.path.isfile(os.path.join(entry.path, f))
                        for f in ("prefs.js", "extensions.json", "permissions.sqlite")
                    )
                    if has_marker:
                        candidates.append((entry.name, entry.path))
                candidates.sort(key=lambda x: x[0].lower())
                profiles.extend(candidates[:max_profiles])
        except OSError:
            pass
        return profiles

    @classmethod
    def _resolve_manifest_name(cls, ext_dir, raw_name):
        name = str(raw_name or "").strip()
        if not name.startswith("__MSG_") or not name.endswith("__"):
            return name
        msg_key = name[6:-2]
        for loc in ("en", "en_US", "en_GB"):
            msg_data = cls._read_json_safe(os.path.join(ext_dir, "_locales", loc, "messages.json"))
            if isinstance(msg_data, dict):
                entry = msg_data.get(msg_key) or msg_data.get(msg_key.lower())
                if isinstance(entry, dict) and entry.get("message"):
                    return str(entry["message"]).strip()
        return name

    @classmethod
    def _audit_chromium(cls, spec, running_flags):
        user_data = spec["user_data"]
        policy_key = spec["policy_key"]
        ext_reg_key = spec["ext_reg_key"]

        profiles = cls._discover_chromium_profiles(user_data)

        # Read HKLM + HKCU policies
        policies = {}
        for hive in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
            policies.update(cls._read_reg_dict(hive, policy_key))

        forced_exts = []
        for hive in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
            forced_exts.extend(cls._read_reg_subkey_values(hive, f"{policy_key}\\ExtensionInstallForcelist"))
            forced_exts.extend(cls._read_reg_subkey_names(hive, ext_reg_key))

        proc_flags = set()
        for pn in spec["proc_names"]:
            proc_flags.update(running_flags.get(pn, set()))

        if not profiles and not policies and not forced_exts and not proc_flags:
            return None

        total_extensions = 0
        unsigned_or_sideloaded = []
        suspicious_extensions = []
        insecure_configs = []
        perm_counts = {}
        http_perm_grants = 0
        privacy_notes = []

        # Policy checks
        if policies.get("SafeBrowsingEnabled") == 0 or policies.get("SafeBrowsingProtectionLevel") == 0:
            insecure_configs.append("Safe Browsing disabled by policy")
        if policies.get("SSLErrorOverrideAllowed") == 1:
            insecure_configs.append("SSL error override allowed by policy")
        if policies.get("CommandLineFlagSecurityWarningsEnabled") == 0:
            insecure_configs.append("CLI security warnings suppressed by policy")
        if policies.get("AllowOutdatedPlugins") == 1:
            insecure_configs.append("Outdated plugins allowed by policy")
        if policies.get("DisableSafeBrowsingProceedAnyway") == 0:
            insecure_configs.append("Safe Browsing bypass allowed by policy")
        if forced_exts:
            insecure_configs.append(f"Policy/Registry forced extensions ({len(set(forced_exts))})")

        seen_ext_keys = set()

        for prof_name, prof_path in profiles:
            prefs = cls._read_json_safe(os.path.join(prof_path, "Preferences")) or {}
            sec_prefs = cls._read_json_safe(os.path.join(prof_path, "Secure Preferences")) or {}

            # --- Extensions ---
            ext_settings = {}
            for src in (prefs, sec_prefs):
                es = (src.get("extensions") or {}).get("settings")
                if isinstance(es, dict):
                    ext_settings.update(es)

            for ext_id, meta in ext_settings.items():
                if not isinstance(meta, dict):
                    continue
                # Skip disabled or built-in component extensions (location 5=COMPONENT, 10=EXTERNAL_COMPONENT)
                location = meta.get("location")
                if location in (5, 10):
                    continue
                if meta.get("state") == 0:
                    continue

                dedup_key = (prof_name, ext_id)
                if dedup_key in seen_ext_keys:
                    continue
                seen_ext_keys.add(dedup_key)
                total_extensions += 1

                manifest = meta.get("manifest") if isinstance(meta.get("manifest"), dict) else {}
                ext_rel_path = meta.get("path") or ""
                ext_abs_dir = None
                if isinstance(ext_rel_path, str) and ext_rel_path:
                    if os.path.isabs(ext_rel_path):
                        ext_abs_dir = ext_rel_path
                    else:
                        ext_abs_dir = os.path.join(prof_path, "Extensions", ext_rel_path)

                if not manifest and ext_abs_dir:
                    manifest = cls._read_json_safe(os.path.join(ext_abs_dir, "manifest.json")) or {}

                raw_name = manifest.get("name") or ext_id
                ext_name = cls._resolve_manifest_name(ext_abs_dir, raw_name) if ext_abs_dir else str(raw_name)
                ext_label = ext_name[:32].rstrip(" (-") if ext_name else ext_id[:16]

                # Unsigned / unpacked / sideloaded checks
                unsigned_reasons = []
                from_store = meta.get("from_webstore")
                by_default = meta.get("was_installed_by_default") is True
                if location == 4:
                    unsigned_reasons.append("unpacked/dev-mode")
                elif location == 8:
                    unsigned_reasons.append("loaded via CLI")
                elif location in (2, 3, 6, 7, 9) and not (by_default and from_store is True):
                    unsigned_reasons.append("sideloaded/policy")

                if from_store is False and not unsigned_reasons:
                    unsigned_reasons.append("non-store")

                update_url = str(manifest.get("update_url") or "").strip()
                if update_url:
                    try:
                        uhost = (urlparse(update_url).hostname or "").lower()
                        if uhost and uhost not in cls._OFFICIAL_UPDATE_HOSTS:
                            unsigned_reasons.append(f"external update host ({uhost})")
                    except Exception:
                        pass

                if ext_abs_dir and os.path.isdir(ext_abs_dir) and not cls._is_symlink_or_junction(ext_abs_dir):
                    verified_file = os.path.join(ext_abs_dir, "_metadata", "verified_contents.json")
                    if not os.path.isfile(verified_file) and from_store is not True and "unpacked/dev-mode" not in unsigned_reasons:
                        unsigned_reasons.append("no verified_contents.json")

                if unsigned_reasons:
                    entry_str = f"{ext_label} ({', '.join(unsigned_reasons)})"
                    if entry_str not in unsigned_or_sideloaded:
                        unsigned_or_sideloaded.append(entry_str)

                # Suspicious permission checks
                all_perms = set()
                for pkey in ("permissions", "host_permissions"):
                    plist = manifest.get(pkey)
                    if isinstance(plist, list):
                        all_perms.update(str(p) for p in plist if isinstance(p, str))

                high_perms = sorted(p for p in all_perms if p in BROWSER_HIGH_RISK_PERMISSIONS)
                broad_hosts = any(p in BROWSER_BROAD_HOST_PATTERNS for p in all_perms)
                sus_reasons = []
                if broad_hosts and high_perms:
                    sus_reasons.append(f"broad host + {', '.join(high_perms[:3])}")
                elif len(high_perms) >= 3:
                    sus_reasons.append(f"high-risk perms: {', '.join(high_perms[:3])}")
                elif "debugger" in high_perms or "nativeMessaging" in high_perms or "proxy" in high_perms:
                    sus_reasons.append(f"sensitive API: {', '.join(p for p in high_perms if p in ('debugger', 'nativeMessaging', 'proxy'))}")

                if sus_reasons:
                    sus_str = f"{ext_label} ({'; '.join(sus_reasons)})"
                    if sus_str not in suspicious_extensions:
                        suspicious_extensions.append(sus_str)

            # --- Profile Configuration ---
            sb = prefs.get("safebrowsing")
            if isinstance(sb, dict) and sb.get("enabled") is False:
                msg = f"Safe Browsing disabled ({prof_name})"
                if msg not in insecure_configs:
                    insecure_configs.append(msg)

            https_only = prefs.get("https_only_mode_enabled")
            if https_only is False:
                note = f"HTTPS-Only Mode: Off ({prof_name})"
                if note not in privacy_notes:
                    privacy_notes.append(note)

            # --- Site Permissions (content_settings.exceptions) ---
            profile_dict = prefs.get("profile") if isinstance(prefs.get("profile"), dict) else {}
            content_settings = (
                profile_dict.get("content_settings")
                if isinstance(profile_dict.get("content_settings"), dict)
                else {}
            )
            exceptions = (
                content_settings.get("exceptions")
                if isinstance(content_settings.get("exceptions"), dict)
                else {}
            )
            for key, label in cls._CHROMIUM_PERM_LABELS.items():
                entries = exceptions.get(key)
                if not isinstance(entries, dict):
                    continue
                for origin, rule in entries.items():
                    if isinstance(rule, dict) and rule.get("setting") == 1:
                        perm_counts[label] = perm_counts.get(label, 0) + 1
                        if str(origin).lower().startswith("http://"):
                            http_perm_grants += 1

            # --- Privacy Settings ---
            cookie_mode = profile_dict.get("cookie_controls_mode")
            block_3p = profile_dict.get("block_third_party_cookies")
            if cookie_mode == 1 or block_3p is True:
                p_cookie = "3rd-Party Cookies: Blocked"
            elif cookie_mode == 2:
                p_cookie = "3rd-Party Cookies: Blocked in Incognito"
            else:
                p_cookie = "3rd-Party Cookies: Allowed"
            if p_cookie not in privacy_notes:
                privacy_notes.append(p_cookie)

            if prefs.get("enable_do_not_track") is True:
                dnt = "Do Not Track: On"
            else:
                dnt = "Do Not Track: Off"
            if dnt not in privacy_notes:
                privacy_notes.append(dnt)

            if prefs.get("credentials_enable_service") is False:
                pm = "Password Saving: Disabled"
            else:
                pm = "Password Saving: Enabled"
            if pm not in privacy_notes:
                privacy_notes.append(pm)

            webrtc = prefs.get("webrtc") if isinstance(prefs.get("webrtc"), dict) else {}
            webrtc_pol = webrtc.get("ip_handling_policy")
            if webrtc_pol:
                w_note = f"WebRTC Policy: {webrtc_pol}"
                if w_note not in privacy_notes:
                    privacy_notes.append(w_note)

        return {
            "name": spec["name"],
            "profiles": [p[0] for p in profiles],
            "total_extensions": total_extensions,
            "unsigned_extensions": unsigned_or_sideloaded,
            "suspicious_extensions": suspicious_extensions,
            "insecure_configs": insecure_configs,
            "running_flags": sorted(proc_flags),
            "perm_counts": perm_counts,
            "http_perm_grants": http_perm_grants,
            "privacy_notes": privacy_notes,
        }

    @staticmethod
    def _parse_firefox_prefs_file(file_path, max_bytes=4 * 1024 * 1024):
        prefs = {}
        try:
            if not os.path.isfile(file_path) or os.path.getsize(file_path) > max_bytes:
                return prefs
            with open(file_path, "r", encoding="utf-8", errors="replace") as fp:
                content = fp.read()
            for match in re.finditer(
                r'user_pref\(\s*"([^"]+)"\s*,\s*(true|false|-?\d+|"[^"]*")\s*\)',
                content,
            ):
                key, raw_val = match.group(1), match.group(2)
                if raw_val == "true":
                    prefs[key] = True
                elif raw_val == "false":
                    prefs[key] = False
                elif raw_val.startswith('"') and raw_val.endswith('"'):
                    prefs[key] = raw_val[1:-1]
                else:
                    try:
                        prefs[key] = int(raw_val)
                    except ValueError:
                        prefs[key] = raw_val
        except Exception:
            pass
        return prefs

    @classmethod
    def _read_firefox_permissions_sqlite(cls, db_path):
        """Read Firefox permissions.sqlite strictly in read-only immutable URI mode."""
        perm_counts = {}
        http_grants = 0
        if not db_path or not os.path.isfile(db_path) or cls._is_symlink_or_junction(db_path):
            return perm_counts, http_grants

        try:
            abs_path = os.path.abspath(db_path).replace("\\", "/")
            encoded = quote(abs_path, safe="/:")
            uri = f"file:///{encoded}?mode=ro&immutable=1"
            with contextlib.closing(sqlite3.connect(uri, uri=True, timeout=2.0)) as conn:
                cur = conn.cursor()
                rows = []
                for query in (
                    "SELECT origin, type FROM moz_perms WHERE permission = 1",
                    "SELECT host, type FROM moz_hosts WHERE permission = 1",
                ):
                    try:
                        rows = cur.execute(query).fetchall()
                        break
                    except sqlite3.Error:
                        continue
                for origin, ptype in rows:
                    label = cls._FIREFOX_PERM_LABELS.get(str(ptype or "").lower())
                    if label:
                        perm_counts[label] = perm_counts.get(label, 0) + 1
                        if str(origin or "").lower().startswith("http://"):
                            http_grants += 1
        except (sqlite3.Error, OSError):
            pass

        return perm_counts, http_grants

    @classmethod
    def _audit_firefox(cls, spec, running_flags):
        profiles = cls._discover_firefox_profiles(spec["user_data"])

        policies = {}
        for hive in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
            policies.update(cls._read_reg_dict(hive, spec["policy_key"]))

        # Check distribution/policies.json if Firefox is installed in Program Files
        dist_policies = {}
        for env_key in ("ProgramFiles", "ProgramFiles(x86)"):
            pf = os.environ.get(env_key)
            if pf:
                pfile = os.path.join(pf, "Mozilla Firefox", "distribution", "policies.json")
                pdata = cls._read_json_safe(pfile)
                if isinstance(pdata, dict) and isinstance(pdata.get("policies"), dict):
                    dist_policies.update(pdata["policies"])

        proc_flags = set()
        for pn in spec["proc_names"]:
            proc_flags.update(running_flags.get(pn, set()))

        if not profiles and not policies and not dist_policies and not proc_flags:
            return None

        total_extensions = 0
        unsigned_or_sideloaded = []
        suspicious_extensions = []
        insecure_configs = []
        perm_counts = {}
        http_perm_grants = 0
        privacy_notes = []

        if policies.get("DisableAppUpdate") == 1 or dist_policies.get("DisableAppUpdate") is True:
            insecure_configs.append("Browser updates disabled by policy")
        if policies.get("DisableSafeBrowsing") == 1 or dist_policies.get("DisableSafeBrowsing") is True:
            insecure_configs.append("Safe Browsing disabled by policy")

        for prof_name, prof_path in profiles:
            # --- Extensions (extensions.json) ---
            ext_data = cls._read_json_safe(os.path.join(prof_path, "extensions.json")) or {}
            addons = ext_data.get("addons")
            if isinstance(addons, list):
                for addon in addons:
                    if not isinstance(addon, dict):
                        continue
                    if addon.get("type") != "extension":
                        continue
                    if addon.get("active") is False:
                        continue
                    loc = str(addon.get("location") or "")
                    if loc in ("app-builtin", "app-system-defaults"):
                        continue

                    total_extensions += 1
                    default_loc = addon.get("defaultLocale") if isinstance(addon.get("defaultLocale"), dict) else {}
                    ext_name = str(default_loc.get("name") or addon.get("id") or "Unknown")[:32]

                    signed_state = addon.get("signedState")
                    unsigned_reasons = []
                    if signed_state == 0:
                        unsigned_reasons.append("unsigned")
                    elif signed_state == -1:
                        unsigned_reasons.append("broken signature")
                    if loc in ("winreg-app-user", "winreg-app-global"):
                        unsigned_reasons.append(f"sideloaded ({loc})")
                    if unsigned_reasons:
                        unsigned_or_sideloaded.append(f"{ext_name} ({', '.join(unsigned_reasons)})")

                    user_perms = addon.get("userPermissions") if isinstance(addon.get("userPermissions"), dict) else {}
                    p_list = [str(p) for p in (user_perms.get("permissions") or []) if isinstance(p, str)]
                    o_list = [str(o) for o in (user_perms.get("origins") or []) if isinstance(o, str)]
                    high_perms = sorted(p for p in p_list if p in BROWSER_HIGH_RISK_PERMISSIONS)
                    broad_hosts = any(o in BROWSER_BROAD_HOST_PATTERNS for o in o_list)
                    sus_reasons = []
                    if broad_hosts and high_perms:
                        sus_reasons.append(f"broad host + {', '.join(high_perms[:3])}")
                    elif len(high_perms) >= 3:
                        sus_reasons.append(f"high-risk perms: {', '.join(high_perms[:3])}")
                    elif any(p in ("debugger", "nativeMessaging", "proxy") for p in high_perms):
                        sus_reasons.append(
                            f"sensitive API: {', '.join(p for p in high_perms if p in ('debugger', 'nativeMessaging', 'proxy'))}"
                        )
                    if sus_reasons:
                        suspicious_extensions.append(f"{ext_name} ({'; '.join(sus_reasons)})")

            # --- Configuration (prefs.js & user.js) ---
            prefs = cls._parse_firefox_prefs_file(os.path.join(prof_path, "prefs.js"))
            user_js_path = os.path.join(prof_path, "user.js")
            if os.path.isfile(user_js_path) and not cls._is_symlink_or_junction(user_js_path):
                prefs.update(cls._parse_firefox_prefs_file(user_js_path))
                insecure_configs.append(f"Custom user.js override present ({prof_name})")

            if prefs.get("xpinstall.signatures.required") is False:
                insecure_configs.append(f"Extension signature enforcement disabled ({prof_name})")
            if prefs.get("browser.safebrowsing.malware.enabled") is False:
                insecure_configs.append(f"Malware Safe Browsing disabled ({prof_name})")
            if prefs.get("browser.safebrowsing.phishing.enabled") is False:
                insecure_configs.append(f"Phishing Safe Browsing disabled ({prof_name})")

            # --- Site Permissions (read-only immutable SQLite) ---
            p_counts, h_grants = cls._read_firefox_permissions_sqlite(
                os.path.join(prof_path, "permissions.sqlite")
            )
            for k, v in p_counts.items():
                perm_counts[k] = perm_counts.get(k, 0) + v
            http_perm_grants += h_grants

            # --- Privacy Settings ---
            cookie_beh = prefs.get("network.cookie.cookieBehavior")
            if cookie_beh in (1, 4, 5):
                p_cookie = "3rd-Party Cookies: Blocked / Isolated"
            elif cookie_beh == 0:
                p_cookie = "3rd-Party Cookies: Allowed"
            else:
                p_cookie = "3rd-Party Cookies: Default (Total Cookie Protection)"
            if p_cookie not in privacy_notes:
                privacy_notes.append(p_cookie)

            if prefs.get("dom.security.https_only_mode") is True:
                h_note = "HTTPS-Only Mode: On"
            else:
                h_note = "HTTPS-Only Mode: Off"
            if h_note not in privacy_notes:
                privacy_notes.append(h_note)

            if prefs.get("signon.rememberSignons") is False:
                pm = "Password Saving: Disabled"
            else:
                pm = "Password Saving: Enabled"
            if pm not in privacy_notes:
                privacy_notes.append(pm)

            if prefs.get("security.enterprise_roots.enabled") is True:
                er = "Enterprise OS Roots: Enabled"
                if er not in privacy_notes:
                    privacy_notes.append(er)

        return {
            "name": spec["name"],
            "profiles": [p[0] for p in profiles],
            "total_extensions": total_extensions,
            "unsigned_extensions": unsigned_or_sideloaded,
            "suspicious_extensions": suspicious_extensions,
            "insecure_configs": insecure_configs,
            "running_flags": sorted(proc_flags),
            "perm_counts": perm_counts,
            "http_perm_grants": http_perm_grants,
            "privacy_notes": privacy_notes,
        }

    def scan_web_browsers(self):
        """Scan all supported installed browsers and return structured findings sorted A-Z."""
        running_flags = self._collect_running_flags()
        results = []
        for spec in self._browser_specs():
            try:
                if spec["engine"] == "chromium":
                    entry = self._audit_chromium(spec, running_flags)
                else:
                    entry = self._audit_firefox(spec, running_flags)
                if entry is not None:
                    results.append(entry)
            except Exception:
                continue
        results.sort(key=lambda r: r["name"].lower())
        return results

    @staticmethod
    def _format_list_preview(items, limit=5):
        if not items:
            return "None detected"
        shown = items[:limit]
        extra = len(items) - len(shown)
        text = "; ".join(shown)
        if extra > 0:
            text += f" (+{extra} more)"
        return text

    @staticmethod
    def _has_attention(browser_entry):
        return bool(
            browser_entry.get("unsigned_extensions")
            or browser_entry.get("suspicious_extensions")
            or browser_entry.get("insecure_configs")
            or browser_entry.get("running_flags")
            or (browser_entry.get("http_perm_grants") or 0) > 0
        )

    @classmethod
    def _format_browser_results(cls, results):
        """Format browser scan results as Option 3 compact tree cards (sorted A-Z)."""
        if not results:
            return "\nNo supported web browsers detected."

        sep = " " + ("–" * 98)
        att_cnt = sum(1 for b in results if cls._has_attention(b))
        clean_cnt = len(results) - att_cnt

        lines = [
            "",
            f" Browsers Scanned: {len(results)}  (Attention: {att_cnt} | Clean: {clean_cnt})",
            sep,
        ]

        label_w = 22
        for idx, b in enumerate(results):
            has_att = cls._has_attention(b)
            badge = "Attention" if has_att else "Clean"
            p_cnt = len(b.get("profiles") or [])
            e_cnt = int(b.get("total_extensions") or 0)
            p_word = "profile" if p_cnt == 1 else "profiles"
            e_word = "extension" if e_cnt == 1 else "extensions"

            lines.append(f" [ {badge} ] {b['name']}  ({p_cnt} {p_word} | {e_cnt} {e_word})")

            if b.get("perm_counts"):
                perm_summary = ", ".join(
                    f"{k} ({v})" for k, v in sorted(b["perm_counts"].items())
                )
                if (b.get("http_perm_grants") or 0) > 0:
                    perm_summary += f" [HTTP non-TLS grants: {b['http_perm_grants']}]"
            else:
                perm_summary = "None detected"

            priv_summary = " | ".join(b["privacy_notes"]) if b.get("privacy_notes") else "Default / Unknown"

            if has_att:
                lines.append(
                    f"   ├─ {'Unsigned / Non-Store':<{label_w}}: {cls._format_list_preview(b['unsigned_extensions'])}"
                )
                lines.append(
                    f"   ├─ {'Suspicious Extensions':<{label_w}}: {cls._format_list_preview(b['suspicious_extensions'])}"
                )
                lines.append(
                    f"   ├─ {'Insecure Config':<{label_w}}: {cls._format_list_preview(b['insecure_configs'])}"
                )
                lines.append(
                    f"   ├─ {'Running Flags':<{label_w}}: {cls._format_list_preview(b['running_flags'])}"
                )
                lines.append(f"   ├─ {'Site Permissions':<{label_w}}: {perm_summary}")
                lines.append(f"   └─ {'Privacy Settings':<{label_w}}: {priv_summary}")
            else:
                lines.append(
                    f"   ├─ {'Security Checks':<{label_w}}: No unsigned/suspicious extensions, insecure policies, or flags"
                )
                lines.append(f"   ├─ {'Site Permissions':<{label_w}}: {perm_summary}")
                lines.append(f"   └─ {'Privacy Settings':<{label_w}}: {priv_summary}")

            if idx != len(results) - 1:
                lines.append(sep)

        return "\n".join(lines)

    def show_web_browsers(self, run_all_clicked=None, single_check=None):
        cls = type(self)

        if run_all_clicked is None:
            run_all_clicked = secuditor_modules.run_all_clicked
        if single_check is None:
            single_check = secuditor_modules.single_check

        if (
            cls._cache is not None
            and not run_all_clicked
            and not single_check
        ):
            return cls._cache

        results = self.scan_web_browsers()
        cls._cache = self._format_browser_results(results)
        return cls._cache
