# Secuditor Scanners – Copyright (c) 2026 Menahem Levinski

import os
import re
import time
import hashlib
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
import win32gui, win32con, win32process, win32clipboard

from urllib.parse import urlparse
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
KNOWN_BENIGN_FILES = {f.lower() for f in SEC.get("known_benign_files", [])}

# --- Data for SSL/TLS Interception ---
LEGIT_ISSUERS = SEC["legit_issuers"]
PUBLIC_CAS = SEC["public_cas"]


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
    def _fetch_peer_cert(host: str, port: int, context: ssl.SSLContext):
        """Connect, perform TLS handshake, and return (DER bytes, negotiated TLS version)."""
        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                return ssock.getpeercert(binary_form=True), ssock.version()

    def _verify_public_chain(self, host: str, port: int):
        """
        Verify certificate chain against public WebPKI roots (certifi).

        Returns:
            True if trusted by Mozilla/certifi roots,
            False if certificate/hostname verification fails against certifi,
            None if certifi is unavailable or a transient socket error occurred.
        """
        if certifi is None:
            return None
        try:
            public_ctx = ssl.create_default_context(cafile=certifi.where())
            public_ctx.check_hostname = True
            public_ctx.verify_mode = ssl.CERT_REQUIRED
            self._fetch_peer_cert(host, port, public_ctx)
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
            try:
                der, tls_version = self._fetch_peer_cert(host, port, os_ctx)
            except ssl.SSLCertVerificationError as verify_exc:
                os_trusted = False
                verify_error = getattr(verify_exc, "verify_message", None) or str(verify_exc)
                # Fallback unverified fetch only to extract certificate metadata for reporting
                raw_ctx = ssl.create_default_context()
                raw_ctx.check_hostname = False
                raw_ctx.verify_mode = ssl.CERT_NONE
                der, tls_version = self._fetch_peer_cert(host, port, raw_ctx)

            # --- Stage 2: Check whether an OS-trusted cert also chains to a public WebPKI root ---
            public_trusted = self._verify_public_chain(host, port) if os_trusted else False

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
            matched_public_ca = self._matches_issuer_list(issuer_fields, PUBLIC_CAS)
            matched_legit_vendor = self._matches_issuer_list(issuer_fields, LEGIT_ISSUERS)

            triggers = []
            trust_mismatch = False

            if not os_trusted:
                trust_mismatch = True
                triggers.append(
                    f"Untrusted certificate ({verify_error})" if verify_error else "Untrusted certificate"
                )
            elif public_trusted is False:
                trust_mismatch = True
                triggers.append("Non-public root CA")
            elif public_trusted is None and not matched_public_ca:
                trust_mismatch = True
                triggers.append("Unknown issuer")

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
                elif matched_legit_vendor:
                    legit = True
                    verdict = "Likely Legitimate"
                    reason = f"Issued by {matched_legit_vendor} (firewall inspection)"
                else:
                    verdict = "Suspicious"
                    reason = ", ".join(triggers)
            elif triggers:
                verdict = "Suspicious"
                reason = ", ".join(triggers)
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

    @staticmethod
    def _parse_proxy_endpoints(raw_value):
        """Parse Windows ProxyServer / WinHTTP / URL proxy strings into (scheme, host, port) tuples."""
        endpoints = []
        if not isinstance(raw_value, str) or not raw_value.strip():
            return endpoints

        for part in raw_value.split(";"):
            item = part.strip()
            if not item:
                continue

            scheme = "http"
            if "=" in item and "://" not in item:
                scheme_part, item = item.split("=", 1)
                scheme = scheme_part.strip().lower() or "http"

            candidate = item if "://" in item else f"{scheme}://{item}"
            try:
                parsed = urlparse(candidate)
                host = (parsed.hostname or "").strip().lower()
                port = parsed.port
                parsed_scheme = (parsed.scheme or scheme).lower()
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

        hkcu_enable = cls._read_reg(winreg.HKEY_CURRENT_USER, user_sub, "ProxyEnable", 0)
        hkcu_server = cls._read_reg(winreg.HKEY_CURRENT_USER, user_sub, "ProxyServer")
        hkcu_pac = cls._read_reg(winreg.HKEY_CURRENT_USER, user_sub, "AutoConfigURL")
        hkcu_auto = bool(cls._read_reg(winreg.HKEY_CURRENT_USER, user_sub, "AutoDetect", 0))

        hklm_enable = cls._read_reg(winreg.HKEY_LOCAL_MACHINE, user_sub, "ProxyEnable", 0)
        hklm_server = cls._read_reg(winreg.HKEY_LOCAL_MACHINE, user_sub, "ProxyServer")
        hklm_pac = cls._read_reg(winreg.HKEY_LOCAL_MACHINE, user_sub, "AutoConfigURL")

        pol_per_user = cls._read_reg(winreg.HKEY_LOCAL_MACHINE, policy_sub, "ProxySettingsPerUser")
        pol_enable = cls._read_reg(winreg.HKEY_LOCAL_MACHINE, policy_sub, "ProxyEnable", 0)
        pol_server = cls._read_reg(winreg.HKEY_LOCAL_MACHINE, policy_sub, "ProxyServer")
        pol_pac = cls._read_reg(winreg.HKEY_LOCAL_MACHINE, policy_sub, "AutoConfigURL")

        manual = None
        if hkcu_enable and hkcu_server:
            manual = str(hkcu_server).strip()
        elif hklm_enable and hklm_server:
            manual = f"[HKLM] {str(hklm_server).strip()}"
        elif pol_enable and pol_server:
            manual = f"[Policy] {str(pol_server).strip()}"

        pac = hkcu_pac or hklm_pac or pol_pac
        pac = str(pac).strip() if pac else None

        return {
            "manual": manual,
            "raw_manual": str(hkcu_server or hklm_server or pol_server or "").strip() if manual else "",
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

                if host in self._LOCALHOST_HOSTS and port:
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

    @staticmethod
    def get_fixed_drives():
        drives = []
        for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            drive = f"{letter}:\\"
            if os.path.exists(drive):
                drives.append(drive)
        return drives

    @classmethod
    def build_sensitive_paths(cls):
        paths = []
        for drive in cls.get_fixed_drives():
            for tpl in SENSITIVE_PATH_TEMPLATES:
                paths.append(tpl.format(drive=drive))
        return paths

    # --- Utility: Safe stat ---
    @staticmethod
    def has_everyone_permission(path):
        try:
            cmd = [_system_exe("icacls"), path]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                env=_safe_subproc_env(),
                **_subproc_kwargs_hide_window()
            )
            output = result.stdout.lower()
            return "everyone" in output
        except Exception:
            return False

    @staticmethod
    def is_hidden(path):
        """Basic hidden check using filename starting with dot."""
        return os.path.basename(path).startswith(".")

    # --- SENSITIVE TARGET SCAN ---
    def check_sensitive_targets(self):
        results = []
        SYSTEM_PROTECTED_PREFIXES = [r"C:\Windows\System32\config", r"C:\Windows\NTDS", r"C:\Windows\SYSVOL"]
        SENSITIVE_PATHS = self.build_sensitive_paths()

        for p in SENSITIVE_PATHS:
            matches = glob.glob(p, recursive=False)
            if not matches and "*" not in p and "?" not in p:
                matches = [p]

            for m in matches:
                if not os.path.exists(m):
                    continue

                base = os.path.basename(m).lower()

                if base in KNOWN_BENIGN_FILES:
                    continue

                # Protected system DB/hives treated as low risk
                if base in {"ntds.dit", "sam", "security", "system", "software"}:
                    results.append({"target": m, "risk": "low risk"})
                    continue

                in_system_prefix = any(m.lower().startswith(pref.lower()) for pref in SYSTEM_PROTECTED_PREFIXES)

                locked = False
                try:
                    if os.path.isfile(m):
                        with open(m, "rb"):
                            pass
                except PermissionError:
                    locked = True

                everyone_access = self.has_everyone_permission(m)
                hidden = self.is_hidden(m)

                if everyone_access:
                    risk = "exposed"
                elif (not locked) and (not hidden) and (not in_system_prefix):
                    risk = "weak path"
                else:
                    risk = "low risk"

                results.append({"target": m, "risk": risk})

        return results

    # --- SEARCH FOR STAGED COPIES ---
    def search_for_db_copies(self, search_dirs, max_depth=3):
        """
        Recursively scan directories for sensitive files.
        Skips unconfigured user profiles while allowing explicitly targeted profile subdirectories.
        """
        found = []

        def safe_scan(base, depth, skip_user_profiles=True):
            if depth > max_depth:
                return
            try:
                for entry in os.scandir(base):
                    path = entry.path
                    path_l = path.lower()

                    # Skip user profiles only when walking broader root paths
                    if skip_user_profiles and path_l.startswith("c:\\users\\") and not path_l.startswith("c:\\users\\public"):
                        continue

                    if entry.is_file():
                        name_l = entry.name.lower()
                        if name_l in KNOWN_BENIGN_FILES:
                            continue
                        for pat in SENSITIVE_PATTERNS:
                            if glob.fnmatch.fnmatch(name_l, pat.lower()):
                                exposed = self.has_everyone_permission(path)
                                risk = "exposed" if exposed else "low risk"
                                found.append({"target": path, "risk": risk})
                                break
                    elif entry.is_dir():
                        safe_scan(path, depth + 1, skip_user_profiles=skip_user_profiles)

            except (PermissionError, FileNotFoundError):
                pass
            except Exception as e:
                print(f"[WARN] Could not scan {base}: {e}")

        expanded_dirs = []
        seen_dirs = set()
        for base in search_dirs:
            if not base:
                continue
            candidates = glob.glob(base) if ("*" in base or "?" in base) else [base]
            for candidate in candidates:
                if os.path.isdir(candidate):
                    norm_dir = os.path.normcase(os.path.abspath(candidate))
                    if norm_dir not in seen_dirs:
                        seen_dirs.add(norm_dir)
                        expanded_dirs.append(candidate)

        for target_dir in expanded_dirs:
            target_l = os.path.normcase(os.path.abspath(target_dir))
            skip_profiles = not target_l.startswith("c:\\users\\")
            safe_scan(target_dir, 0, skip_user_profiles=skip_profiles)

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
    @staticmethod
    def minimal_report(targets, copies):
        sensitive = []
        seen = set()

        for item in targets + copies:
            target = item["target"]
            key = os.path.normcase(
                os.path.abspath(target)
            )

            if key in seen:
                continue

            seen.add(key)

            sensitive.append(
                f"{target} ({item['risk']})"
            )

        if sensitive:
            result = "\nSensitive Files Detected:\n"
            for s in sensitive:
                result += f"- {s}\n"
        else:
            result = "No sensitive files detected"

        return result

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
    def show_sensitive_paths(self, check_dirs=None):
        result = self.check_sensitive_paths(check_dirs=check_dirs)
        if "error" in result:
            return result["error"]
        return self.minimal_report(result["targets"], result["copies"])

# ===== Suspicious Processes =====
class SuspiciousProcesses:

    _cache = None
    _driver_services = None

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

    @staticmethod
    def get_clipboard_text():
        """Safely read clipboard text on Windows."""
        try:
            win32clipboard.OpenClipboard()
            data = win32clipboard.GetClipboardData(win32con.CF_TEXT)
            win32clipboard.CloseClipboard()

            if isinstance(data, bytes):
                return data.decode(errors="ignore")
            return data

        except Exception:
            try:
                win32clipboard.CloseClipboard()
            except:
                pass
            return None

    # --- Clipboard monitoring ---
    @staticmethod
    def clipboard_hash(text):
        """Normalize clipboard content for comparison."""
        if not text:
            return None
        return hashlib.sha256(text.encode(errors="ignore")).hexdigest()

    @classmethod
    def get_clipboard_events(cls, poll_interval=0.1, samples=20):
        """
        Snapshot clipboard state for correlation (NON-BLOCKING).

        Returns:
            list of clipboard change events
        """

        last_hash = None
        events = []

        for _ in range(samples):
            try:
                text = cls.get_clipboard_text()
            except Exception:
                text = ""

            h = cls.clipboard_hash(text)

            if h and h != last_hash:
                events.append({
                    "timestamp": time.time(),
                    "size": len(text) if text else 0,
                })

                last_hash = h

                # keep memory bounded
                if len(events) > 20:
                    events.pop(0)

            time.sleep(poll_interval)

        return events

    # --- Set services variable ---
    @classmethod
    def _get_driver_services(cls):
        if cls._driver_services is None:
            services = set()
            for svc in psutil.win_service_iter():
                try:
                    info = svc.as_dict()
                    binpath = (info.get("binpath") or "").lower()

                    if ".sys" in binpath:
                        services.add(info["name"].lower())

                except Exception:
                    continue
            cls._driver_services = services
        return cls._driver_services

    # --- Process privilege / module helpers ---
    @staticmethod
    def is_process_elevated(pid):
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

            OpenProcess = ctypes.windll.kernel32.OpenProcess
            OpenProcess.restype = wintypes.HANDLE

            process_handle = OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION,
                False,
                pid
            )

            if not process_handle:
                return None

            try:
                OpenProcessToken = ctypes.windll.advapi32.OpenProcessToken
                OpenProcessToken.restype = wintypes.BOOL

                token_handle = wintypes.HANDLE()

                if not OpenProcessToken(
                    process_handle,
                    TOKEN_QUERY,
                    ctypes.byref(token_handle)
                ):
                    return None

                try:
                    GetTokenInformation = ctypes.windll.advapi32.GetTokenInformation
                    GetTokenInformation.restype = wintypes.BOOL

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
                    ctypes.windll.kernel32.CloseHandle(token_handle)

            finally:
                ctypes.windll.kernel32.CloseHandle(process_handle)

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

            for module in modules:
                path = getattr(module, "path", None)

                if not path:
                    continue

                path_lower = os.path.normcase(path).lower()

                # Skip normal Windows modules.
                if path_lower.startswith(
                    os.path.normcase(r"c:\windows\system32")
                ):
                    continue

                if path_lower.startswith(
                    os.path.normcase(r"c:\windows\syswow64")
                ):
                    continue

                if path_lower.startswith(
                    os.path.normcase(r"c:\windows\winsxs")
                ):
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
            escaped_path = exe_path.replace("'", "''")

            command = (
                f"$sig = Get-AuthenticodeSignature -LiteralPath '{escaped_path}'; "
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
                env=_safe_subproc_env(),
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
            escaped = r"\s+".join(re.escape(part) for part in parts)
            if pat.startswith("-"):
                regex = re.compile(rf"(?:^|\s){escaped}(?=\s|$|=)")
            else:
                regex = re.compile(rf"(?:^|[\s\"'\\/(\[.]){escaped}(?:\.exe)?(?=$|[\s\"'();.\]])")
            compiled.append((pat, regex))
        return compiled

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

        # --- Preload scheduled tasks executables ---
        scheduled_execs = set()
        try:
            output = subprocess.check_output(
                [_system_exe("schtasks"), "/query", "/fo", "LIST", "/v"],
                text=True, encoding='utf-8', errors='ignore',
                env=_safe_subproc_env(),
                **_subproc_kwargs_hide_window()
            )
            current_task = {}
            for line in output.splitlines():
                line = line.strip()
                if not line:
                    if current_task.get("Task To Run"):
                        exe_name = _extract_exec_name(current_task["Task To Run"])
                        if exe_name:
                            scheduled_execs.add(exe_name)
                    current_task = {}
                    continue
                if ":" in line:
                    key, val = line.split(":", 1)
                    current_task[key.strip()] = val.strip()
            if current_task.get("Task To Run"):
                exe_name = _extract_exec_name(current_task["Task To Run"])
                if exe_name:
                    scheduled_execs.add(exe_name)
        except Exception:
            scheduled_execs = set()

        # --- Preload registry run key executables ---
        registry_execs = set()
        run_keys = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"),
        ]
        for hive, path in run_keys:
            try:
                with winreg.OpenKey(hive, path) as reg_key:
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

        process_name_counts = {}

        for proc in psutil.process_iter(['name']):
            try:
                pname = (proc.info.get("name") or "").lower()

                if pname:
                    process_name_counts[pname] = process_name_counts.get(pname, 0) + 1

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # --- Scan running processes ---
        try:
            self_path = os.path.normcase(psutil.Process(self_pid).exe())
        except Exception:
            self_path = None

        scan_now = time.time()
        try:
            boot_grace = (scan_now - psutil.boot_time()) < 180
        except Exception:
            boot_grace = False

        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                # Skip Secuditor's own process
                if proc.pid == self_pid:
                    continue

                try:
                    proc_path = os.path.normcase(proc.exe())
                except (psutil.AccessDenied, psutil.NoSuchProcess, FileNotFoundError):
                    proc_path = None

                if self_path and proc_path == self_path:
                    continue

                total += 1
                pname = (proc.info.get("name") or "").lower()
                cmdline = " ".join(proc.info.get('cmdline') or []).lower()
                risk = 0
                reasons = []

                # --- Path ---
                try:
                    path = proc.exe()
                except (psutil.AccessDenied, psutil.NoSuchProcess, FileNotFoundError):
                    path = None

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

                except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                    pass

                # --- Scheduled task trigger ---
                if pname in scheduled_execs or strip_extension(pname) in scheduled_execs:
                    risk += 10
                    reasons.append("Found in scheduled tasks")

                # --- Registry Run key trigger ---
                if pname in registry_execs or strip_extension(pname) in registry_execs:
                    risk += 10
                    reasons.append("Found in registry Run keys")

                # --- Multiple process instances ---
                instance_count = process_name_counts.get(pname, 1)

                if instance_count > 1:

                    risk += 10
                    reasons.append(
                        f"Multiple instances running ({instance_count})"
                    )

                # --- Suspicious child process tracking ---
                children = proc.children()
                if len(children) > 3:
                    risk += 10
                    reasons.append("Multiple child processes")

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
                if path and not is_verified_system:

                    # --- Digital signature validation ---
                    sig_status = "Unknown"

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
                            reasons.append(f"Unknown signature status")

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
                            time.time() - e["timestamp"] < 30
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
                            if (
                                entropy >= 7.5
                                and not is_windows_path
                                and sig_status != "Valid"
                            ):
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

                    # --- Driver usage trigger ---
                    try:
                        for sname in self._get_driver_services():
                            if pname == sname:
                                risk += 10
                                reasons.append(f"Driver-backed service: {sname}")
                    except Exception:
                        pass

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
                    ", ".join(reasons),
                    True
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

        if not deduped:
            cls._cache = "No suspicious activity detected"
            return cls._cache

        # --- Output formatting fix only ---
        lines = [""]

        for name, pid, risk, path, reasons, flag in deduped:
            lines.append(
                f"- '{name}', pid: {pid}, path: '{path}', risk: {risk}\n"
                f"      [findings: {reasons}]\n"
            )

        cls._cache = "\n    ".join(lines)
        return cls._cache
