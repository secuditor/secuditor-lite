# Secuditor Lite – Copyright (c) 2026 Menahem Levinski

import requests, json, logging, time, psutil
import sys, io, re, os, webbrowser
import socket, ssl, ipaddress, traceback
import ctypes, types
import threading
import tkinter as tk

from tkinter import ttk, scrolledtext, filedialog, messagebox
from urllib.parse import urlparse
from requests.adapters import HTTPAdapter
from datetime import datetime

from secuditor_utilities import (
    TrafficFlow,
    LanScanner,
    NetStatus,
    SpeedTest,
    resource_path,
    set_window_icon,
    load_oui_database,
)
import secuditor_scanners
from secuditor_scanners import SSLInspection, SensitivePaths, SuspiciousProcesses, SuspiciousProxy
import secuditor_modules
from secuditor_modules import (
    get_domain_settings,
    check_ntlm_policy,
    HardwareReport,
    NetworkSettings,
    SharedFolders,
    GatewayDiscovery,
    SystemSettings,
    InstalledApps,
    SecuritySettings,
    RemoteAccessSettings,
    DomainSettings,
    PasswordPolicy,
    CredentialIntegrity,
    WindowsEvents,
    WindowsUpdates,
)

import secuditor_loader

# ===== CONFIGURATION =====

# --- Safe check for other functions ---
def safe_call(func):
    try:
        return func()
    except Exception as e:
        return f"Error: {e}"

# ==== DYNAMIC FUNCTIONS ====
# Remove CWD from default Windows DLL search order without breaking _MEIPASS/PyInstaller
if sys.platform == "win32":
    try:
        ctypes.windll.kernel32.SetDllDirectoryW("")
    except Exception:
        pass

_ALLOWED_DOWNLOAD_HOSTS = {"secuditor.com", "www.secuditor.com", "updates.secuditor.com"}

def _is_safe_download_url(url: str) -> bool:
    if not isinstance(url, str):
        return False
    parsed = urlparse(url.strip())
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "https":
        return False
    if host in _ALLOWED_DOWNLOAD_HOSTS:
        return True
    if host == "github.com" and parsed.path.lower().startswith("/secuditor/"):
        return True
    return False

class _HybridSSLAdapter(HTTPAdapter):
    """Verify HTTPS against both the OS certificate store and certifi CA bundle."""

    def _build_ssl_context(self):
        ctx = ssl.create_default_context()
        try:
            import certifi
            ctx.load_verify_locations(cafile=certifi.where())
        except Exception:
            pass
        return ctx

    def init_poolmanager(self, *args, **kwargs):
        kwargs["ssl_context"] = self._build_ssl_context()
        return super().init_poolmanager(*args, **kwargs)

    def proxy_manager_for(self, *args, **kwargs):
        kwargs["ssl_context"] = self._build_ssl_context()
        return super().proxy_manager_for(*args, **kwargs)


def check_transmission_port(url: str, timeout: int = 4):
    target_url = url if "://" in url else f"http://{url}"
    parsed = urlparse(target_url)
    host = parsed.hostname
    protocol = (parsed.scheme or "http").lower()
    port = parsed.port or (443 if protocol == "https" else 80)

    start_time = time.perf_counter()
    try:
        headers = {"User-Agent": "Secuditor-Lite"}
        with requests.Session() as session:
            session.mount("https://", _HybridSSLAdapter())
            with session.head(
                target_url,
                headers=headers,
                timeout=timeout,
                allow_redirects=True,
            ):
                pass
        latency = (time.perf_counter() - start_time) * 1000  # ms

        return {
            "host": host,
            "port": port,
            "reachable": True,
            "latency_ms": round(latency, 2),
            "protocol": protocol.upper(),
            "error": None,
        }

    except Exception as e:
        return {
            "host": host,
            "port": port,
            "reachable": False,
            "latency_ms": None,
            "protocol": protocol.upper(),
            "error": str(e),
        }

# ===== CACHE HELPERS =====
def _clear_all_audit_caches():
    secuditor_modules.clear_audit_caches()
    secuditor_scanners.clear_audit_caches()

# ===== Timeouts =====
CALCULATION_TIMEOUT = 60  # seconds
MODULE_TIMEOUT = 180  # seconds per module

# ===== SECURITY CHECKS =====
# --- OUI Vendor Database ---
def initialize_oui_database():
    """Load the local OUI cache at startup and check for updates."""
    logging.info("[*] Initializing OUI database...")

    # Load local SQLite cache immediately.
    load_oui_database(force_reload=True)

    # Check and download updates without blocking application startup.
    def update_worker():
        logging.info("[*] Checking for OUI database updates...")

        if secuditor_loader.update_oui_cache():
            # Refresh the cache after a successful update.
            oui_cache = load_oui_database(force_reload=True)

            logging.info(
                f"[+] OUI database updated successfully "
                f"({len(oui_cache):,} vendor mappings)."
            )
        else:
            logging.info(
                "[=] OUI database update not applied; "
                "continuing with the available local cache."
            )

    threading.Thread(
        target=update_worker,
        daemon=True,
        name="OUI-Update"
    ).start()

# ===== CALCULATE =====
# --- Calculate a security score based on collected data with explanations (breakdown) ---
def calculate_score_with_breakdown(data):
    score = 100
    result = {}
    severity = {}
    breakdown = {}
    config = {}
    gravity = {}

    def ensure_dict(val):
        if isinstance(val, str):
            try:
                parsed = json.loads(val)
                return parsed if isinstance(parsed, dict) else {}
            except Exception:
                return {}
        return val if isinstance(val, dict) else {}

    def _as_str(val, default="Unknown"):
        return val if isinstance(val, str) else (str(val) if val is not None else default)

    def _set_score(name, points, res, cfg, grav, sev):
        nonlocal score
        breakdown[name] = points
        result[name] = res
        config[name] = cfg
        gravity[name] = grav
        severity[name] = sev
        score += points

    def _set_na(name):
        _set_score(name, 0, "N/A", "N/A", "N/A", "N/A")

    def _safe_section(name, fn):
        try:
            fn()
        except Exception as e:
            logging.warning("[Score Calculation] %s failed: %s", name, e)
            _set_na(name)

    def _score_interception_verdict(name, verdict_val, legit_points):
        verdict_norm = _as_str(verdict_val).strip().title()
        if verdict_norm == "Not Detected":
            _set_score(name, 5, "Pass", "Network Security", "NoDetect", "Med")
        elif verdict_norm == "Likely Legitimate":
            _set_score(name, legit_points, "Pass", "Network Security", "Complies", "Med")
        elif verdict_norm == "Suspicious":
            _set_score(name, -15, "Fail", "Network Security", "Detected", "Med")
        elif verdict_norm == "Unknown":
            _set_score(name, -5, "Fail", "Network Security", "Unknown", "Med")
        else:
            _set_na(name)

    failed_checks = set(data.get("_failed_checks") or ()) if isinstance(data, dict) else set()

    infosec = {}
    infosec_ok = False
    if "Endpoint_Security_Settings" not in failed_checks:
        try:
            infosec = ensure_dict(SecuritySettings().get_security_settings())
            infosec_ok = True
        except Exception as e:
            logging.warning("[Score Calculation] SecuritySettings failed: %s", e)

    # --- Antivirus ---
    def _score_antivirus():
        if not infosec_ok:
            _set_na("Endpoint Protection")
            return

        defender = infosec.get("Windows Defender", [])
        endpoint = infosec.get("Endpoint Protection", [])

        if isinstance(defender, str):
            defender = [defender]
        elif not isinstance(defender, list):
            defender = []

        if isinstance(endpoint, str):
            endpoint = [endpoint]
        elif not isinstance(endpoint, list):
            endpoint = []

        av_list = endpoint if endpoint else defender
        av_active = any(isinstance(av, str) and "Active" in av for av in av_list)

        if av_list:
            first_item = _as_str(av_list[0])
            words = first_item.split()
            av_name = " ".join(words[:2]) if len(words) >= 2 else first_item
        else:
            av_name = "Unknown"

        if av_active:
            _set_score("Endpoint Protection", 10, "Pass", av_name, "Operates", "Hvy")
        else:
            _set_score("Endpoint Protection", -25, "Fail", av_name, "Inactive", "Hvy")

    _safe_section("Endpoint Protection", _score_antivirus)

    # --- Firewall ---
    def _score_firewall():
        if not infosec_ok:
            _set_na("Host-based Firewall")
            return

        fw = _as_str(infosec.get("Host-based Firewall", "Unknown"))
        if "(" in fw and ")" in fw:
            status = fw.split("(")[-1].strip(")")
        else:
            status = fw

        controller = fw.split("(")[0].strip() if "(" in fw else fw

        if status == "Off":
            _set_score("Host-based Firewall", -10, "Fail", controller, "Inactive", "Med")
        elif status == "Partially":
            _set_score("Host-based Firewall", 0, "Pass", controller, "Operates", "Med")
        elif status == "On":
            _set_score("Host-based Firewall", 10, "Pass", controller, "Operates", "Med")
        else:
            _set_na("Host-based Firewall")

    _safe_section("Host-based Firewall", _score_firewall)

    # --- Gateway Discovery ---
    def _score_gateway():
        if "Gateway_Discovery" in failed_checks:
            _set_na("Network Gateway")
            return

        gw = GatewayDiscovery()
        gateways = gw.get_default_gateway()
        gw_ip = (gateways.get("IPv4") or gateways.get("IPv6")) if isinstance(gateways, dict) else None

        if not gw_ip:
            _set_na("Network Gateway")
            return

        if ipaddress.ip_address(gw_ip.split("%")[0]).version == 6:
            vendor = "IPv6 Gateway"
        else:
            mac = gw.get_mac_from_arp(gw_ip)
            vendor = gw.lookup_vendor(mac, device_ip=gw_ip) if mac else "Unknown"

        nat = gw.detect_nat() or "Unknown"
        vendor_str = _as_str(vendor)
        vendor_short = " ".join(vendor_str.split()[:2]) if vendor_str else "Unknown"
        vendor_display = vendor_short

        management_ports = gw.detect_management_ports(gw_ip)
        exposed_port = isinstance(management_ports, str) and "Exposed" in management_ports

        if vendor_short != "Unknown" or nat == "Detected":
            if exposed_port:
                _set_score("Network Gateway", -15, "Fail", vendor_display, "Exposed", "Med")
            else:
                _set_score("Network Gateway", 5, "Pass", vendor_display, "Operates", "Med")
        else:
            _set_score("Network Gateway", -15, "Fail", "Unknown Vendor", "Inactive", "Med")

    _safe_section("Network Gateway", _score_gateway)

    # --- Auto Screen Lock ---
    def _score_auto_lock():
        if not infosec_ok:
            _set_na("Auto Screen Lock")
            return

        raw_lock = _as_str(infosec.get("Auto Screen Lock", "Unknown"))
        lock_parts = raw_lock.split()
        auto_lock = lock_parts[0] if lock_parts else "Unknown"

        match = re.search(r"\((.*?)\)", raw_lock)
        auto_lock_ref = match.group(1) if match else "Unknown"

        if auto_lock == "Disabled":
            _set_score("Auto Screen Lock", -10, "Fail", auto_lock_ref, "Inactive", "Med")
        elif auto_lock == "Default":
            _set_score("Auto Screen Lock", 5, "Pass", auto_lock_ref, "Operates", "Med")
        elif auto_lock == "Enforced":
            _set_score("Auto Screen Lock", 10, "Pass", auto_lock_ref, "Operates", "Med")
        else:
            _set_na("Auto Screen Lock")

    _safe_section("Auto Screen Lock", _score_auto_lock)

    # --- UAC Protection ---
    def _score_uac():
        if not infosec_ok:
            _set_na("Elevation Prompt")
            return

        uac = _as_str(infosec.get("UAC Elevation", "Unknown"))

        if uac.startswith(("Prompt for consent", "Prompt for credentials")):
            _set_score("Elevation Prompt", 5, "Pass", "UAC Protection", "Enforced", "Med")

        elif uac == "Unknown":
            _set_na("Elevation Prompt")

        else:
            _set_score("Elevation Prompt", -15, "Fail", "UAC Protection", "Inactive", "Med")

    _safe_section("Elevation Prompt", _score_uac)

    # --- Core Isolation ---
    def _score_core_isolation():
        if not infosec_ok:
            _set_na("Memory Integrity")
            return

        core = _as_str(infosec.get("Core Isolation", "Unknown"))
        if core.startswith("Enabled"):
            _set_score("Memory Integrity", 5, "Pass", "Core Isolation", "Enforced", "Low")
        elif core.startswith("Disabled"):
            _set_score("Memory Integrity", -5, "Fail", "Core Isolation", "Inactive", "Low")
        else:
            _set_na("Memory Integrity")

    _safe_section("Memory Integrity", _score_core_isolation)

    # --- UEFI Secure Boot ---
    def _score_secure_boot():
        if not infosec_ok:
            _set_na("Boot Security Layer")
            return

        secureboot = _as_str(infosec.get("UEFI Secure Boot", "Unknown"))
        if secureboot == "Enabled":
            _set_score("Boot Security Layer", 5, "Pass", "UEFI Secure Boot", "Enforced", "Low")
        elif secureboot == "Disabled":
            _set_score("Boot Security Layer", -5, "Fail", "UEFI Secure Boot", "Inactive", "Low")
        else:
            _set_na("Boot Security Layer")

    _safe_section("Boot Security Layer", _score_secure_boot)

    # --- System Restore ---
    def _score_system_restore():
        if not infosec_ok:
            _set_na("System Restore")
            return

        sys_restore = _as_str(infosec.get("System Restore", "Unknown"))
        if sys_restore.startswith("Disabled"):
            _set_score("System Restore", -5, "Fail", "Restore Point", "Inactive", "Low")
        elif sys_restore.startswith("Enabled"):
            _set_score("System Restore", 5, "Pass", "Restore Point", "Enforced", "Low")
        elif sys_restore == "Unusable (Server)":
            _set_score("System Restore", 5, "Pass", "Restore Point", "Unusable", "Low")
        else:
            _set_na("System Restore")

    _safe_section("System Restore", _score_system_restore)

    # --- BitLocker Drive Encryption ---
    def _score_bitlocker():
        if not infosec_ok:
            _set_na("Disk Encryption")
            return

        bitlock = _as_str(infosec.get("BitLocker Drive Encryption", "Unknown"))
        if bitlock == "Enabled":
            _set_score("Disk Encryption", 5, "Pass", "Enterprise Related", "Enforced", "Med")
        elif bitlock == "Disabled":
            _set_score("Disk Encryption", -5, "Fail", "Enterprise Related", "Inactive", "Med")
        else:
            _set_na("Disk Encryption")

    _safe_section("Disk Encryption", _score_bitlocker)

    # --- LAPS Protection ---
    def _score_laps():
        if "Domain_Settings" in failed_checks:
            _set_na("LAPS Protection")
            return

        domain_set = ensure_dict(get_domain_settings())
        laps = _as_str(domain_set.get("LAPS", "Not Detected"), default="Not Detected")

        if laps in ("Not Detected", "Disabled"):
            _set_score("LAPS Protection", -15, "Fail", "Enterprise Related", "Inactive", "Med")
        elif laps == "Enabled":
            _set_score("LAPS Protection", 5, "Pass", "Enterprise Related", "Enforced", "Med")
        else:
            _set_na("LAPS Protection")

    _safe_section("LAPS Protection", _score_laps)

    # --- Credential Guard ---
    def _score_credential_guard():
        if "Credential_Integrity" in failed_checks:
            _set_na("Credential Guard")
            return

        cred = CredentialIntegrity()
        credential_gua = _as_str(cred.check_credential_guard()).strip()
        credential_pro = _as_str(cred.check_lsass_protection())

        if credential_pro == "Enabled (Protected Process Light)" and credential_gua == "Enabled":
            _set_score("Credential Guard", 5, "Pass", "Enterprise Related", "Enforced", "Med")
        elif credential_gua in ("Unknown", "Not supported by current Windows edition"):
            _set_na("Credential Guard")
        else:
            _set_score("Credential Guard", -10, "Fail", "Enterprise Related", "Inactive", "Med")

    _safe_section("Credential Guard", _score_credential_guard)

    # --- Domain Settings & Password Policy ---
    policy = {}
    policy_ok = False
    directory = "Unknown"
    if "Password_Policy" not in failed_checks:
        try:
            policy = ensure_dict(PasswordPolicy().get_password_policy_nonadmin())
            policy_ok = True
        except Exception as e:
            logging.warning("[Score Calculation] PasswordPolicy failed: %s", e)

    def _score_domain_settings():
        nonlocal directory
        if not policy_ok:
            _set_na("Domain Settings")
            return

        affiliation_full = _as_str(policy.get("Policy Affiliation", "Unknown")).strip()
        cleaned = re.sub(r"\(.*?\)", "", affiliation_full).strip()
        parts = cleaned.split()
        affiliation_first = parts[0] if parts else "Unknown"

        if affiliation_first == "Domain":
            directory = "Active Directory"
            _set_score("Domain Settings", 0, "Pass", directory, "Managed", "Med")
        elif affiliation_first == "Workgroup":
            directory = "Workgroup (Local)"
            _set_score("Domain Settings", 0, "Pass", directory, "Default", "Med")
        else:
            directory = "Unknown"
            _set_score("Domain Settings", 0, "Pass", directory, "Default", "Med")

    _safe_section("Domain Settings", _score_domain_settings)

    def _score_password_policy():
        if not policy_ok:
            _set_na("Password Policy")
            return

        verdict = _as_str(policy.get("Verdict", "Unknown"))
        if verdict == "Weak":
            _set_score("Password Policy", -40, "Fail", directory, "Minimal", "Hvy")
        elif verdict == "Moderate":
            _set_score("Password Policy", 0, "Pass", directory, "Moderate", "Hvy")
        elif verdict == "Strong":
            _set_score("Password Policy", 10, "Pass", directory, "Strong", "Hvy")
        else:
            _set_na("Password Policy")

    _safe_section("Password Policy", _score_password_policy)

    # --- Remote Security score ---
    ra = None
    remote = {}
    remote_ok = False
    if "Remote_Access_Settings" not in failed_checks:
        try:
            ra = RemoteAccessSettings()
            remote = ensure_dict(ra.get_remote_access_settings())
            remote_ok = True
        except Exception as e:
            logging.warning("[Score Calculation] RemoteAccessSettings failed: %s", e)

    # --- Bluetooth ---
    def _score_bluetooth():
        if not remote_ok:
            _set_na("Bluetooth Component")
            return

        bluetooth = _as_str(remote.get("Bluetooth", "Unknown"))
        if bluetooth.startswith(("Enabled, Moderate Risk", "Enabled, Exposure")):
            _set_score("Bluetooth Component", -5, "Fail", "Remote Access", "Exposed", "Low")
        elif bluetooth.startswith("Enabled, Low Risk"):
            _set_score("Bluetooth Component", 5, "Pass", "Remote Access", "Default", "Low")
        elif bluetooth.startswith(("Disabled", "Not Detected", "Unknown")):
            _set_score("Bluetooth Component", 0, "Pass", "Remote Access", "Disabled", "Low")
        else:
            _set_na("Bluetooth Component")

    _safe_section("Bluetooth Component", _score_bluetooth)

    # --- PowerShell Remoting ---
    def _score_psr():
        if not remote_ok:
            _set_na("PowerShell Remoting")
            return

        psr = _as_str(remote.get("PowerShell Remoting", "Unknown"))
        if psr.startswith("Enabled, Potentially Dangerous"):
            _set_score("PowerShell Remoting", -15, "Fail", "Remote Access", "Exposed", "Med")
        elif psr.startswith("Disabled"):
            _set_score("PowerShell Remoting", 0, "Pass", "Remote Access", "Disabled", "Med")
        else:
            _set_na("PowerShell Remoting")

    _safe_section("PowerShell Remoting", _score_psr)

    # --- RPC Print Spooler ---
    def _score_rpc():
        if not remote_ok:
            _set_na("RPC Print Spooler")
            return

        rpc = _as_str(remote.get("RPC Print Spooler", "Unknown"))
        if rpc.startswith("Enabled, Potentially Dangerous"):
            _set_score("RPC Print Spooler", -10, "Fail", "Remote Access", "Exposed", "Low")
        elif rpc.startswith(("Enabled, Low Risk", "Enabled, Moderate Risk")):
            _set_score("RPC Print Spooler", 0, "Pass", "Remote Access", "Hardened", "Low")
        elif rpc == "Disabled":
            _set_score("RPC Print Spooler", 0, "Pass", "Remote Access", "Disabled", "Low")
        else:
            _set_na("RPC Print Spooler")

    _safe_section("RPC Print Spooler", _score_rpc)

    # --- SMBv1 Protocol ---
    def _score_smb1():
        if not remote_ok:
            _set_na("SMBv1 Protocol")
            return

        smb1_raw = _as_str(remote.get("SMB1", "Unknown"))
        smb1 = " ".join(smb1_raw.split()[:3])
        if smb1 == "Enabled, High Risk":
            _set_score("SMBv1 Protocol", -25, "Fail", "Remote Access", "Exposed", "Hvy")
        elif smb1 == "Disabled":
            _set_score("SMBv1 Protocol", 0, "Pass", "Remote Access", "Disabled", "Hvy")
        else:
            _set_na("SMBv1 Protocol")

    _safe_section("SMBv1 Protocol", _score_smb1)

    # --- SMBv2 Protocol ---
    def _score_smb2():
        if not remote_ok:
            _set_na("SMBv2 Protocol")
            return

        smb2 = _as_str(remote.get("SMB2", "Unknown")).strip()
        if smb2.startswith("Enabled, Potentially Dangerous"):
            _set_score("SMBv2 Protocol", -15, "Fail", "Remote Access", "Exposed", "Hvy")
        elif smb2.startswith("Enabled, Low Risk"):
            _set_score("SMBv2 Protocol", 0, "Pass", "Remote Access", "Hardened", "Hvy")
        elif smb2.startswith("Enabled, Moderate Risk"):
            _set_score("SMBv2 Protocol", 0, "Pass", "Remote Access", "Default", "Hvy")
        elif smb2 == "Disabled":
            _set_score("SMBv2 Protocol", 0, "Pass", "Remote Access", "Disabled", "Hvy")
        else:
            _set_na("SMBv2 Protocol")

    _safe_section("SMBv2 Protocol", _score_smb2)

    # --- FTP Service ---
    def _score_ftp():
        if not remote_ok:
            _set_na("FTP Service")
            return

        ftp = _as_str(remote.get("FTP Service", "Unknown"))
        if ftp.startswith("Running,"):
            _set_score("FTP Service", -10, "Fail", "Remote Access", "Exposed", "Med")
        elif ftp.startswith(("Stopped", "Not Detected")):
            _set_score("FTP Service", 0, "Pass", "Remote Access", "Disabled", "Med")
        else:
            _set_na("FTP Service")

    _safe_section("FTP Service", _score_ftp)

    # --- DCOM Service ---
    def _score_dcom():
        if not remote_ok:
            _set_na("DCOM Service")
            return

        dcom = _as_str(remote.get("DCOM", "Unknown"))
        if dcom.startswith("Enabled, Potentially Dangerous"):
            _set_score("DCOM Service", -10, "Fail", "Remote Access", "Exposed", "Med")
        elif dcom.startswith(("Enabled, Low Risk", "Enabled, Hardened")):
            _set_score("DCOM Service", 0, "Pass", "Remote Access", "Hardened", "Med")
        elif dcom.startswith("Enabled, Moderate Risk"):
            _set_score("DCOM Service", 0, "Pass", "Remote Access", "Default", "Med")
        elif dcom == "Remote Disabled":
            _set_score("DCOM Service", 0, "Pass", "Remote Access", "Disabled", "Med")
        else:
            _set_na("DCOM Service")

    _safe_section("DCOM Service", _score_dcom)

    # --- WinRM Service ---
    def _score_winrm():
        if "Remote_Access_Settings" in failed_checks:
            _set_na("WinRM Service")
            return

        ra_inst = ra or RemoteAccessSettings()
        winrm_data = ensure_dict(ra_inst.audit_winrm())
        winrm = _as_str(winrm_data.get("verdict", "Unknown"))

        if winrm.startswith("Enabled, High Risk"):
            _set_score("WinRM Service", -10, "Fail", "Remote Access", "Exposed", "Med")
        elif winrm.startswith(("Enabled, Moderate Risk", "Enabled, Low Risk")):
            _set_score("WinRM Service", 0, "Pass", "Remote Access", "Default", "Med")
        elif winrm == "Disabled":
            _set_score("WinRM Service", 0, "Pass", "Remote Access", "Disabled", "Med")
        else:
            _set_na("WinRM Service")

    _safe_section("WinRM Service", _score_winrm)

    # --- Remote Desktop ---
    def _score_rdp():
        if not remote_ok:
            _set_na("Remote Desktop")
            return

        rdp = _as_str(remote.get("Remote Desktop", "Unknown"))
        if rdp.startswith("Enabled, Potentially Exposed"):
            _set_score("Remote Desktop", -10, "Fail", "Remote Access", "Exposed", "Med")
        elif rdp.startswith("Enabled, Low Risk"):
            _set_score("Remote Desktop", 0, "Pass", "Remote Access", "Default", "Med")
        elif rdp == "Disabled":
            _set_score("Remote Desktop", 0, "Pass", "Remote Access", "Disabled", "Med")
        else:
            _set_na("Remote Desktop")

    _safe_section("Remote Desktop", _score_rdp)

    # --- NTLM Policy ---
    def _score_ntlm():
        if "Domain_Settings" in failed_checks:
            _set_na("NTLM Configuration")
            return

        ntlm_verdict = _as_str(check_ntlm_policy())
        ntlm_parts = ntlm_verdict.split()
        ntlm_verdict_short = ntlm_parts[0].strip(",") if ntlm_parts else "Unknown"

        if ntlm_verdict_short in ("Critical", "Warning"):
            _set_score("NTLM Configuration", -20, "Fail", "Network Security", "Exposed", "Hvy")
        elif ntlm_verdict_short == "Moderate":
            _set_score("NTLM Configuration", 0, "Pass", "Network Security", "Moderate", "Hvy")
        elif ntlm_verdict_short == "Strong":
            _set_score("NTLM Configuration", 10, "Pass", "Network Security", "Strong", "Hvy")
        else:
            _set_na("NTLM Configuration")

    _safe_section("NTLM Configuration", _score_ntlm)

    # --- Proxy Configuration ---
    def _score_proxy():
        if "Proxy_Configuration" in failed_checks:
            _set_na("Proxy Configuration")
            return

        proxy_data = ensure_dict(SuspiciousProxy().check_suspicious_proxy())
        proxy_verdict = proxy_data.get("verdict", proxy_data.get("Verdict", "Unknown"))
        _score_interception_verdict("Proxy Configuration", proxy_verdict, legit_points=5)

    _safe_section("Proxy Interception", _score_proxy)

    # --- SSL Interception ---
    def _score_ssl():
        if "SSL/TLS_Interception" in failed_checks:
            _set_na("SSL/TLS Interception")
            return

        ssl_data = ensure_dict(SSLInspection().check_ssl_inspection(host="www.google.com", port=443))
        ssl_verdict = ssl_data.get("verdict", ssl_data.get("Verdict", "Unknown"))
        _score_interception_verdict("SSL/TLS Interception", ssl_verdict, legit_points=10)

    _safe_section("SSL/TLS Interception", _score_ssl)

    # --- Suspicious Activity ---
    def _score_suspicious_activity():
        if "Scan_Suspicious_Activity" in failed_checks:
            _set_na("Suspicious Activity")
            return

        sus_proc = SuspiciousProcesses().show_suspicious_processes()

        if (isinstance(sus_proc, list) and len(sus_proc) > 0) or (
            isinstance(sus_proc, str) and sus_proc not in ("", "No suspicious activity detected")
        ):
            _set_score("Suspicious Activity", -15, "Fail", "Network Security", "Detected", "Med")
        elif sus_proc == "No suspicious activity detected":
            _set_score("Suspicious Activity", 5, "Pass", "Network Security", "NoDetect", "Med")
        else:
            _set_na("Suspicious Activity")

    _safe_section("Suspicious Activity", _score_suspicious_activity)

    # Ensure score stays between 0 and 100
    score = max(0, min(score, 100))
    return score, result, breakdown, config, gravity, severity

# ===== CLASS GUI =====
# --- Single-window with tree-per-function ---
class OpSecGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        
        # --- Load oui.csv database to cache ---
        initialize_oui_database()
        
        self.net_status = NetStatus()
        self.speedtest = SpeedTest(self)
        self.lanscan = LanScanner(self)
        self.traflow = TrafficFlow(self)

        # Hide the ghost window
        self.withdraw()
        
        secuditor_modules.set_scan_mode(run_all=False, single=False)
        
        # ✅ Define the target server before calling
        connecting_server = "https://secuditor.com"
        SERVER_CONNECTION = check_transmission_port(connecting_server)
        if SERVER_CONNECTION["reachable"]:
            print(
                f'Connection established with {SERVER_CONNECTION["host"]} (port={SERVER_CONNECTION["port"]})'
            )
        else:
            print(
                f'Connection failed with {SERVER_CONNECTION["host"]} (port={SERVER_CONNECTION["port"]}): {SERVER_CONNECTION["error"]}'
            )
        
        self._idle_log_file = self.start_idle_logging()
        
        self.internet_status = None  # initially unknown
        self.internet_thread = threading.Thread(target=self.check_and_store_internet, daemon=True)
        self.internet_thread.start()

        # --- Shared state ---
        self.FQDN = socket.getfqdn()
        self.CURRENT_VERSION = "2.4.0"
        self.VERSION_URL = "https://updates.secuditor.com/version.json"
        self.download_url = "https://secuditor.com"

        self.latest_version = self.fetch_latest_version()
        self.version_check = self.latest_version > self.CURRENT_VERSION

        # --- Load icon safely ---
        try:
            ico_path = resource_path("icon.ico")
            if os.path.exists(ico_path):
                self.iconbitmap(default=ico_path)
                self.iconbitmap(ico_path)
            else:
                icon_path = resource_path("secuditor_icon.png")
                if os.path.exists(icon_path):
                    icon = tk.PhotoImage(file=icon_path)
                    self._icon_photo = icon
                    self.iconphoto(False, icon)
                else:
                    # Fallback to system info icon
                    user32 = ctypes.windll.user32
                    WM_SETICON = 0x80
                    ICON_BIG = 1
                    ICON_SMALL = 0
                    IDI_INFORMATION = 32516
                    hwnd = user32.GetParent(self.winfo_id()) or self.winfo_id()
                    hicon = user32.LoadIconW(0, IDI_INFORMATION)
                    if hicon:
                        user32.SendMessageW(hwnd, WM_SETICON, ICON_BIG, hicon)
                        user32.SendMessageW(hwnd, WM_SETICON, ICON_SMALL, hicon)
        except Exception as e:
            print(f"⚠️ Could not load icon: {e}")

        # --- ASCII art / welcome text ---
        self.SECUDITOR_LINES = [
            """
░█▀▀░█▀▀░█▀▀░█░█░█▀▄░▀█▀░▀█▀░█▀█░█▀▄░░░█░░░▀█▀░▀█▀░█▀▀
░▀▀█░█▀▀░█░░░█░█░█░█░░█░░░█░░█░█░█▀▄░░░█░░░░█░░░█░░█▀▀
░▀▀▀░▀▀▀░▀▀▀░▀▀▀░▀▀░░▀▀▀░░▀░░▀▀▀░▀░▀░░░▀▀▀░▀▀▀░░▀░░▀▀▀
            """
        ]

        self.WELCOME_UPDATED = [
            "",
            f" Secuditor Lite is Up to Date ✔️",
            "",
            "",
        ]

        self.WELCOME_OUTDATED = [
            "",
            f" Secuditor Lite is Outdated ⚠",
            f" Download the Latest Version Here: {self.download_url}",
            "",
            "",
        ]

        self._host_pulse_job = None
        self._welcome_probe_job = None
        self._welcome_probe_busy = False
        self._welcome_ssl_last_ts = None
        self._endpoint_status_lines = ["Checking endpoint status..."]
        self._welcome_ssl_lines = ["  Checking SSL/TLS interception..."]
        try:
            psutil.cpu_percent(interval=None)
        except Exception:
            pass
        self._start_welcome_probe()
        
        # --- window setup ---
        set_window_icon(self)
        self.title(f"Secuditor Lite")
        self.geometry("1000x720")
        self.minsize(900, 600)
        self.resizable(False, False)

        # --- Center the window on the screen ---
        self.update_idletasks()  # ensures winfo_width and height are accurate
        window_width = 1000
        window_height = 720
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        x = (screen_width // 2) - (window_width // 2)
        y = (screen_height // 2) - (window_height // 2)
        self.geometry(f"{window_width}x{window_height}+{x}+{y}")

        # --- shared state ---
        self.data_cache = {}
        self.single_node_cache = {}
        self._current_single_thread = None
        self._current_single_stop = None
        self._current_single_run_id = 0
        self._active_single_key = None
        self._single_timeout_job = None
                
        # --- build GUI ---
        self._build_toolbar()
        self._build_status_bar()
        self._build_layout()
        self._load_tree_icons()
        self._populate_tree()
        self._bind_tree_context_menu()
        self._bind_keyboard_navigation()

        # --- simulate single-click on hostname node at startup ---
        def select_hostname_node():
            # Find the hostname node
            for item in self.tree.get_children(''):
                if self.tree.item(item, "text") == self.hostname:
                    self.tree.selection_set(item)  # select the node
                    self.tree.focus(item)          # focus the node
                    self.tree.focus_set()          # ensure keyboard events work

                    # Create a fake event object with x, y coordinates inside the tree
                    class Event: pass
                    event = Event()
                    event.x = 1
                    
                    bbox = self.tree.bbox(item)

                    if not bbox:
                        return

                    event.y = bbox[1]  # y-coordinate of the item
                    self._on_tree_single_click(event)
                    break

        # Schedule the simulated click after GUI is ready
        self.after(200, select_hostname_node)

        # --- startup tasks ---
        #self.after(100, self.ask_run_full_audit)

        # Show window only after setup is complete
        self.deiconify()
    
    def show_network_status(self):
        self.net_status.show_network_status(self)

    def show_download_speed(self):
        self.speedtest.show_download_speed()

    def show_lanscan_run(self):
        print("LAN Discovery function clicked")
        self.lanscan.run()

    def show_traflow_run(self):
        print("Traffic Flow function clicked")
        self.traflow.run()
                
    def fetch_latest_version(self):
        version = str(self.CURRENT_VERSION)
        parts = version.split(".")

        if len(parts) >= 2:
            short_version = ".".join(parts[-2:])
        else:
            short_version = version

        try:
            url = f"{self.VERSION_URL}?t={int(time.time())}"
            headers = {"User-Agent": f"Secuditor-Lite/{short_version}"}
            response = requests.get(url, headers=headers, timeout=5)
            response.raise_for_status()

            data = response.json()
            product_data = data.get("secuditor_lite", {})

            candidate_url = product_data.get("download_url")
            if _is_safe_download_url(candidate_url):
                self.download_url = candidate_url.strip()

            latest_version = product_data.get(
                "latest_version",
                self.CURRENT_VERSION
            )

            print(
                f"Current version: {self.CURRENT_VERSION}\n"
                f"Latest available version: {latest_version}"
            )
            return latest_version

        except Exception as e:
            print(
                f"Current version: {self.CURRENT_VERSION}\n"
                f"⚠️ Could not fetch latest available version: {e}"
            )
            return self.CURRENT_VERSION

    def lock_main_widgets(self):
        """Disable interactive widgets only, leave window frame functional."""
        # --- Toolbar buttons ---
        for btn in [self.run_btn, self.home_btn, self.txt_btn, self.upt_btn, self.about_btn, self.network_btn, self.lan_btn, self.traf_btn]:
            btn.config(state="disabled")

        for w in [
            getattr(self, "report_search_entry", None),
            getattr(self, "report_search_prev_btn", None),
            getattr(self, "report_search_next_btn", None),
            getattr(self, "report_search_clear_btn", None),
        ]:
            if w is not None:
                w.config(state="disabled")

        # --- Menu button ---
        if hasattr(self, "menu_button"):
            self.menu_button.config(state="disabled")

        # --- Treeview nodes: fully lock selection and expand/collapse ---
        self._tree_bindings = {}
        for sequence in ["<ButtonRelease-1>", "<Double-1>", "<Return>", "<Up>", "<Down>"]:
            self._tree_bindings[sequence] = self.tree.bind(sequence)
            self.tree.unbind(sequence)

        # Intercept all clicks and navigation keys to prevent expansion/collapse/navigation
        self._tree_click_id = self.tree.bind("<Button-1>", lambda e: "break")
        self._tree_rightclick_id = self.tree.bind("<Button-3>", lambda e: "break")
        self._tree_ctrlclick_id = self.tree.bind("<Control-Button-1>", lambda e: "break")
        self._tree_up_id = self.tree.bind("<Up>", lambda e: "break")
        self._tree_down_id = self.tree.bind("<Down>", lambda e: "break")

        # Gray out tree items to indicate locked state and collapse all
        self.tree.tag_configure("locked", background="#E0E0E0")
        for iid in self.tree.get_children():
            self.tree.item(iid, tags=("locked",))
            self.tree.item(iid, open=False)
            for child in self.tree.get_children(iid):
                self.tree.item(child, open=False)

        # --- Block Report and Console/Logs areas ---
        self.report_output.config(state="disabled")
        self._report_leftclick_id = self.report_output.bind("<Button-1>", lambda e: "break")
        self._report_rightclick_id = self.report_output.bind("<Button-3>", lambda e: "break")

        self.console_output.config(state="disabled")
        self._console_leftclick_id = self.console_output.bind("<Button-1>", lambda e: "break")
        self._console_rightclick_id = self.console_output.bind("<Button-3>", lambda e: "break")

        # --- Reset Report area to welcome text with live Host Pulse (probes paused during audit) ---
        self._render_welcome_banner(include_live_pulse=True)

    def unlock_main_widgets(self):
        """Re-enable previously disabled widgets."""
        # Toolbar buttons
        for btn in [self.run_btn, self.home_btn, self.txt_btn, self.upt_btn, self.about_btn, self.network_btn, self.lan_btn, self.traf_btn]:
            btn.config(state="normal")

        for w in [
            getattr(self, "report_search_entry", None),
            getattr(self, "report_search_prev_btn", None),
            getattr(self, "report_search_next_btn", None),
            getattr(self, "report_search_clear_btn", None),
        ]:
            if w is not None:
                w.config(state="normal")
        
        # Menu button
        if hasattr(self, "menu_button"):
            self.menu_button.config(state="normal")

        # --- Restore Treeview bindings ---
        if hasattr(self, "_tree_bindings"):
            for sequence, callback in self._tree_bindings.items():
                if callback:
                    self.tree.bind(sequence, callback)
            del self._tree_bindings

        # Remove Treeview click and key interception
        if hasattr(self, "_tree_click_id"):
            self.tree.unbind("<Button-1>", self._tree_click_id)
            del self._tree_click_id
        if hasattr(self, "_tree_up_id"):
            self.tree.unbind("<Up>", self._tree_up_id)
            del self._tree_up_id
        if hasattr(self, "_tree_down_id"):
            self.tree.unbind("<Down>", self._tree_down_id)
            del self._tree_down_id
        if hasattr(self, "_tree_ctrlclick_id"):
            self.tree.unbind("<Control-Button-1>", self._tree_ctrlclick_id)
            del self._tree_ctrlclick_id
        if hasattr(self, "_tree_rightclick_id"):
            self.tree.unbind("<Button-3>", self._tree_rightclick_id)
            del self._tree_rightclick_id
            # Restore Treeview right-click context menu
            self._bind_tree_context_menu()

        # Restore Treeview keyboard navigation
        self._bind_keyboard_navigation()

        # Remove gray-out from tree
        for iid in self.tree.get_children():
            self.tree.item(iid, tags=())

        # --- Unblock Report and Console/Logs areas ---
        self.report_output.config(state="normal")
        if hasattr(self, "_report_leftclick_id"):
            self.report_output.unbind("<Button-1>", self._report_leftclick_id)
            del self._report_leftclick_id
        if hasattr(self, "_report_rightclick_id"):
            self.report_output.unbind("<Button-3>", self._report_rightclick_id)
            del self._report_rightclick_id
        self.report_output.bind("<Button-3>", lambda e: self.report_menu.tk_popup(e.x_root, e.y_root))
        self.report_output.bind("<Control-Button-1>", lambda e: self.report_menu.tk_popup(e.x_root, e.y_root))

        self.console_output.config(state="normal")
        if hasattr(self, "_console_leftclick_id"):
            self.console_output.unbind("<Button-1>", self._console_leftclick_id)
            del self._console_leftclick_id
        if hasattr(self, "_console_rightclick_id"):
            self.console_output.unbind("<Button-3>", self._console_rightclick_id)
            del self._console_rightclick_id

    def set_busy_cursor(self):
        # Apply busy cursor to main window and all children
        for widget in self.winfo_children():
            widget.config(cursor="watch")
            if isinstance(widget, (tk.Frame, tk.PanedWindow, tk.Label, tk.Button)):
                for child in widget.winfo_children():
                    child.config(cursor="watch")
        self.config(cursor="watch")
        self.update_idletasks()

    def reset_cursor(self):
        # Restore default cursor for all children
        for widget in self.winfo_children():
            widget.config(cursor="")
            if isinstance(widget, (tk.Frame, tk.PanedWindow, tk.Label, tk.Button)):
                for child in widget.winfo_children():
                    child.config(cursor="")
        self.config(cursor="")
        self.update_idletasks()

    # --- About version ---
    def show_about_version(self):
        about_win = tk.Toplevel(self)
        about_win.withdraw()  # hide while configuring

        set_window_icon(about_win)

        about_win.title("About Secuditor")
        about_win.resizable(False, False)

        # Set size
        width, height = 400, 400
        about_win.geometry(f"{width}x{height}")

        # Center on the main window
        self.update_idletasks()
        x = self.winfo_x() + (self.winfo_width() // 2) - (width // 2)
        y = self.winfo_y() + (self.winfo_height() // 2) - (height // 2)
        about_win.geometry(f"+{x}+{y}")

        # Logo
        try:
            logo = tk.PhotoImage(
                file=resource_path(r"Icons\secuditor_logo.png")
            )

            logo_label = tk.Label(
                about_win,
                image=logo,
                bd=0
            )
            logo_label.image = logo
            logo_label.pack(pady=(15, 5))

        except Exception:
            # Continue without the logo if it cannot be loaded
            pass

        # Application Information
        tk.Label(
            about_win,
            text=f"Secuditor Lite – Version {self.CURRENT_VERSION}",
            font=("Segoe UI", 11, "bold")
        ).pack(pady=(2, 0))

        tk.Label(
            about_win,
            text="Copyright © 2026 Menahem Levinski. All rights reserved.",
            font=("Segoe UI", 9)
        ).pack(pady=(4, 0))

        # Separator
        tk.Frame(
            about_win,
            height=1,
            bg="#d0d0d0"
        ).pack(fill="x", padx=35, pady=(15, 10))

        # Documents
        documents_frame = tk.Frame(about_win)
        documents_frame.pack()

        privacy_link = tk.Label(
            documents_frame,
            text="Privacy Policy (on GitHub)",
            font=("Segoe UI", 10, "underline"),
            fg="blue",
            cursor="hand2"
        )
        privacy_link.pack(pady=(0, 7))

        privacy_link.bind(
            "<Button-1>",
            lambda e: webbrowser.open(
                "https://github.com/secuditor/secuditor-lite/blob/main/PRIVACY.md"
            )
        )

        # License Agreement
        def open_license(event=None):
            about_win.grab_release()

            webbrowser.open(
                "https://github.com/secuditor/secuditor-lite/blob/main/LICENSE.txt"
            )

        license_link = tk.Label(
            documents_frame,
            text="License Agreement (on GitHub)",
            font=("Segoe UI", 10, "underline"),
            fg="blue",
            cursor="hand2"
        )
        license_link.pack()

        license_link.bind(
            "<Button-1>",
            open_license
        )

        # Separator
        tk.Frame(
            about_win,
            height=1,
            bg="#d0d0d0"
        ).pack(fill="x", padx=35, pady=(15, 10))

        # Contact & Website
        info_frame = tk.Frame(about_win)
        info_frame.pack(pady=(8, 0))

        # --- Contact ---
        contact_frame = tk.Frame(info_frame)
        contact_frame.grid(row=0, column=0, padx=(0, 25))

        tk.Label(
            contact_frame,
            text="Contact Us",
            font=("Segoe UI", 9, "bold")
        ).pack()

        email_address = "info@secuditor.com"

        email_link = tk.Label(
            contact_frame,
            text=email_address,
            fg="blue",
            cursor="hand2",
            font=("Segoe UI", 10, "underline")
        )
        email_link.pack(pady=(2, 0))

        email_link.bind(
            "<Button-1>",
            lambda e: webbrowser.open(f"mailto:{email_address}")
        )

        # --- Official Website ---
        website_frame = tk.Frame(info_frame)
        website_frame.grid(row=0, column=1, padx=(25, 0))

        tk.Label(
            website_frame,
            text="Official Website",
            font=("Segoe UI", 9, "bold")
        ).pack()

        website_link = tk.Label(
            website_frame,
            text="www.secuditor.com",
            fg="blue",
            cursor="hand2",
            font=("Segoe UI", 10, "underline")
        )
        website_link.pack(pady=(2, 0))

        website_link.bind(
            "<Button-1>",
            lambda e: webbrowser.open_new("https://secuditor.com")
        )

        # Keyboard shortcuts
        about_win.bind(
            "<Return>",
            lambda e: about_win.destroy()
        )

        about_win.bind(
            "<Escape>",
            lambda e: about_win.destroy()
        )

        # Make modal
        about_win.transient(self)
        about_win.grab_set()
        about_win.deiconify()
        about_win.focus_force()

        self.wait_window(about_win)

    # --- Check for version update status ---
    def check_update_clicked(self):

        print("Check Update function started")
        net_status = self.net_status.check_internet_connection()
        
        update_win = tk.Toplevel(self)
        update_win.withdraw()

        set_window_icon(update_win)

        # Keyboard shortcuts
        update_win.bind(
            "<Escape>",
            lambda e: update_win.destroy()
        )
        
        update_win.title("Check Updates")
        update_win.resizable(False, False)

        width, height = 350, 150
        main_x = self.winfo_x()
        main_y = self.winfo_y()
        update_win.geometry(
            f"{width}x{height}+{main_x + (self.winfo_width()//2 - width//2)}+"
            f"{main_y + (self.winfo_height()//2 - height//2)}"
        )

        update_win.transient(self)
        update_win.grab_set()
        update_win.focus_force()

        status_label = tk.Label(update_win, text="Checking for updates...")
        status_label.pack(pady=20)

        def close_update():
            update_win.destroy()

        update_win.update_idletasks()
        update_win.deiconify()

        try:
            if net_status["Connected"]:
                if self.version_check:
                    status_label.config(
                        text=f"⚠️ Update Available! (Latest: {self.latest_version})"
                    )
                    print("Check Update function completed")

                    def open_download():
                        safe_url = self.download_url if _is_safe_download_url(self.download_url) else "https://secuditor.com"
                        webbrowser.open(safe_url)
                        self.clipboard_clear()
                        self.clipboard_append(safe_url)
                        self.update()

                    download_btn = tk.Button(
                        update_win,
                        text=f"Download ({self.download_url})",
                        fg="blue",
                        bg="#F0F0F0",
                        cursor="hand2",
                        relief="flat",
                        font=("Segoe UI", 10, "underline"),
                        command=open_download
                    )
                    download_btn.pack(pady=10)
                else:
                    status_label.config(
                        text=f"✔ You are Up to Date (v{self.CURRENT_VERSION})"
                    )
                    print("Check Update function completed")
                    ok_btn = tk.Button(update_win, text="OK", width=8, command=close_update)
                    ok_btn.pack(pady=10)

            else:
                # Handles connection errors, timeouts, DNS failure, 403/404, etc.
                status_label.config(text="❌ Update Check Failed (No Internet or Server Error)")
                print("Update check error: No internet connection or server unreachable.")
                ok_btn = tk.Button(update_win, text="OK", width=8, command=close_update)
                ok_btn.pack(pady=10)
                print("Check Update function failed. No internet connection")

        except ValueError as e:
            # Handles invalid JSON response
            status_label.config(text="❌ Update Check Failed (Invalid Server Response)")
            print(f"Update check error: {e}")
            ok_btn = tk.Button(update_win, text="OK", width=8, command=close_update)
            ok_btn.pack(pady=10)
            print("Check Update function failed. Invalid Server Response")

        self.wait_window(update_win)

    def _close_realtime_log(self):
        log_file = getattr(self, "_realtime_log_file", None)
        if log_file:
            try:
                log_file.flush()
                log_file.close()
            except Exception:
                pass
            self._realtime_log_file = None

    def destroy(self):
        self._stop_host_pulse()
        self._close_realtime_log()
        super().destroy()

    def show_exit_program(self):
        self.destroy()  # closes the main window and exits the program

    # --- Start capturing IDLE Shell output automatically ---
    def start_idle_logging(self):

        timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")

        timestamp_file = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        
        # --- Memory buffer ---
        log_buffer = io.StringIO()

        # --- Real-time log file (per-user AppData\Local\Secuditor Lite\Logs) ---
        local_app_data = os.getenv("LOCALAPPDATA") or os.path.join(
            os.path.expanduser("~"), "AppData", "Local"
        )
        log_dir = os.path.join(local_app_data, "Secuditor Lite", "Logs")

        log_file = None
        log_path = None
        try:
            os.makedirs(log_dir, exist_ok=True)
            candidate_path = os.path.join(log_dir, f"secuditor_{timestamp_file}.log")
            log_file = open(candidate_path, "a", encoding="utf-8", buffering=1)
            log_path = candidate_path
        except OSError:
            log_file = None
            log_path = None

        if log_file:
            try:
                log_file.write("\n")

                separator = "=" * 51

                log_file.write(f"{separator}\n")
                log_file.write(f"{timestamp} - Secuditor Lite Started\n")
                log_file.write(f"{separator}\n")

                log_file.flush()
            except OSError:
                try:
                    log_file.close()
                except OSError:
                    pass
                log_file = None
                log_path = None

        # Save references
        self._idle_log_file = log_buffer
        self._realtime_log_file = log_file
        self._realtime_log_path = log_path

        # Save original streams
        orig_stdout = sys.stdout
        orig_stderr = sys.stderr

        class TeeStream:
            def __init__(self, *streams):
                self.streams = streams
                self.buffer = ""

            def write(self, data):
                self.buffer += data

                while "\n" in self.buffer:
                    line, self.buffer = self.buffer.split("\n", 1)

                    if line.strip():
                        ts = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
                        line = f"{ts} {line}"

                    for s in self.streams:
                        try:
                            s.write(line + "\n")
                            s.flush()
                        except Exception:
                            pass

            def flush(self):
                for s in self.streams:
                    try:
                        s.flush()
                    except Exception:
                        pass

        # Redirect stdout/stderr to both terminal and memory (and disk if writable)
        streams_out = [orig_stdout, log_buffer] + ([log_file] if log_file else [])
        streams_err = [orig_stderr, log_buffer] + ([log_file] if log_file else [])
        sys.stdout = TeeStream(*streams_out)
        sys.stderr = TeeStream(*streams_err)

        # Capture uncaught exceptions
        def log_exceptions(exc_type, exc_value, exc_traceback):
            sys.__excepthook__(exc_type, exc_value, exc_traceback)
            if log_buffer:
                traceback.print_exception(exc_type, exc_value, exc_traceback, file=log_buffer)

        sys.excepthook = log_exceptions
        
        print(f"Secuditor console logging started")
        return log_buffer

    # --- Wrap Tk console insert method ---
    def wrap_console_for_logging(self):

        console = self.console_output
        original_insert = console.insert
        self._wrap_console_enabled = True

        def new_insert(self_console, index, text, *args, **kwargs):

            stripped = text.strip()

            # Only timestamp if logging is enabled
            if getattr(self, "_wrap_console_enabled", False) and stripped and stripped not in (".", "✓"):
                timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S] ")
                text = timestamp + text

            original_insert(index, text, *args, **kwargs)

            # Logging
            if getattr(self, "_wrap_console_enabled", False):

                # Memory buffer
                if hasattr(self, "_idle_log_file") and self._idle_log_file:
                    try:
                        self._idle_log_file.write(text)
                        self._idle_log_file.flush()
                    except Exception:
                        pass

                # Real-time disk log
                if hasattr(self, "_realtime_log_file") and self._realtime_log_file:
                    try:
                        self._realtime_log_file.write(text)
                        self._realtime_log_file.flush()
                    except Exception:
                        pass

        console.insert = types.MethodType(new_insert, console)
        
    def stop_wrap_console_logging(self):
        self._wrap_console_enabled = False

    # --- Resume memory logging for this wrapper only ---
    def resume_wrap_console_logging(self):
        self._wrap_console_enabled = True

    # --- Export logs ---
    def export_logs_clicked(self):
        try:
            if not hasattr(self, "_idle_log_file") or self._idle_log_file is None:
                messagebox.showinfo(
                    "Export Logs",
                    "No logs have been captured yet.",
                    parent=self
                )
                return

            log_content = self._idle_log_file.getvalue()

            if not log_content.strip():
                messagebox.showinfo(
                    "Export Logs",
                    "No logs have been captured yet.",
                    parent=self
                )
                return

            save_path = filedialog.asksaveasfilename(
                title="Save Logs As",
                defaultextension=".txt",
                filetypes=[
                    ("Text Files", "*.txt"),
                    ("All Files", "*.*")
                ],
                parent=self
            )

            if save_path:
                with open(save_path, "w", encoding="utf-8") as f:
                    f.write(log_content)

                messagebox.showinfo(
                    "Export Logs",
                    f"Logs saved successfully to:\n{save_path}",
                    parent=self
                )

        except Exception as e:
            messagebox.showerror(
                "Export Logs Error",
                f"Failed to export logs:\n{e}",
                parent=self
            )
                
    # --- UI builders ---
    def _build_toolbar(self):
        bar = tk.Frame(self, bd=1, relief="flat", bg="#F0F0F0")
        bar.pack(side="top", fill="x")

        def load_icon(filename):
            return tk.PhotoImage(
                file=resource_path(os.path.join("Icons", filename))
            )

        self.speed_icon    = load_icon("speed_icon.png")
        self.network_icon  = load_icon("network_icon.png")
        self.lan_icon      = load_icon("lan_icon.png")
        self.run_icon      = load_icon("run_icon.png")
        self.txt_icon      = load_icon("txt_icon.png")
        self.traf_icon     = load_icon("traf_icon.png")
        self.about_icon    = load_icon("about_icon.png")
        self.home_icon     = load_icon("home_icon.png")
        self.menu_icon     = load_icon("menu_icon.png")
        
        # --- Hover function ---
        def set_btn_bg(btn, color):
            btn['bg'] = color

        # --- Right-aligned Speed Test button ---
        upt_frame = tk.Frame(bar, bg="#F0F0F0")
        upt_frame.pack(side="right", padx=0, pady=5)

        self.upt_btn = tk.Button(
            upt_frame, image=self.speed_icon, command=self.show_download_speed,
            bg="#F0F0F0", bd=2, relief="flat", padx=10, pady=10
        )
        self.upt_btn.pack()
        self.upt_btn.bind("<Enter>", lambda e: set_btn_bg(self.upt_btn, "#D3D3D3"))
        self.upt_btn.bind("<Leave>", lambda e: set_btn_bg(self.upt_btn, "#F0F0F0"))

        upt_label = tk.Label(upt_frame, text="Speed", bg="#F0F0F0", fg="#000", font=("Segoe UI", 8))
        upt_label.pack()

        # --- Right-aligned NAT button ---
        network_frame = tk.Frame(bar, bg="#F0F0F0")
        network_frame.pack(side="right", padx=0, pady=5)

        self.network_btn = tk.Button(
            network_frame, image=self.network_icon, command=self.show_network_status,
            bg="#F0F0F0", bd=2, relief="flat", padx=10, pady=10
        )
        self.network_btn.pack()
        self.network_btn.bind("<Enter>", lambda e: set_btn_bg(self.network_btn, "#D3D3D3"))
        self.network_btn.bind("<Leave>", lambda e: set_btn_bg(self.network_btn, "#F0F0F0"))

        robot_label = tk.Label(network_frame, text="NAT", bg="#F0F0F0", fg="#000", font=("Segoe UI", 8))
        robot_label.pack()

        # --- Right-aligned LAN button ---
        lan_frame = tk.Frame(bar, bg="#F0F0F0")
        lan_frame.pack(side="right", padx=0, pady=5)

        self.lan_btn = tk.Button(
            lan_frame, image=self.lan_icon, command=self.show_lanscan_run,
            bg="#F0F0F0", bd=2, relief="flat", padx=10, pady=10
        )
        self.lan_btn.pack()
        self.lan_btn.bind("<Enter>", lambda e: set_btn_bg(self.lan_btn, "#D3D3D3"))
        self.lan_btn.bind("<Leave>", lambda e: set_btn_bg(self.lan_btn, "#F0F0F0"))

        robot_label = tk.Label(lan_frame, text="LAN", bg="#F0F0F0", fg="#000", font=("Segoe UI", 8))
        robot_label.pack()

        # --- Right-aligned Traffic button ---
        traf_frame = tk.Frame(bar, bg="#F0F0F0")
        traf_frame.pack(side="right", padx=3, pady=5)

        self.traf_btn = tk.Button(
            traf_frame, image=self.traf_icon, command=self.show_traflow_run,
            bg="#F0F0F0", bd=2, relief="flat", padx=10, pady=10
        )
        self.traf_btn.pack()
        self.traf_btn.bind("<Enter>", lambda e: set_btn_bg(self.traf_btn, "#D3D3D3"))
        self.traf_btn.bind("<Leave>", lambda e: set_btn_bg(self.traf_btn, "#F0F0F0"))

        txt_label = tk.Label(traf_frame, text="Traffic", bg="#F0F0F0", fg="#000", font=("Segoe UI", 8))
        txt_label.pack()

        # --- Right-aligned Run button ---
        run_frame = tk.Frame(bar, bg="#F0F0F0")
        run_frame.pack(side="right", padx=3, pady=5)

        self.run_btn = tk.Button(
            run_frame, image=self.run_icon, command=self.ask_run_full_audit,
            bg="#F0F0F0", bd=2, relief="flat", padx=10, pady=10
        )
        self.run_btn.pack()
        self.run_btn.bind("<Enter>", lambda e: set_btn_bg(self.run_btn, "#D3D3D3"))
        self.run_btn.bind("<Leave>", lambda e: set_btn_bg(self.run_btn, "#F0F0F0"))

        run_label = tk.Label(run_frame, text="Audit", bg="#F0F0F0", fg="#000", font=("Segoe UI", 8))
        run_label.pack()

        # --- Menu button ---
        menu_frame = tk.Frame(bar, bg="#F0F0F0")
        menu_frame.pack(side="left", padx=0, pady=5)

        self.menu_button = tk.Menubutton(
            menu_frame, image=self.menu_icon,
            bg="#F0F0F0", activebackground="#D3D3D3",
            bd=2, relief="flat", padx=10, pady=10
        )
        self.menu_button.pack()  # vertical stacking
        self.menu_button.bind("<Enter>", lambda e: set_btn_bg(self.menu_button, "#D3D3D3"))
        self.menu_button.bind("<Leave>", lambda e: set_btn_bg(self.menu_button, "#F0F0F0"))

        menu_label = tk.Label(menu_frame, text="Menu", bg="#F0F0F0", fg="#000", font=("Segoe UI", 8))
        menu_label.pack()

        # --- Home button ---
        home_frame = tk.Frame(bar, bg="#F0F0F0")
        home_frame.pack(side="left", padx=(5, 0), pady=5)

        self.home_btn = tk.Button(
            home_frame, image=self.home_icon,
            command=self.show_welcome_screen,
            bg="#F0F0F0", bd=2, relief="flat", padx=10, pady=10
        )
        self.home_btn.pack()  # vertical stacking
        self.home_btn.bind("<Enter>", lambda e: set_btn_bg(self.home_btn, "#D3D3D3"))
        self.home_btn.bind("<Leave>", lambda e: set_btn_bg(self.home_btn, "#F0F0F0"))

        home_label = tk.Label(home_frame, text="Home", bg="#F0F0F0", fg="#000", font=("Segoe UI", 8))
        home_label.pack()
        
        # --- About button ---
        about_frame = tk.Frame(bar, bg="#F0F0F0")
        about_frame.pack(side="left", padx=5, pady=5)

        self.about_btn = tk.Button(
            about_frame, image=self.about_icon,
            command=self.show_about_version,
            bg="#F0F0F0", bd=2, relief="flat", padx=10, pady=10
        )
        self.about_btn.pack()  # vertical stacking
        self.about_btn.bind("<Enter>", lambda e: set_btn_bg(self.about_btn, "#D3D3D3"))
        self.about_btn.bind("<Leave>", lambda e: set_btn_bg(self.about_btn, "#F0F0F0"))

        about_label = tk.Label(about_frame, text="About", bg="#F0F0F0", fg="#000", font=("Segoe UI", 8))
        about_label.pack()

        # --- Right-aligned TXT button ---
        txt_frame = tk.Frame(bar, bg="#F0F0F0")
        txt_frame.pack(side="left", padx=0, pady=5)

        self.txt_btn = tk.Button(
            txt_frame, image=self.txt_icon, command=self.save_as_txt_clicked,
            bg="#F0F0F0", bd=2, relief="flat", padx=10, pady=10
        )
        self.txt_btn.pack()
        self.txt_btn.bind("<Enter>", lambda e: set_btn_bg(self.txt_btn, "#D3D3D3"))
        self.txt_btn.bind("<Leave>", lambda e: set_btn_bg(self.txt_btn, "#F0F0F0"))

        txt_label = tk.Label(txt_frame, text="Export", bg="#F0F0F0", fg="#000", font=("Segoe UI", 8))
        txt_label.pack()

        # --- Menu items ---
        menu = tk.Menu(self.menu_button, tearoff=0, bg="#F0F0F0", fg="black",
                       activebackground="#D3D3D3", activeforeground="black")
        menu.add_command(label="Security Audit", command=self.ask_run_full_audit)
        menu.add_command(label="Traffic Flow", command=self.show_traflow_run)
        menu.add_command(label="LAN Discovery", command=self.show_lanscan_run)
        menu.add_separator()
        menu.add_command(label="NAT Status", command=self.show_network_status)
        menu.add_command(label="Speed Test", command=self.show_download_speed)
        menu.add_command(label="Check Updates", command=self.check_update_clicked)
        menu.add_separator()
        menu.add_command(label="Export Report", command=self.save_as_txt_clicked)
        menu.add_command(label="Export Logs", command=self.export_logs_clicked)
        menu.add_separator()
        menu.add_command(label="About", command=self.show_about_version)
        menu.add_command(label="Exit", command=self.show_exit_program)
        self.menu_button.config(menu=menu)

        # --- Score Frame (hidden initially) ---
        self.score_frame = tk.Frame(bar, bg="#F0F0F0")
        self.after(0, self.update_score_label)

    # --- Update score label in toolbar ---
    def update_score_label(self):
        score = self.data_cache.get("security_score", None)
        verdict = self.data_cache.get("score_verdict", None)
        hostname = getattr(self, "hostname", "Unknown Host")

        if score is not None and verdict is not None:

            # clear previous labels
            for widget in self.score_frame.winfo_children():
                widget.destroy()

            # Inner frame to hold the labels and center them
            inner_frame = tk.Frame(self.score_frame, bg="#F0F0F0")
            inner_frame.pack(expand=True, anchor="center")

            # Labels
            tk.Label(
                inner_frame,
                text="",
                bg="#F0F0F0",
                fg="black",
                font=("Segoe UI", 14, "bold")
            ).pack(side="left")
            
            tk.Label(
                inner_frame,
                text=f"",
                bg="#F0F0F0",
                fg="black",
                font=("Segoe UI", 14, "bold")
            ).pack(side="left")

            # Pack the main frame if not yet mapped
            if not self.score_frame.winfo_ismapped():
                self.score_frame.pack(side="top", fill="x", pady=2)

    # --- Status bar ---
    def _build_status_bar(self):
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status = tk.Label(
            self,
            textvariable=self.status_var,
            bd=1,
            relief="sunken",
            anchor="w",
            bg="#F0F0F0",
            fg="black"
        )
        status.pack(side="bottom", fill="x")

    # --- Build Layout ---
    def _build_layout(self):
        # --- Helper to lock PanedWindow sashes ---
        def disable_pane_drag(paned):
            def block_sash(event):
                return "break"
            paned.bind("<ButtonPress-1>", block_sash)
            paned.bind("<B1-Motion>", block_sash)  
        
        # PanedWindow fills the remaining space above the status bar
        paned = tk.PanedWindow(self, orient="horizontal", bg="#F0F0F0", bd=1, relief="groove")
        paned.pack(fill="both", expand=True)

        # Left frame (tree + search)
        left = tk.Frame(paned, bg="#F0F0F0", bd=0, relief="flat")
        paned.add(left, minsize=250)

        # --- Treeview style ---
        style = ttk.Style()
        style.theme_use('clam')

        style.configure(
            "Treeview",
            background="#FFFFFF",      # ✅ normal rows
            fieldbackground="#FFFFFF", # ✅ background when no data
            foreground="black",        # ✅ text color
            rowheight=24,
            font=("Segoe UI", 10)
        )

        style.layout("Treeview.Item", [
            ('Treeitem.padding', {
                'sticky': 'nswe',
                'children': [
                    ('Treeitem.indicator', {'side': 'left', 'sticky': ''}),
                    ('Treeitem.image',     {'side': 'left', 'sticky': ''}),
                    ('Treeitem.text',      {'side': 'left', 'sticky': ''}),
                ]
            })
        ])

        # Treeview
        self.tree = ttk.Treeview(left, selectmode="browse", show="tree", style="Treeview")
        self.tree.pack(fill="both", expand=True, padx=6, pady=6)

        # Right frame
        right = tk.Frame(paned, bg="#F0F0F0", bd=0, relief="flat")  # bd=4 makes it thicker
        paned.add(right)

        right_paned = tk.PanedWindow(right, orient="vertical", bg="#F0F0F0")
        right_paned.pack(fill="both", expand=True)

        disable_pane_drag(paned)

        # Report area
        report_frame = tk.Frame(right_paned, bg="#F0F0F0")
        report_header = tk.Frame(report_frame, bg="#F0F0F0")
        report_header.pack(fill="x", padx=8, pady=(4, 0))
        tk.Label(report_header, text="Report", bg="#F0F0F0", fg="black", font=("Segoe UI", 10, "bold")).pack(side="left")

        # Report search bar
        self._report_search_matches = []
        self._report_search_index = -1
        self.report_search_var = tk.StringVar()

        search_controls = tk.Frame(report_header, bg="#F0F0F0")
        search_controls.pack(side="right")
        tk.Label(search_controls, text="Search:", bg="#F0F0F0", fg="#333333", font=("Segoe UI", 9)).pack(side="left", padx=(0, 4))
        self.report_search_entry = tk.Entry(search_controls, textvariable=self.report_search_var, width=24, font=("Segoe UI", 9))
        self.report_search_entry.pack(side="left")
        self.report_search_count = tk.Label(search_controls, text="", bg="#F0F0F0", fg="#555555", font=("Segoe UI", 9), width=7, anchor="e")
        self.report_search_count.pack(side="left", padx=(4, 2))
        self.report_search_prev_btn = tk.Button(search_controls, text="▲", command=self._report_search_prev, font=("Segoe UI", 8), padx=5, pady=0, relief="groove")
        self.report_search_prev_btn.pack(side="left", padx=(2, 1))
        self.report_search_next_btn = tk.Button(search_controls, text="▼", command=self._report_search_next, font=("Segoe UI", 8), padx=5, pady=0, relief="groove")
        self.report_search_next_btn.pack(side="left", padx=(1, 1))
        self.report_search_clear_btn = tk.Button(search_controls, text="✕", command=self._clear_report_search, font=("Segoe UI", 8), padx=5, pady=0, relief="groove")
        self.report_search_clear_btn.pack(side="left", padx=(1, 0))

        self.report_output = scrolledtext.ScrolledText(report_frame, wrap=tk.WORD, font=("Consolas", 10), fg="black", bg="#FFFFFF")
        self.report_output.pack(fill="both", expand=True, padx=8, pady=(6,4))
        self.report_output.tag_config("search_match", background="#FFF59D", foreground="black")
        self.report_output.tag_config("search_current", background="#FFA726", foreground="black")
        self.report_output.config(state="disabled")  # Make read-only
        right_paned.add(report_frame, minsize=500)

        self.report_search_var.trace_add("write", lambda *_: self._refresh_report_search(scroll=True))
        self.report_search_entry.bind("<Return>", self._report_search_next)
        self.report_search_entry.bind("<Shift-Return>", self._report_search_prev)
        self.report_search_entry.bind("<Escape>", self._clear_report_search)
        self.bind("<Control-f>", self._focus_report_search)
        self.bind("<Control-F>", self._focus_report_search)

        # --- Clickable report links ---
        jump_links = [
            ("jump_gateway", "Gateway_Discovery"),
            ("jump_suspicious", "Scan_Suspicious_Activity"),
            ("jump_proxy", "Proxy_Configuration"),
            ("jump_ssl", "SSL/TLS_Interception"),
            ("jump_domain", "Domain_Settings"),
            ("jump_password", "Password_Policy"),
        ]
        for tag_name, target_key in jump_links:
            self.report_output.tag_config(tag_name, foreground="black", underline=True)
            self.report_output.tag_bind(
                tag_name, "<Button-1>", lambda e, k=target_key: self._jump_to_node(k)
            )
            self.report_output.tag_bind(
                tag_name, "<Enter>", lambda e: self.report_output.config(cursor="hand2")
            )
            self.report_output.tag_bind(
                tag_name, "<Leave>", lambda e: self.report_output.config(cursor="")
            )

        def _select_all_report_text(event=None):
            self.report_output.focus_set()
            self.report_output.tag_add(tk.SEL, "1.0", "end-1c")
            return "break"

        # --- Add right-click context menu to report ---
        self.report_menu = tk.Menu(self.report_output, tearoff=0)
        self.report_menu.add_command(label="Copy", command=lambda: self._copy_report_text())
        self.report_menu.add_command(label="Select All", command=_select_all_report_text)

        def do_report_popup(event):
            self.report_menu.tk_popup(event.x_root, event.y_root)
            self.report_menu.grab_release()

        self.report_output.bind("<Button-3>", do_report_popup)  # Right-click
        self.report_output.bind("<Control-Button-1>", do_report_popup)  # macOS Ctrl+Click
        self.report_output.bind("<Control-a>", _select_all_report_text)
        self.report_output.bind("<Control-A>", _select_all_report_text)

        # Function to copy selected text
        def _copy_report_text():
            try:
                selected_text = self.report_output.get(tk.SEL_FIRST, tk.SEL_LAST)
                self.report_output.clipboard_clear()
                self.report_output.clipboard_append(selected_text)
            except tk.TclError:
                pass  # Nothing selected

        self._copy_report_text = _copy_report_text  # save method

        # Console/log area
        log_frame = tk.Frame(right_paned, bg="#F0F0F0")
        tk.Label(log_frame, text="Console / Logs", bg="#F0F0F0", fg="black", font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=8)
        self.console_output = scrolledtext.ScrolledText(log_frame, wrap=tk.NONE, height=12, font=("Segoe UI", 10), fg="black", bg="#FFFFFF")
        self.console_output.pack(fill="both", expand=True, padx=8, pady=(4,8))
        self.console_output.config(state="disabled")  # Make read-only
        right_paned.add(log_frame, minsize=150)
        
        self.wrap_console_for_logging()

        # Bind tree actions
        self.tree.bind("<ButtonRelease-1>", self._on_tree_single_click)
        self.tree.bind("<Double-1>", self._on_tree_double_click)
        self.tree.bind("<Return>", lambda e: self._run_or_show_selection())

    def _focus_report_search(self, event=None):
        if hasattr(self, "report_search_entry") and self.report_search_entry.winfo_exists():
            if str(self.report_search_entry.cget("state")) == "disabled":
                return "break"
            self.report_search_entry.focus_set()
            self.report_search_entry.selection_range(0, tk.END)
        return "break"

    def _clear_report_search(self, event=None):
        if hasattr(self, "report_search_var"):
            self.report_search_var.set("")
        if hasattr(self, "report_output") and self.report_output.winfo_exists():
            self.report_output.tag_remove("search_match", "1.0", tk.END)
            self.report_output.tag_remove("search_current", "1.0", tk.END)
        self._report_search_matches = []
        self._report_search_index = -1
        if hasattr(self, "report_search_count"):
            self.report_search_count.config(text="")
        return "break"

    def _highlight_current_report_match(self, scroll=True):
        if not hasattr(self, "report_output") or not self.report_output.winfo_exists():
            return
        self.report_output.tag_remove("search_current", "1.0", tk.END)
        if not self._report_search_matches or not (0 <= self._report_search_index < len(self._report_search_matches)):
            return
        start_idx, end_idx = self._report_search_matches[self._report_search_index]
        self.report_output.tag_add("search_current", start_idx, end_idx)
        self.report_output.tag_raise("search_current")
        if hasattr(self, "report_search_count"):
            self.report_search_count.config(text=f"{self._report_search_index + 1} / {len(self._report_search_matches)}")
        if scroll:
            self.report_output.see(start_idx)

    def _refresh_report_search(self, scroll=False):
        if not hasattr(self, "report_output") or not self.report_output.winfo_exists():
            return
        self.report_output.tag_remove("search_match", "1.0", tk.END)
        self.report_output.tag_remove("search_current", "1.0", tk.END)
        self._report_search_matches = []
        self._report_search_index = -1

        query = self.report_search_var.get() if hasattr(self, "report_search_var") else ""
        if not query:
            if hasattr(self, "report_search_count"):
                self.report_search_count.config(text="")
            return

        start_idx = "1.0"
        count_var = tk.IntVar()
        while True:
            pos = self.report_output.search(query, start_idx, stopindex=tk.END, nocase=True, count=count_var)
            if not pos:
                break
            length = count_var.get()
            if length <= 0:
                break
            end_idx = f"{pos}+{length}c"
            self._report_search_matches.append((pos, end_idx))
            self.report_output.tag_add("search_match", pos, end_idx)
            start_idx = end_idx

        if self._report_search_matches:
            self.report_output.tag_raise("search_match")
            self._report_search_index = 0
            self._highlight_current_report_match(scroll=scroll)
        elif hasattr(self, "report_search_count"):
            self.report_search_count.config(text="0 / 0")

    def _report_search_next(self, event=None):
        if not hasattr(self, "report_search_var") or not self.report_search_var.get():
            return "break"
        if not self._report_search_matches:
            self._refresh_report_search(scroll=True)
            return "break"
        self._report_search_index = (self._report_search_index + 1) % len(self._report_search_matches)
        self._highlight_current_report_match(scroll=True)
        return "break"

    def _report_search_prev(self, event=None):
        if not hasattr(self, "report_search_var") or not self.report_search_var.get():
            return "break"
        if not self._report_search_matches:
            self._refresh_report_search(scroll=True)
            return "break"
        self._report_search_index = (self._report_search_index - 1) % len(self._report_search_matches)
        self._highlight_current_report_match(scroll=True)
        return "break"

    def _jump_to_node(self, key):
        iid = self.tree_keys_to_iid.get(key)
        if not iid:
            return

        def do_jump():
            parent = self.tree.parent(iid)
            while parent:
                self.tree.item(parent, open=True)
                parent = self.tree.parent(parent)

            self.tree.see(iid)
            self.tree.focus_set()
            self.tree.selection_set(iid)
            self.tree.focus(iid)

            class Event:
                pass

            event = Event()
            bbox = self.tree.bbox(iid)
            event.x = 1
            event.y = bbox[1] if bbox else 0
            self._on_tree_single_click(event)

        self.tree.after(10, do_jump)

    # --- Right-click context menu ---
    def _bind_tree_context_menu(self):
        for attr in ("subnode_menu", "root_menu"):
            old_menu = getattr(self, attr, None)
            if old_menu is not None:
                try:
                    old_menu.destroy()
                except tk.TclError:
                    pass

        # Menu for sub-nodes
        self.subnode_menu = tk.Menu(self, tearoff=0)
        self.subnode_menu.add_command(label="Run Check")  # command set dynamically below
        self.subnode_menu.add_command(label="Export Node", command=self._export_node_txt)

        # Menu for root nodes
        self.root_menu = tk.Menu(self, tearoff=0)
        self.root_menu.add_command(label="Expand", command=lambda: self._expand_collapse_root(True))
        self.root_menu.add_command(label="Collapse", command=lambda: self._expand_collapse_root(False))

        def do_popup(event):
            iid = self.tree.identify_row(event.y)
            if iid:
                self.tree.selection_set(iid)
                self.tree.focus(iid)

                # Disable right-click for hostname node
                hostname = getattr(self, "hostname", "Unknown Host")
                if self.tree.item(iid, "text") == hostname:
                    return

                if self.tree.parent(iid) == '':
                    # Top-level node → root menu
                    try:
                        self.root_menu.tk_popup(event.x_root, event.y_root)
                    finally:
                        self.root_menu.grab_release()
                else:
                    # Sub-node → sub-node menu
                    key = self.tree_items.get(iid)  # resolve the key dynamically
                    if key:
                        # Update menu command dynamically with correct key
                        self.subnode_menu.entryconfig(0, command=lambda k=key: self.run_single_check(k))
                        try:
                            self.subnode_menu.tk_popup(event.x_root, event.y_root)
                        finally:
                            self.subnode_menu.grab_release()

        # Bind right-click
        self.tree.bind("<Button-3>", do_popup)
        self.tree.bind("<Control-Button-1>", do_popup)  # macOS Ctrl+Click
        
    def _expand_collapse_root(self, expand=True):
        # Use the node that was right-clicked, not just selection
        selected = self.tree.selection()
        if not selected:
            return
        node_id = selected[0]
        self._expand_collapse_subtree(node_id, expand)

    def _expand_collapse_subtree(self, node_id, expand=True):
        # Only try to open if node has children
        children = self.tree.get_children(node_id)
        if not children:
            return
        self.tree.item(node_id, open=expand)
        for child in children:
            self._expand_collapse_subtree(child, expand)

    def _load_tree_icons(self):
        self.tree_icons = {
            "windows": tk.PhotoImage(file=resource_path("Icons/x_windows.png")),
            "computer": tk.PhotoImage(file=resource_path("icons/x_computer.png")),
            "network": tk.PhotoImage(file=resource_path("icons/x_network.png")),
            "security": tk.PhotoImage(file=resource_path("icons/x_security.png")),
            "detection": tk.PhotoImage(file=resource_path("icons/x_search.png")),
            "events": tk.PhotoImage(file=resource_path("icons/x_warning.png")),
        }
    
    def _populate_tree(self):
        # Category roots with example data
        self.tree_keys_to_iid = {}
        self.hostname = self.get_hostname_gui()

        hostname_node = self.tree.insert(
            '',
            'end',
            text=self.hostname,
            image=self.tree_icons["computer"],
            open=True
        )

        nodes = {}

        nodes['system'] = self.tree.insert(
            '',
            'end',
            text=' System',
            image=self.tree_icons["windows"],
            values=('system_info',),
            open=True
        )

        nodes['network'] = self.tree.insert(
            '',
            'end',
            text=' Network',
            image=self.tree_icons["network"],
            values=('network_info',),
            open=True
        )

        nodes['security'] = self.tree.insert(
            '',
            'end',
            text=' Security',
            image=self.tree_icons["security"],
            values=('security_info',),
            open=True
        )

        nodes['detection'] = self.tree.insert(
            '',
            'end',
            text=' Detection',
            image=self.tree_icons["detection"],
            values=('detection_info',),
            open=True
        )

        nodes['events'] = self.tree.insert(
            '',
            'end',
            text=' Events',
            image=self.tree_icons["events"],
            values=('events_info',),
            open=True
        )

        # Function registry
        self.checks = [
            ("System_Settings", "System Settings", 'system', lambda: SystemSettings().get_formatted_system_settings()),
            ("Hardware_Components", "Hardware Components", 'system', lambda: HardwareReport().get_hardware_report()),
            ("Installed_Applications", "Installed Applications", 'system', lambda: InstalledApps().get_installed_apps()),
            ("Network_Settings", "Network Settings", 'network', lambda: NetworkSettings().get_network_settings()),
            ("Gateway_Discovery", "Gateway Discovery", 'network', lambda: GatewayDiscovery().detect_gateway_device()),
            ("Detect_Shared_Folders", "Shares Mapping", 'network', lambda: SharedFolders().get_shared_folders()),
            ("Endpoint_Security_Settings", "Endpoint Security", 'security', lambda: SecuritySettings().show_security_settings()),
            ("Remote_Access_Settings", "Remote Access", 'security', lambda: RemoteAccessSettings().show_remote_access_settings()),
            ("Domain_Settings", "Domain Settings", 'security', lambda: DomainSettings().show_domain_settings()),
            ("Password_Policy", "Password Policy", 'security', lambda: PasswordPolicy().show_password_policy_nonadmin()),
            ("Credential_Integrity", "Credential Integrity", 'security', lambda: CredentialIntegrity().run_credential_integrity_checks()),
            ("OS_Version_Status", "Operating System", 'security', lambda: WindowsUpdates().display_windows_update_info()),
            ("Security_Events", "Security Events", 'events', lambda: WindowsEvents().get_security_events()),
            ("Windows_Events", "Windows Events", 'events', lambda: WindowsEvents().get_system_events()),
            ("Proxy_Configuration", "Proxy Configuration", 'security', lambda: SuspiciousProxy().show_suspicious_proxy()),
            ("SSL/TLS_Interception", "SSL/TLS Interception", 'security', lambda: SSLInspection().show_ssl_inspection()),
            ("Scan_Sensitive_Paths", "Scan Sensitive Paths", 'detection', lambda: SensitivePaths().show_sensitive_paths()),
            ("Scan_Suspicious_Activity", "Scan Suspicious Activity", 'detection', lambda: SuspiciousProcesses().show_suspicious_processes()),
        ]

        # Build tree items per category
        self.tree_items = {}
        for key, title, cat, func in self.checks:
            parent = nodes[cat]
            iid = self.tree.insert(parent, 'end', text=title, values=(key,))
            self.tree_items[iid] = key
            self.tree_keys_to_iid[key] = iid
            
        for child in self.tree.get_children():
            self.tree.item(child, open=False)

    # ---------- Actions ----------
    # --- Stop current run ---
    def _reset_single_mode(self):
        secuditor_modules.set_scan_mode(single=False)

    def stop_current_run(self):
        """Stop the current running single-check task immediately and invalidate stale callbacks."""
        self._current_single_run_id = getattr(self, "_current_single_run_id", 0) + 1
        self._active_single_key = None
        self._dots_running = False
        self._reset_single_mode()

        timeout_job = getattr(self, "_single_timeout_job", None)
        if timeout_job is not None:
            try:
                self.after_cancel(timeout_job)
            except tk.TclError:
                pass
            self._single_timeout_job = None

        stop_ev = getattr(self, "_current_single_stop", None)
        if stop_ev is not None:
            stop_ev.set()

        self.stop_wrap_console_logging()

    # --- Check Internet Connection ---
    def check_and_store_internet(self):
        status = self.net_status.check_internet_connection()
        self.internet_status = status["Connected"]
        print(f"Internet connected: {self.internet_status}")

    # --- Ask Run Full Audit ---
    def ask_run_full_audit(self):
        
        prompt = tk.Toplevel(self)
        prompt.withdraw()

        set_window_icon(prompt)
        
        prompt.title("Security Audit")
        prompt.resizable(False, False)
        prompt.grab_set()
        prompt.transient(self)

        win_w, win_h = 320, 150
        self.update_idletasks()
        main_x = self.winfo_x()
        main_y = self.winfo_y()
        main_w = self.winfo_width()
        main_h = self.winfo_height()
        pos_x = main_x + (main_w - win_w) // 2
        pos_y = main_y + (main_h - win_h) // 2
        prompt.geometry(f"{win_w}x{win_h}+{pos_x}+{pos_y}")

        msg_text = "Do you want to start the security audit now?\nIt may take a few minutes."
        tk.Label(prompt, text=msg_text, font=("Segoe UI", 10), justify="center", wraplength=300).pack(pady=(16, 8))

        # --- Buttons ---
        def yes_action():
            prompt.destroy()
            self.run_all_clicked()

        def no_action():
            prompt.destroy()

        btn_frame = tk.Frame(prompt)
        btn_frame.pack(pady=8)
        tk.Button(btn_frame, text="Yes", width=6, command=yes_action).pack(side="left", padx=10)
        tk.Button(btn_frame, text="No", width=6, command=no_action).pack(side="left", padx=10)

        prompt.deiconify()
        self.wait_window(prompt)

    # --- Keyboard settings ---
    def _bind_keyboard_navigation(self):
        self.tree.bind("<Return>", lambda e: self._run_or_show_selection())
        self.tree.bind("<Up>", lambda e: self._after_move_selection())
        self.tree.bind("<Down>", lambda e: self._after_move_selection())

    def _after_move_selection(self):
        # Stop any active single check immediately when navigating away, then render new selection
        self.stop_current_run()
        self.after(50, self._on_tree_single_click)

    # --- Enter / run or show selection ---
    def _run_or_show_selection(self):
        selected_item = self.tree.selection()
        if not selected_item:
            return

        iid = selected_item[0]

        # --- Cancel Enter on hostname node ---
        if self.tree.parent(iid) == "" and self.tree.item(iid, "text") == getattr(self, "hostname", "Unknown Host"):
            self.stop_current_run()
            return

        key = self.tree_items.get(iid)

        # --- Root node → show children ---
        if self.tree.parent(iid) == "":
            self.stop_current_run()
            self.report_output.config(state="normal")
            self.console_output.config(state="normal")
            self.report_output.delete("1.0", tk.END)
            self.console_output.delete("1.0", tk.END)
            children = self.tree.get_children(iid)
            if children:
                title = self.tree.item(iid, "text")
                self.report_output.insert(tk.END, f"{title} contains:\n\n")
                for child in children:
                    self.report_output.insert(tk.END, f"    • {self.tree.item(child, 'text')}\n")

            # Scroll to top
            self.report_output.after(50, self.scroll_to_top)

            self.report_output.config(state="disabled")
            self.console_output.config(state="disabled")
            self._refresh_report_search(scroll=False)
            return

        # --- Sub-node → cached or run ---
        if key:
            if key in self.single_node_cache or key in self.data_cache:
                self.stop_current_run()
                self.report_output.config(state="normal")
                self.console_output.config(state="normal")
                self.report_output.delete("1.0", tk.END)
                self.console_output.delete("1.0", tk.END)
                # Show cached result
                self.show_cached_result(key)
                self.report_output.config(state="disabled")
                self.console_output.config(state="disabled")
                self._refresh_report_search(scroll=False)
                # Scroll to top after cached inserts
                self.report_output.after(50, self.scroll_to_top)
            else:
                # Must run on the main thread (run_single_check manages its own worker thread)
                self.run_single_check(key)
        else:
            self.stop_current_run()

    # --- Scroll to top safely after all text is inserted ---
    def scroll_to_top(self):
        self.report_output.config(state="normal")
        self.console_output.config(state="normal")
        self.report_output.see("1.0")
        self.console_output.see("1.0")
        self.report_output.config(state="disabled")
        self.console_output.config(state="disabled")


    # --- Format single check output ---
    def format_single_check(self, title, data, indent=0):
        spacing = " " * indent
        output = f"{spacing}{title}:\n"

        if isinstance(data, dict):
            for k, v in data.items():
                output += self.format_single_check(k, v, indent + 4)
        elif isinstance(data, list):
            if not data:
                output += f"{spacing}    (None)\n"
            else:
                for item in data:
                    output += f"{spacing}    - {item}\n"
        else:
            output += f"{spacing}    {data}\n"

        return output

    # --- Helper to get full tree path ---
    def _get_tree_node_path(self, node_id):
        path = []
        while node_id:
            text = self.tree.item(node_id, "text")
            path.insert(0, text)  # prepend so root comes first
            node_id = self.tree.parent(node_id)
        return " → ".join(path)

    # --- Single-click handler (integrated with status bar) ---
    def _on_tree_single_click(self, event=None):
        # --- Update status bar with full path ---
        item = self.tree.focus()
        if item:
            self.status_var.set(self._get_tree_node_path(item))
        else:
            self.status_var.set("Ready")

        selected_item = self.tree.selection()
        selected_key = self.tree_items.get(selected_item[0]) if selected_item else None

        # Stop any active single check immediately when navigating away from its node
        if getattr(self, "_active_single_key", None) is not None and selected_key != self._active_single_key:
            self.stop_current_run()
        elif not selected_item and getattr(self, "_active_single_key", None) is not None:
            self.stop_current_run()

        self._stop_host_pulse()
        self.report_output.config(state="normal")
        self.console_output.config(state="normal")
        self.report_output.delete("1.0", tk.END)

        if not selected_item:
            self.report_output.config(state="disabled")
            self.console_output.config(state="disabled")
            self._refresh_report_search(scroll=False)
            return

        iid = selected_item[0]
        node_text = self.tree.item(iid, "text")
        hostname = getattr(self, "hostname", "Unknown Host")

        key = self.tree_items.get(iid)

        # Clear logs only if no cache exists
        if not key or (key not in getattr(self, "single_node_cache", {}) and key not in getattr(self, "data_cache", {})):
            self.console_output.config(state="normal")
            self.console_output.delete("1.0", tk.END)
            self.console_output.config(state="disabled")

        # --- Hostname node special handling ---
        if node_text == hostname:
            final_text = self.generate_scorebreakdown()
            last_run = self.data_cache.get("report_timestamp")
            if isinstance(last_run, datetime):
                timestamp = last_run.strftime("[%Y-%m-%d %H:%M:%S] ")
            elif last_run:
                timestamp = f"[{last_run}] "
            else:
                timestamp = "[Unknown time] "

            if final_text:
                self.report_output.config(state="normal")
                self.report_output.delete("1.0", tk.END)

                # Configure tags
                self.report_output.tag_config("bold", font=("Consolas", 10, "bold"))
                self.report_output.tag_config("fail_red", foreground="red", font=("Consolas", 10, "bold"))
                self.report_output.tag_config("fail_bg", background="", font=("Consolas", 10))
                self.report_output.tag_config("detected_purple", foreground="#A855F7", font=("Consolas", 10))


                # Console header
                self.console_output.config(state="normal")
                self.console_output.delete("1.0", tk.END)
                self.console_output.insert("1.0", f"{timestamp} Summary Report for {self.FQDN}\n")
                self.console_output.see("1.0")

                # Insert lines with tags
                clickable_checks = {
                    "Suspicious Activity": "jump_suspicious",
                    "Proxy Configuration": "jump_proxy",
                    "SSL/TLS Interception": "jump_ssl",
                    "Password Policy": "jump_password",
                    "Domain Settings": "jump_domain",
                    "Network Gateway": "jump_gateway"
                }

                # Loop over each line in the report
                for i, line in enumerate(final_text.splitlines(), start=1):
                    self.report_output.insert(f"{i}.0", line + "\n")

                    # Bold headers
                    if "Security Elements" in line and "Settings" in line:
                        self.report_output.tag_add("bold", f"{i}.0", f"{i}.end")

                    # Highlight Fail text
                    if "Fail" in line:
                        self.report_output.tag_add("fail_bg", f"{i}.0", f"{i}.end")
                        start_idx = f"{i}.0"
                        while True:
                            pos = self.report_output.search("Fail", start_idx, stopindex=f"{i}.end")
                            if not pos:
                                break
                            end_pos = f"{pos}+4c"
                            self.report_output.tag_add("fail_red", pos, end_pos)
                            start_idx = end_pos

                    # Highlight Detected text in purple
                    if "Detected" in line:
                        start_idx = f"{i}.0"
                        while True:
                            pos = self.report_output.search("Detected", start_idx, stopindex=f"{i}.end")
                            if not pos:
                                break

                            end_pos = f"{pos}+{len('Detected')}c"
                            self.report_output.tag_add("detected_purple", pos, end_pos)
                            start_idx = end_pos

                    # --- Add clickable links for failed checks dynamically ---
                    for display_name, tag_name in clickable_checks.items():
                        if display_name in line:
                            start_idx = f"{i}.0+{line.find(display_name)}c"
                            end_idx = f"{start_idx}+{len(display_name)}c"
                            self.report_output.tag_add(tag_name, start_idx, end_idx)
                    
            else:
                # If no report, show welcome banner (ASCII) + live Host Pulse
                self._render_welcome_banner(include_live_pulse=True)

        else:
            # --- Other nodes ---
            children = self.tree.get_children(iid)
            if children:
                self.report_output.insert(tk.END, f"{node_text} contains:\n\n")
                for child in children:
                    child_text = self.tree.item(child, "text")
                    self.report_output.insert(tk.END, f"    • {child_text}\n")
            else:
                if key:
                    if key in self.single_node_cache or key in self.data_cache:
                        self.show_cached_result(key)
                    else:
                        self.report_output.insert(tk.END, 'Press "Enter" for More Data\n', "moredata")
                        self.report_output.tag_configure("moredata", foreground="black", font=("TkDefaultFont", 11, "bold"))
                else:
                    self.report_output.insert(tk.END, "(No sub-items)\n")

        # Scroll to top
        self.report_output.after(50, self.scroll_to_top)

        # Disable writing
        self.report_output.config(state="disabled")
        self.console_output.config(state="disabled")
        self._refresh_report_search(scroll=False)

    # --- Double-click handler ---
    def _on_tree_double_click(self, event):
        # Just call the single-click handler
        self._on_tree_single_click(event)

    # --- Live Host Pulse helpers (welcome view via psutil) ---
    @staticmethod
    def _render_pulse_bar(percent, width=20):
        clamped = max(0.0, min(100.0, float(percent)))
        filled = int(round((clamped / 100.0) * width))
        return "[" + ("█" * filled) + ("░" * (width - filled)) + "]"

    @staticmethod
    def _resolve_system_version():
        """Return the friendly Windows version/edition matching the System Settings node."""
        try:
            edition = SystemSettings()._get_windows_edition()
            if edition and edition != "Unknown":
                return edition
        except Exception:
            pass
        return "Windows" if sys.platform == "win32" else sys.platform

    def _format_host_pulse(self):
        """Collect current OS version, CPU, memory, and disk telemetry via psutil."""
        os_version = getattr(self, "_welcome_os_version", None)
        if not os_version:
            os_version = self._resolve_system_version()
            self._welcome_os_version = os_version

        try:
            cpu_pct = psutil.cpu_percent(interval=None)
        except Exception:
            cpu_pct = 0.0

        try:
            vm = psutil.virtual_memory()
            mem_pct = vm.percent
            mem_used_gb = vm.used / (1024 ** 3)
            mem_total_gb = vm.total / (1024 ** 3)
            mem_detail = f"({mem_used_gb:.1f} / {mem_total_gb:.1f} GB)"
        except Exception:
            mem_pct = 0.0
            mem_detail = ""

        sys_drive = (os.environ.get("SystemDrive") or "C:").rstrip("\\/")
        disk_label = f"Disk Usage ({sys_drive})"
        try:
            du = psutil.disk_usage(sys_drive + "\\")
            disk_pct = du.percent
            disk_used_gb = du.used / (1024 ** 3)
            disk_total_gb = du.total / (1024 ** 3)
            disk_detail = f"({disk_used_gb:.1f} / {disk_total_gb:.1f} GB)"
        except Exception:
            disk_pct = 0.0
            disk_detail = ""

        endpoint_lines = getattr(self, "_endpoint_status_lines", ["Checking endpoint status..."])
        ssl_lines = getattr(self, "_welcome_ssl_lines", ["  Checking SSL/TLS interception..."])
        lines = [
            " Endpoint Security Status:",
            " " + "–" * 70,
            *(f"   {line}" for line in endpoint_lines),
            "",
            "",
            f" Operating System: {os_version}",
            " " + "–" * 70,
            f"   {'CPU Usage':<18}{self._render_pulse_bar(cpu_pct)} {cpu_pct:5.1f}%",
            f"   {'Memory Usage':<18}{self._render_pulse_bar(mem_pct)} {mem_pct:5.1f}%  {mem_detail}".rstrip(),
            f"   {disk_label:<18}{self._render_pulse_bar(disk_pct)} {disk_pct:5.1f}%  {disk_detail}".rstrip(),
            "",
            "",
            " SSL/TLS Interception:",
            " " + "–" * 70,
            *(f" {line}" if not line.startswith(" ") else line for line in ssl_lines),
        ]
        return "\n".join(lines)

    def _apply_host_pulse_highlights(self):
        """Color status keywords and >=90% percentages inside the welcome block."""
        ranges = self.report_output.tag_ranges("host_pulse")
        if not ranges:
            return
        self.report_output.tag_remove("pulse_active", "1.0", tk.END)
        self.report_output.tag_remove("pulse_inactive", "1.0", tk.END)
        self.report_output.tag_remove("pulse_high", "1.0", tk.END)
        self.report_output.tag_remove("pulse_mitm", "1.0", tk.END)
        for prefix, word, tag in (
            ("is: ", "Active", "pulse_active"),
            ("is: ", "Inactive", "pulse_inactive"),
            ("", "Untrusted / MITM", "pulse_mitm"),
        ):
            token = prefix + word
            start = ranges[0]
            while True:
                pos = self.report_output.search(token, start, stopindex=ranges[1])
                if not pos:
                    break
                word_start = f"{pos}+{len(prefix)}c"
                word_end = f"{word_start}+{len(word)}c"
                self.report_output.tag_add(tag, word_start, word_end)
                start = word_end

        start_line, start_col = (int(x) for x in str(self.report_output.index(ranges[0])).split("."))
        block_text = self.report_output.get(ranges[0], ranges[1])
        resource_re = re.compile(
            r"^\s*(?:CPU Usage|Memory Usage|Disk Usage \([^)]+\))\s+\[[█░]+\]\s+((\d+(?:\.\d+)?)%)"
        )
        for idx, line_text in enumerate(block_text.splitlines()):
            match = resource_re.match(line_text)
            if match and float(match.group(2)) >= 90.0:
                line_num = start_line + idx
                col_offset = start_col if idx == 0 else 0
                pct_start = f"{line_num}.{col_offset + match.start(1)}"
                pct_end = f"{line_num}.{col_offset + match.end(1)}"
                self.report_output.tag_add("pulse_high", pct_start, pct_end)

        self.report_output.tag_raise("pulse_active")
        self.report_output.tag_raise("pulse_inactive")
        self.report_output.tag_raise("pulse_high")
        self.report_output.tag_raise("pulse_mitm")
        self.report_output.tag_raise(tk.SEL)

    def _update_host_pulse_text(self):
        """Replace the tagged 'host_pulse' text range in place without disturbing selection/scroll."""
        try:
            if not self.winfo_exists() or not self.report_output.winfo_exists():
                return False
            ranges = self.report_output.tag_ranges("host_pulse")
            if not ranges:
                return False

            sel = self.report_output.tag_ranges(tk.SEL)
            if sel and (
                self.report_output.compare(sel[1], ">", ranges[0])
                and self.report_output.compare(sel[0], "<", ranges[1])
            ):
                return True

            top_y = self.report_output.yview()[0]
            prev_state = str(self.report_output.cget("state"))
            start_idx = self.report_output.index(ranges[0])
            self.report_output.config(state="normal")
            self.report_output.delete(ranges[0], ranges[1])
            self.report_output.insert(start_idx, self._format_host_pulse(), ("normal_ascii", "host_pulse"))
            self._apply_host_pulse_highlights()
            self.report_output.config(state=prev_state)
            self.report_output.yview_moveto(top_y)

            if getattr(self, "report_search_var", None) and self.report_search_var.get().strip():
                self._refresh_report_search(scroll=False)
            return True
        except tk.TclError:
            return False

    _WELCOME_STATUS_INTERVAL_MS = 15000
    _WELCOME_SSL_INTERVAL_SEC = 60.0

    def _schedule_welcome_probe(self, delay_ms=_WELCOME_STATUS_INTERVAL_MS):
        """Schedule the next guarded welcome status refresh (AV/FW 15s, SSL/TLS 60s)."""
        job = getattr(self, "_welcome_probe_job", None)
        if job is not None:
            try:
                self.after_cancel(job)
            except tk.TclError:
                pass
            self._welcome_probe_job = None
        try:
            if (
                self.winfo_exists()
                and hasattr(self, "report_output")
                and self.report_output.winfo_exists()
                and self.report_output.tag_ranges("host_pulse")
            ):
                self._welcome_probe_job = self.after(delay_ms, self._on_welcome_probe_timer)
        except tk.TclError:
            pass

    def _on_welcome_probe_timer(self):
        """Timer callback: refresh AV/FW every 15s and SSL/TLS every 60s while idle on welcome."""
        self._welcome_probe_job = None
        try:
            if (
                not self.winfo_exists()
                or not hasattr(self, "report_output")
                or not self.report_output.winfo_exists()
                or not self.report_output.tag_ranges("host_pulse")
            ):
                return
        except tk.TclError:
            return

        if secuditor_modules.run_all_clicked or secuditor_modules.single_check:
            self._schedule_welcome_probe(self._WELCOME_STATUS_INTERVAL_MS)
            return

        self._start_welcome_probe()

    def _finish_welcome_probe(self, endpoint_lines, ssl_lines=None, ssl_checked_at=None):
        """Apply refreshed AV/FW (and optional SSL) status on the main thread and schedule next 15s cycle."""
        self._welcome_probe_busy = False
        self._endpoint_status_lines = list(endpoint_lines)
        if ssl_lines is not None:
            self._welcome_ssl_lines = list(ssl_lines)
            if ssl_checked_at is not None:
                self._welcome_ssl_last_ts = ssl_checked_at
        if self._update_host_pulse_text():
            self._schedule_welcome_probe(self._WELCOME_STATUS_INTERVAL_MS)

    def _welcome_probe_worker(self, run_ssl=True):
        """Background worker collecting AV/FW (15s) and SSL/TLS (60s) without touching audit caches."""
        try:
            quick = SecuritySettings().get_quick_endpoint_status()
            ep_lines = [quick["av_line"], quick["fw_line"]]
        except Exception:
            ep_lines = ["Antivirus status is: Unknown", "Host-based FW status is: Unknown"]

        ssl_lines = None
        ssl_checked_at = None
        if run_ssl:
            try:
                res = SSLInspection().check_ssl_inspection("www.google.com", 443, use_cache=False)
                raw_lines = SSLInspection._format_illustration(res).splitlines()
                ssl_lines = raw_lines[1:] if len(raw_lines) > 1 else raw_lines
            except Exception:
                ssl_lines = ["  [ This Host ] --- X (Handshake Failed) ---> [ www.google.com:443 ]"]
            ssl_checked_at = time.monotonic()

        try:
            self.after(0, lambda e=ep_lines, s=ssl_lines, ts=ssl_checked_at: self._finish_welcome_probe(e, s, ts))
        except (tk.TclError, RuntimeError):
            self._welcome_probe_busy = False

    def _start_welcome_probe(self):
        """Launch non-overlapping background worker for AV/FW (15s) + gated SSL (60s) telemetry."""
        if getattr(self, "_welcome_probe_busy", False):
            return
        last_ssl_ts = getattr(self, "_welcome_ssl_last_ts", None)
        run_ssl = (
            last_ssl_ts is None
            or (time.monotonic() - last_ssl_ts) >= (self._WELCOME_SSL_INTERVAL_SEC - 1.0)
        )
        self._welcome_probe_busy = True
        threading.Thread(
            target=self._welcome_probe_worker,
            args=(run_ssl,),
            daemon=True,
            name="Welcome-SecurityProbe",
        ).start()

    def _stop_host_pulse(self):
        """Cancel active Host Pulse and 15s security probe timers and clear the host_pulse tag."""
        for attr in ("_host_pulse_job", "_welcome_probe_job"):
            job = getattr(self, attr, None)
            if job is not None:
                try:
                    self.after_cancel(job)
                except tk.TclError:
                    pass
                setattr(self, attr, None)

        try:
            if hasattr(self, "report_output") and self.report_output.winfo_exists():
                self.report_output.tag_remove("host_pulse", "1.0", tk.END)
        except tk.TclError:
            pass

    def _tick_host_pulse(self):
        """Periodic main-thread UI refresh while welcome screen is displayed."""
        self._host_pulse_job = None
        if self._update_host_pulse_text():
            try:
                self._host_pulse_job = self.after(2000, self._tick_host_pulse)
            except tk.TclError:
                pass

    def show_welcome_screen(self):
        """Return to the welcome screen with live Host Pulse and Endpoint/SSL telemetry."""
        if secuditor_modules.run_all_clicked:
            return
        if getattr(self, "_active_single_key", None) is not None or secuditor_modules.single_check:
            self.stop_current_run()

        if hasattr(self, "tree"):
            sel = self.tree.selection()
            if sel:
                self.tree.selection_remove(*sel)

        if hasattr(self, "status_var"):
            self.status_var.set("Ready")

        if hasattr(self, "console_output") and self.console_output.winfo_exists():
            self.console_output.config(state="normal")
            self.console_output.delete("1.0", tk.END)
            self.console_output.config(state="disabled")

        self._render_welcome_banner(include_live_pulse=True)
        if not getattr(self, "_welcome_probe_busy", False):
            self._start_welcome_probe()
        if hasattr(self, "report_output") and self.report_output.winfo_exists():
            self.report_output.after(50, self.scroll_to_top)

    def _render_welcome_banner(self, include_live_pulse=True):
        """Insert the ASCII banner, version notice, and optional selectable live Host Pulse."""
        self._stop_host_pulse()
        self.report_output.config(state="normal")
        self.report_output.delete("1.0", tk.END)

        self.report_output.tag_config("bold_ascii", font=("Consolas", 12, "bold"))
        self.report_output.tag_config("normal_ascii", font=("Consolas", 10))
        self.report_output.tag_config("normal_text", font=("Segoe UI", 10))
        self.report_output.tag_config("host_pulse", font=("Consolas", 10), foreground="#1E293B")
        self.report_output.tag_config("pulse_active", font=("Consolas", 10), foreground="darkgreen")
        self.report_output.tag_config("pulse_inactive", font=("Consolas", 10), foreground="red")
        self.report_output.tag_config("pulse_high", font=("Consolas", 10), foreground="darkred")
        self.report_output.tag_config("pulse_mitm", font=("Consolas", 10), foreground="#A855F7")

        for line in self.SECUDITOR_LINES:
            self.report_output.insert("end", line + "\n", "bold_ascii")

        lines_to_insert = self.WELCOME_UPDATED if not self.version_check else self.WELCOME_OUTDATED
        for line in lines_to_insert:
            self.report_output.insert("end", line + "\n", "normal_text")
            if self.version_check and self.download_url in line:
                start_idx = f"{float(self.report_output.index('end')) - 2} + {line.find(self.download_url)} chars"
                end_idx = f"{start_idx}+{len(self.download_url)}c"
                self.report_output.tag_add("download_link", start_idx, end_idx)
                self.report_output.tag_config("download_link", foreground="blue", underline=True)
                self.report_output.tag_bind(
                    "download_link",
                    "<Button-1>",
                    lambda e, url=self.download_url: webbrowser.open(
                        url if _is_safe_download_url(url) else "https://secuditor.com"
                    ),
                )

        if include_live_pulse:
            self.report_output.insert("end", self._format_host_pulse(), ("normal_ascii", "host_pulse"))
            self._apply_host_pulse_highlights()
            self.report_output.insert("end", "\n")
            self._host_pulse_job = self.after(2000, self._tick_host_pulse)
            if not getattr(self, "_welcome_probe_busy", False):
                self._schedule_welcome_probe(15000)

        self.report_output.config(state="disabled")
        self._refresh_report_search(scroll=False)

    # --- Show cached result ---
    def show_cached_result(self, key):
        self._stop_host_pulse()
        # Define time and date
        now = datetime.now()
        timestamp = now.strftime("[%Y-%m-%d %H:%M:%S] ")  # e.g. [2025-09-23 20:15:00]
        # Check both caches
        if key in getattr(self, "single_node_cache", {}):
            result = self.single_node_cache[key]
            source = "Single Node"
        elif key in getattr(self, "data_cache", {}):
            result = self.data_cache[key]
            source = "Single Node"
        else:
            messagebox.showwarning("No Data", f"No cached result available for '{key}'.")
            return

        # Clear previous output
        self.report_output.delete('1.0', tk.END)
        self.console_output.delete('1.0', tk.END)

        # Show formatted result
        title = next((t for k, t, _, _ in self.checks if k == key), key)
        self.report_output.insert(tk.END, self.format_single_check(title, result))
        self.report_output.see("1.0")

        self.console_output.insert(tk.END, f"Cached {source} for {title}\n")
        self.console_output.see(tk.END)

    # --- Run single check and store in single-node cache ---
    def run_single_check(self, key):
        func = None
        title = key
        for k, t, cat, f in self.checks:
            if k == key:
                func = f
                title = t
                break
        if func is None:
            messagebox.showerror("Error", f"No function bound for key '{key}'")
            return

        # Stop any previous running single check before enabling mode and logging for the new run
        self.stop_current_run()

        secuditor_modules.set_scan_mode(single=True)
        self.resume_wrap_console_logging()

        self._current_single_run_id = getattr(self, "_current_single_run_id", 0) + 1
        run_id = self._current_single_run_id
        self._active_single_key = key

        stop_event = threading.Event()
        self._current_single_stop = stop_event
        self._dots_running = True

        # Clear previous outputs and show running feedback immediately on main thread
        self._stop_host_pulse()
        self.report_output.config(state="normal")
        self.report_output.delete('1.0', tk.END)
        self.report_output.insert(tk.END, f"[Running check: {title}] Please wait...\n")
        self.report_output.config(state="disabled")
        self._refresh_report_search(scroll=False)

        self.console_output.config(state="normal")
        self.console_output.delete('1.0', tk.END)
        self.console_output.config(state="disabled")

        def _is_active():
            if stop_event.is_set():
                return False
            if run_id != getattr(self, "_current_single_run_id", None):
                return False
            try:
                return bool(self.winfo_exists())
            except tk.TclError:
                return False

        # --- Animate dots for a single check (main thread only) ---
        def animate_dots(max_dots=100, interval_ms=300):
            dot_count = [0]

            def _step():
                if not _is_active() or not getattr(self, "_dots_running", False):
                    return
                if dot_count[0] >= max_dots:
                    return
                try:
                    if not self.console_output.winfo_exists():
                        return
                    self.console_output.config(state="normal")
                    self.console_output.insert(tk.END, ".")
                    self.console_output.see(tk.END)
                    self.console_output.config(state="disabled")
                except tk.TclError:
                    return

                dot_count[0] += 1
                self.console_output.after(interval_ms, _step)

            _step()

        # --- Log function for single checks (main thread only) ---
        def log(msg, add_dot=False, new_line=False):
            if not _is_active():
                return
            try:
                if not self.console_output.winfo_exists():
                    return
                self.console_output.config(state="normal")
                self.console_output.insert(tk.END, msg)
                if add_dot:
                    self.console_output.insert(tk.END, ".")
                if new_line:
                    self.console_output.insert(tk.END, "\n")
                self.console_output.see(tk.END)
                self.console_output.config(state="disabled")
            except tk.TclError:
                pass

        log("\n")
        log(f"[Single Run] {title} started...", add_dot=True)
        animate_dots()

        def _complete_ui(result):
            if not _is_active():
                return

            self._dots_running = False
            self._active_single_key = None
            timeout_job = getattr(self, "_single_timeout_job", None)
            if timeout_job is not None:
                try:
                    self.after_cancel(timeout_job)
                except tk.TclError:
                    pass
                self._single_timeout_job = None

            log("\n")
            log(f"[Single Run] {title} completed.", new_line=True)

            self.single_node_cache[key] = result

            try:
                self._stop_host_pulse()
                if self.report_output.winfo_exists():
                    self.report_output.config(state="normal")
                    self.report_output.delete('1.0', tk.END)
                    self.report_output.insert(tk.END, self.format_single_check(title, result))
                    self.report_output.config(state="disabled")
                    self._refresh_report_search(scroll=False)
                    self.after(0, self.scroll_to_top)
            except tk.TclError:
                pass

            self._reset_single_mode()
            self.stop_wrap_console_logging()

        def worker(ev, my_run_id):
            result = safe_call(func)
            if ev.is_set() or my_run_id != getattr(self, "_current_single_run_id", None):
                return
            try:
                self.after(0, lambda r=result: _complete_ui(r))
            except (tk.TclError, RuntimeError):
                pass

        worker_thread = threading.Thread(
            target=worker,
            args=(stop_event, run_id),
            daemon=True
        )
        self._current_single_thread = worker_thread
        worker_thread.start()

        def check_timeout():
            self._single_timeout_job = None
            if not _is_active():
                return
            if worker_thread.is_alive():
                log("\n")
                log(f"[Single Run] {title} timeout after {MODULE_TIMEOUT}s", new_line=True)
                self._current_single_run_id += 1
                self._active_single_key = None
                self._dots_running = False
                stop_event.set()
                self._reset_single_mode()
                self.stop_wrap_console_logging()

        self._single_timeout_job = self.after(MODULE_TIMEOUT * 1000, check_timeout)

    def _assemble_data(self):
        defaults = {
            'System_Settings': {},
            'Network_Settings': {},
            'Detect_Shared_Folders': [],
            'Remote_Access_Settings': {}, 
            'Hardware_Components:': [],
            'Installed_Applications': [],
            'Scan_Sensitive_Paths': [],
            'Domain_Settings': {},
            'Security_Events': {},
            'Windows_Events': {},
            'Password_Policy': {},
            'Credential_Integrity': {},
            'OS_Version_Status': {},
            'Endpoint_Security_Settings': {},
            'Gateway_Discovery': {},
            'Scan_Suspicious_Activity': [],
            'Proxy_Interception': {},
            'SSL/TLS_Interception': [],
        }

        data = defaults.copy()

        # Fill with actual collected data from full report cache
        for k in defaults.keys():
            if k in getattr(self, "data_cache", {}):
                data[k] = self.data_cache[k]

        # Merge single-node cache if keys match
        for key, value in getattr(self, "single_node_cache", {}).items():
            if key in data:
                data[key] = value

        return data
    
    # --- Check hostname ---
    def get_hostname_gui(self):
        try:
            return socket.gethostname()
        except Exception as e:
            return f"Error: {e}"

    # --- Reset flag ---
    def reset_run_all_flag(self):
            secuditor_modules.set_scan_mode(run_all=False)
            
    # --- Run full audit ---
    def run_all_clicked(self):
        self.stop_current_run()
        secuditor_modules.set_scan_mode(run_all=True, single=False)
        self.resume_wrap_console_logging()
        self.set_busy_cursor()
        self.lock_main_widgets()
                
        stop_event = threading.Event()
        
        hostname = self.get_hostname_gui()
        date_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # --- Main console/log area ---
        console = self.console_output
        console.config(state="normal")
        console.delete("1.0", tk.END)
        console.insert(tk.END, "\n")
        console.insert(tk.END, f"Security Audit Run started on {hostname}\n")
        console.see(tk.END)
        console.config(state="disabled")

        def _append_console(text):
            try:
                if not console.winfo_exists():
                    return
                console.config(state="normal")
                console.insert(tk.END, text)
                console.see(tk.END)
                console.config(state="disabled")
            except tk.TclError:
                pass

        def _safe_append_console(text):
            try:
                self.after(0, lambda t=text: _append_console(t))
            except (tk.TclError, RuntimeError):
                pass
        
        def on_audit_stop():
            stop_event.set()
            try:
                if not self.winfo_exists():
                    return
                self.reset_cursor()      # <-- restore cursor
                self.unlock_main_widgets()

                # restore Treeview selection
                hostname_node = None
                for item in self.tree.get_children(''):
                    if self.tree.item(item, "text") == getattr(self, "hostname", "Unknown Host"):
                        hostname_node = item
                        break
                if hostname_node:
                    self.tree.selection_set(hostname_node)
                    self.tree.focus(hostname_node)
                    self.tree.focus_set()
                    self.tree.see(hostname_node)
                    # simulate click event to display report
                    class Event: pass
                    event = Event()
                    event.x = 1
                    bbox = self.tree.bbox(hostname_node)
                    event.y = bbox[1] if bbox else 0
                    self._on_tree_single_click(event)
            except tk.TclError:
                pass

        def expand_all(tree, item=""):
            try:
                if not tree.winfo_exists():
                    return
                children = tree.get_children(item)
                for child in children:
                    tree.item(child, open=True)
                    expand_all(tree, child)
            except tk.TclError:
                pass

        # --- Audit worker ---
        def worker():
            try:
                self.data_cache.clear()
                self.single_node_cache.clear()
                _clear_all_audit_caches()
                failed_checks = set()
                total = len(self.checks)
                skip_modules = {}

                audit_completed = False

                for i, (key, title, cat, func) in enumerate(self.checks, start=1):
                    if stop_event.is_set():
                        _safe_append_console("[Audit stopped before completion]\n")
                        break

                    if key in skip_modules:
                        _safe_append_console(f"[Skipped {title}]\n")
                        continue

                    # --- Start module log & dots animation on main thread ---
                    dots_state = {"running": True, "count": 0}

                    def start_module_ui(t_name=title, state=dots_state):
                        _append_console(f" -> {t_name}")

                        def _step():
                            if not state["running"] or state["count"] >= 120:
                                return
                            try:
                                if not console.winfo_exists():
                                    return
                                _append_console(".")
                                state["count"] += 1
                                console.after(1000, _step)
                            except tk.TclError:
                                pass

                        _step()

                    try:
                        self.after(0, start_module_ui)
                    except (tk.TclError, RuntimeError):
                        pass

                    # --- Run module with timeout ---
                    result_container = {"result": None, "error": None}

                    def run_module():
                        try:
                            result_container["result"] = func()
                        except Exception as e:
                            result_container["error"] = e

                    t = threading.Thread(target=run_module, daemon=True)
                    t.start()
                    t.join(MODULE_TIMEOUT)

                    if t.is_alive():
                        _safe_append_console(f" Timeout after {MODULE_TIMEOUT}s\n")
                        self.single_node_cache.pop(key, None)
                        failed_checks.add(key)
                        module_ok = False
                    else:
                        if result_container["error"]:
                            _safe_append_console(f" Error: {result_container['error']}\n")
                            self.single_node_cache.pop(key, None)
                            failed_checks.add(key)
                            module_ok = False
                        else:
                            self.data_cache[key] = result_container["result"]
                            self.single_node_cache[key] = result_container["result"]
                            module_ok = True

                    def finish_module_ui(state=dots_state, ok=module_ok):
                        state["running"] = False
                        if not ok:
                            return
                        try:
                            if not console.winfo_exists():
                                return
                            console.config(state="normal")
                            if state["count"] == 0:
                                console.insert(tk.END, ".")
                            last_line = console.index("end-1c linestart")
                            console.insert(f"{last_line} lineend", " ✓\n")
                            console.see(tk.END)
                            console.config(state="disabled")
                        except tk.TclError:
                            pass

                    try:
                        self.after(0, finish_module_ui)
                    except (tk.TclError, RuntimeError):
                        pass

                    # Update toolbar progress label
                    pct = int(i * 100 / total)

                    def update_ui(p=pct):
                        try:
                            if not self.winfo_exists() or not self.score_frame.winfo_exists():
                                return
                            if not self.score_frame.winfo_ismapped():
                                self.score_frame.pack(side="right", padx=(0, 120))
                            for widget in self.score_frame.winfo_children():
                                widget.destroy()
                            tk.Label(
                                self.score_frame,
                                text=f"Processing Security Data: {p}%",
                                bg="#F0F0F0",
                                fg="black",
                                font=("Segoe UI", 14, "bold")
                            ).pack(side="left")
                        except tk.TclError:
                            pass

                    try:
                        self.after(0, update_ui)
                    except (tk.TclError, RuntimeError):
                        pass

                else:
                    audit_completed = True

                # --- Assemble final report ---
                if audit_completed:
                    self.reset_run_all_flag()
                    self.stop_wrap_console_logging()
                    calc_container = {"data": None, "error": None}

                    def run_calculation():
                        try:
                            assembled = self._assemble_data()
                            assembled["_failed_checks"] = set(failed_checks)
                            score, result, breakdown, config, gravity, severity = calculate_score_with_breakdown(assembled)

                            assembled["security_score"] = score
                            assembled["function_result"] = result
                            assembled["gravity_balance"] = gravity
                            assembled["severity_balance"] = severity
                            assembled["score_breakdown"] = breakdown
                            assembled["config_breakdown"] = config

                            calc_container["data"] = assembled

                        except Exception as e:
                            calc_container["error"] = e

                    calc_thread = threading.Thread(target=run_calculation, daemon=True)
                    calc_thread.start()
                    calc_thread.join(CALCULATION_TIMEOUT)

                    if calc_thread.is_alive():
                        _safe_append_console(f"[Calculation timeout after {CALCULATION_TIMEOUT}s]\n")

                        assembled = {}
                        score = 0
                        breakdown = {}
                        config = {}
                        gravity = {}
                        severity = {}
                        result = {}

                    elif calc_container["error"]:
                        _safe_append_console(f"[Calculation error: {calc_container['error']}]\n")

                        assembled = {}
                        score = 0
                        breakdown = {}
                        config = {}
                        gravity = {}
                        severity = {}
                        result = {}

                    else:
                        assembled = calc_container["data"]
                        score = assembled["security_score"]
                        breakdown = assembled["score_breakdown"]
                        config = assembled["config_breakdown"]
                        gravity = assembled["gravity_balance"]
                        severity = assembled["severity_balance"]
                        result = assembled["function_result"]

                    report_lines = []
                    header = f"{'Security Elements'.ljust(26)} {'Settings'.center(22)} {'Reference'.center(30)} {'Result'.center(16)}"
                    report_lines.append(header)
                    report_lines.append("—" * (30 + 25 + 20 + 16))

                    for reason, points in breakdown.items():
                        reason_result = result.get(reason, "Unknown")
                        reason_gravity = gravity.get(reason, "Unknown")
                        reason_severity = severity.get(reason, "Unknown")
                        reason_config = config.get(reason, "Default")
                        line = f" - {reason.ljust(26)} {reason_gravity.center(22)} {reason_config.center(28)} {reason_result.center(16)}"
                        report_lines.append(line)

                    if score >= 90:
                        color = "green"
                        verdict = ""
                    elif score >= 70:
                        color = "limegreen"
                        verdict = ""
                    elif score >= 50:
                        color = "orange"
                        verdict = ""
                    elif score >= 30:
                        color = "brown"
                        verdict = ""
                    else:
                        color = "red"
                        verdict = ""

                    self.data_cache['last_report'] = "\n".join(report_lines)
                    self.data_cache['security_score'] = score
                    self.data_cache["score_verdict"] = verdict
                    self.data_cache["report_timestamp"] = datetime.now()

                    try:
                        self.after(0, self.update_score_label)
                    except (tk.TclError, RuntimeError):
                        pass
                    print("Security Audit Run completed")
            finally:
                self.reset_run_all_flag()
                _clear_all_audit_caches()
                self.stop_wrap_console_logging()
                try:
                    self.after(0, on_audit_stop)
                    self.after(0, lambda: expand_all(self.tree))
                except (tk.TclError, RuntimeError):
                    pass
        
        threading.Thread(target=worker, daemon=True).start()

    # --- Export node to txt (vertical presentation with headline) ---
    def _export_node_txt(self):
        selected = self.tree.selection()
        node_id = selected[0] if selected else self.tree.focus()
        if not node_id:
            messagebox.showwarning("Export Node", "No node selected.")
            return

        if self.tree.parent(node_id) == '':
            messagebox.showwarning("Export Node", "Cannot export a category node. Select a sub-item.")
            return

        values = self.tree.item(node_id, "values")
        if not values:
            messagebox.showwarning("Export Node", "Selected node has no associated key.")
            return
        key = values[0]

        node_name = self.tree.item(node_id, "text")  # Get the node's display name

        # Check both caches
        node_data = None
        if key in getattr(self, "single_node_cache", {}):
            node_data = self.single_node_cache[key]
        elif key in getattr(self, "data_cache", {}):
            node_data = self.data_cache[key]

        if not node_data or (isinstance(node_data, (dict, list)) and not node_data):
            messagebox.showwarning("Export Node", "Selected node is empty.")
            return

        # Convert to vertical text
        def format_vertical(data, indent=0):
            spacer = '  ' * indent
            if isinstance(data, dict):
                lines = []
                for k, v in data.items():
                    if isinstance(v, (dict, list)):
                        lines.append(f"{spacer}{k}:")
                        lines.append(format_vertical(v, indent + 1))
                    else:
                        lines.append(f"{spacer}{k}: {v}")
                return "\n".join(lines)
            elif isinstance(data, list):
                lines = []
                for i, item in enumerate(data, 1):
                    if isinstance(item, (dict, list)):
                        lines.append(f"{spacer}- Item {i}:")
                        lines.append(format_vertical(item, indent + 1))
                    else:
                        lines.append(f"{spacer}- {item}")
                return "\n".join(lines)
            else:
                return f"{spacer}{data}"

        node_text = format_vertical(node_data).strip()
        if not node_text:
            messagebox.showwarning("Export Node", "Selected node is empty.")
            return

        # --- Add date/time above the headline ---
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        export_text = f"Exported for {self.FQDN} on: {now_str}\n\n{node_name}\n{'=' * len(node_name)}\n\n{node_text}"

        # Ask user where to save
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt")],
            title="Export Node"
        )
        if not path:
            return

        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(export_text)
            messagebox.showinfo("Export Node", f"Node saved to {path}")
        except Exception as e:
            messagebox.showerror("Export Node Error", f"Failed to save node: {e}")

    # --- Generate the score breakdown ---
    def generate_scorebreakdown(self):
        """ Return the full audit report if it exists, otherwise None. """
        hostname = getattr(self, "hostname", "Unknown Host")
        report_text = self.data_cache.get("last_report", "")
        score = self.data_cache.get("security_score", None)
        verdict = self.data_cache.get("score_verdict", None)
        timestamp = self.data_cache.get("report_timestamp", datetime.now())
        
        if isinstance(timestamp, datetime):
            timestamp = timestamp.replace(microsecond=0)  # remove .059151
        else:
            timestamp = datetime.now().replace(microsecond=0)

        if not report_text or score is None or verdict is None:
            return None

        # Use cached timestamp
        date_str = timestamp.strftime("%Y-%m-%d")
        time_str = timestamp.strftime("%H:%M:%S")

        header_lines = [""]

        # Updated table header with Balance column
        table_header = (
            f"{'  Security Elements'.ljust(26)}"
            f"{' Settings'.center(22)}"
            f"{'Reference'.center(30)}"
            f"{'Result'.center(16)}"
        )

        separator = "—" * (30 + 25 + 20 + 16)
        formatted_lines = header_lines + [table_header, separator]

        for line in report_text.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith("Security Elements") or stripped.startswith("—"):
                continue

            # Split line into exactly 5 groups (element, config, gravity, severity, result)
            parts = re.split(r"\s{2,}", stripped)

            if len(parts) >= 4:
                element = parts[0].ljust(26)
                gravity = parts[1].center(22)
                config = parts[2].center(30)
                result = parts[3].center(16)
                formatted_lines.append(f"{element}{gravity}{config}{result}")
            else:
                formatted_lines.append(stripped)

        return "\n".join(formatted_lines).rstrip("\n")

    # --- Generate the TXT report using the new module (with hostname) ---
    def generate_full_txt_report(self, selected_nodes=None):

        if selected_nodes is None:

            win = tk.Toplevel(self)
            win.withdraw()  # 👈 prevents ghost window

            # Keyboard shortcuts
            win.bind(
                "<Escape>",
                lambda e: win.destroy()
            )

            set_window_icon(win)

            win.title("Report Building")
            win.resizable(False, False)
            win.grab_set()
            win.transient(self)

            # Update main window dimensions
            self.update_idletasks()

            main_x = self.winfo_x()
            main_y = self.winfo_y()
            main_w = self.winfo_width()
            main_h = self.winfo_height()

            # Center over the main window
            panel_width = 280
            panel_height = main_h - 200

            x = main_x + (main_w - panel_width) // 2
            y = main_y + (main_h - panel_height) // 2

            win.geometry(f"{panel_width}x{panel_height}+{x}+{y}")

            tk.Label(
                win,
                text="Select nodes to include:\n(Summary report included by default)",
                font=("Segoe UI", 10, "bold")
            ).pack(pady=10)

            vars_dict = {}

            container = tk.Frame(win)
            container.pack(fill="both", expand=True)

            canvas = tk.Canvas(container)
            scrollbar = tk.Scrollbar(container, orient="vertical", command=canvas.yview)
            scroll_frame = tk.Frame(canvas)

            scroll_frame.bind(
                "<Configure>",
                lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
            )

            canvas.create_window((0, 0), window=scroll_frame, anchor="nw")
            canvas.configure(yscrollcommand=scrollbar.set)

            canvas.pack(side="left", fill="both", expand=True)
            scrollbar.pack(side="right", fill="y")

            for key in self.data_cache.keys():
                if key in ("last_report", "security_score", "score_verdict", "report_timestamp", "Scan_Sensitive_Paths", "Scan_Suspicious_Activity", "Security_Events", "Windows_Events"):
                    continue

                var = tk.BooleanVar(value=False)
                tk.Checkbutton(scroll_frame, text=key, variable=var, anchor="w").pack(
                    fill="x", padx=10, pady=2
                )
                vars_dict[key] = var

            bottom = tk.Frame(win, height=50)
            bottom.pack(side="bottom", fill="x")

            def select_all():
                for var in vars_dict.values():
                    var.set(True)

            tk.Button(
                bottom,
                text="Select All",
                command=select_all,
                bg="#F0F0F0",
                fg="black",
                font=("Segoe UI", 10)
            ).pack(side="left", padx=(10, 5), pady=10)

            def export():
                selected = [k for k, v in vars_dict.items() if v.get()]
                win.destroy()
                self.generate_full_txt_report(selected)

            tk.Button(
                bottom,
                text="Save Report",
                command=export,
                bg="#F0F0F0",
                fg="black",
                font=("Segoe UI", 10)
            ).pack(side="right", padx=(5, 10), pady=10)

            win.deiconify()  # 👈 show ONLY when fully ready

            return

        # REPORT GENERATION MODE
        hostname = getattr(self, "hostname", "Unknown Host")
        score = self.data_cache.get("security_score", None)
        verdict = self.data_cache.get("score_verdict", "Unknown")
        report_text = self.data_cache.get("last_report", "")
        timestamp = self.data_cache.get("report_timestamp", datetime.now())

        if isinstance(timestamp, datetime):
            timestamp = timestamp.replace(microsecond=0)
        else:
            timestamp = datetime.now().replace(microsecond=0)

        lines = []

        # --- Header ---
        header_lines = [
            f"Secuditor Lite {self.CURRENT_VERSION}\n",
        ]
        if timestamp is not None:
            header_lines.append(
                f"Extended Security Report for Device {self.FQDN} on {timestamp}\n"
            )
        lines.extend(header_lines)

        # --- Table header ---
        table_header = (
            f"{'  Security Elements'.ljust(26)}"
            f"{'Settings'.center(22)}"
            f"{'Reference'.center(30)}"
            f"{'Result'.center(16)}"
        )
        separator = "—" * (30 + 25 + 20 + 16)
        lines.append(table_header)
        lines.append(separator)

        # --- Parse table body ---
        for line in report_text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("Security Elements") or stripped.startswith("—"):
                continue

            parts = re.split(r"\s{2,}", stripped)

            if len(parts) >= 4:
                element_col = parts[0].ljust(26)
                settings_col = parts[1].center(22)
                reference_col = parts[2].center(30)
                result_col = parts[3].center(16)
                lines.append(f"{element_col}{settings_col}{reference_col}{result_col}")
            else:
                lines.append(stripped)

        lines.append("")

        # --- Formatting helper ---
        def format_vertical_uniform(data, indent=0):
            spacer = '  ' * indent
            if isinstance(data, dict):
                lines_v = []
                for k, v in data.items():
                    if isinstance(v, (dict, list)):
                        lines_v.append(f"{spacer}{k}:")
                        lines_v.append(format_vertical_uniform(v, indent + 1))
                    else:
                        lines_v.append(f"{spacer}{k}:")
                        lines_v.append(f"{spacer}        {v}")
                return "\n".join(lines_v)

            elif isinstance(data, list):
                lines_v = []
                for item in data:
                    if isinstance(item, (dict, list)):
                        lines_v.append(format_vertical_uniform(item, indent))
                    else:
                        lines_v.append(f"{spacer}- {item}")
                return "\n".join(lines_v)

            else:
                return f"{spacer}{data}"

        # --- FULL REPORT MODULES (FILTERED) ---
        for key, value in self.data_cache.items():

            if selected_nodes is not None and key not in selected_nodes:
                continue

            lines.append("")
            lines.append('–' * len(key))
            lines.append(key)
            lines.append('–' * len(key))
            lines.append(format_vertical_uniform(value))
            lines.append("")

        final_text = "\n".join(lines)

        # --- Save dialog ---
        output_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt")],
            title="Export Report"
        )

        if not output_path:
            return

        try:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(final_text)

            messagebox.showinfo(
                "Export Report",
                f"Extended Report Saved as {output_path}"
            )

        except Exception as e:
            messagebox.showerror(
                "Export Report",
                f"Failed to save TXT report: {e}"
            )

    # --- Check report availability ---
    def save_as_txt_clicked(self):
        """
        Save the entire audit report as TXT with hostname, score, verdict, 
        and all module results. Only allowed after security audit.
        """
        # Only allow if full audit has been run
        if not self.data_cache:
            messagebox.showwarning(
                "Attention",
                "No data available yet, please run Security Audit.",
                parent=self
            )
            
            return

        # Call the new full report generator
        self.generate_full_txt_report()

# ===== MAIN =====
# --- Run Program ---
if __name__ == "__main__":
    app = OpSecGUI()
    app.mainloop()
