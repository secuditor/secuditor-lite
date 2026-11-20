# Secuditor Modules – Copyright (c) 2026 Menahem Levinski

import requests, json, getpass, win32security, win32net, win32netcon
import sys, re, os, subprocess, tempfile, warnings
import socket, platform, psutil, ipaddress
import pythoncom, winreg, wmi, ctypes
import time, hashlib
import ntsecuritycon as con

from ctypes import wintypes
from urllib3.exceptions import InsecureRequestWarning
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

from secuditor_utilities import (
    NetStatus,
    load_oui_database,
    _system_exe,
    _safe_subproc_env,
    _run_check_output,
)

# ===== SUBPROCESS SETTINGS =====
_CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)

try:
    _STARTUPINFO = subprocess.STARTUPINFO()
    _STARTUPINFO.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    _STARTUPINFO.wShowWindow = subprocess.SW_HIDE
except Exception:
    _STARTUPINFO = None

# ===== CACHE VALUES =====
_NOT_FOUND = object()
_audit_winrm_cache = None
_gateway_ip_cache = None
_gateway_mac_cache = {}
_mac_vendor_cache = {}
_management_ports_cache = {}
_nat_cache = None
_security_settings_cache = None
_remote_access_cache = None
_credential_guard_cache = None
_lsass_protection_cache = None
_domain_settings_cache = None
_ntlm_policy_cache = None
_password_policy_cache = None
_windows_version_cache = None

run_all_clicked = False
single_check = False


def set_scan_mode(*, run_all=None, single=None):
    global run_all_clicked, single_check
    if run_all is not None:
        run_all_clicked = bool(run_all)
    if single is not None:
        single_check = bool(single)


def clear_audit_caches():
    """Clear all module-level audit caches so subsequent audits rerun fresh and caches serve only scoring."""
    global _audit_winrm_cache
    global _gateway_ip_cache
    global _gateway_mac_cache
    global _mac_vendor_cache
    global _management_ports_cache
    global _nat_cache
    global _security_settings_cache
    global _remote_access_cache
    global _credential_guard_cache
    global _lsass_protection_cache
    global _domain_settings_cache
    global _ntlm_policy_cache
    global _password_policy_cache
    global _windows_version_cache

    _audit_winrm_cache = None
    _gateway_ip_cache = None
    _gateway_mac_cache.clear()
    _mac_vendor_cache.clear()
    _management_ports_cache.clear()
    _nat_cache = None
    _security_settings_cache = None
    _remote_access_cache = None
    _credential_guard_cache = None
    _lsass_protection_cache = None
    _domain_settings_cache = None
    _ntlm_policy_cache = None
    _password_policy_cache = None
    _windows_version_cache = None

# ===== SHARED HELPERS =====

# --- Scan related hardware devices ---
def _run(cmd):
    try:
        if isinstance(cmd, (list, tuple)) and cmd:
            cmd = [_system_exe(str(cmd[0])), *cmd[1:]]
        return subprocess.check_output(
            cmd,
            stderr=subprocess.DEVNULL,
            text=True,
            env=_safe_subproc_env(),
            creationflags=_CREATE_NO_WINDOW,
            startupinfo=_STARTUPINFO,
        )
    except Exception:
        return ""

# --- Detect network adapter headers (Ethernet, Wi-Fi, etc.) ---
def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

# --- Get shared folders ---
# --- Check if script runs as admin ---
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def _get_cim_value(class_name, property_name):
    try:
        result = subprocess.run(
            [
                _system_exe("powershell.exe"),
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                f"(Get-CimInstance -ClassName {class_name}).{property_name}",
            ],
            capture_output=True,
            text=True,
            timeout=5,
            env=_safe_subproc_env(),
            creationflags=_CREATE_NO_WINDOW,
            startupinfo=_STARTUPINFO,
        )
        value = result.stdout.strip()
        return value if result.returncode == 0 and value else "Unknown"
    except (OSError, subprocess.TimeoutExpired):
        return "Unknown"

# --- Get local Windows version/build information ---
def get_local_windows_info():
    """
    Get Windows version information directly from the registry.

    Returns:
        {
            "ProductName": "Windows 11 Pro",
            "DisplayVersion": "24H2",
            "Build": 26100,
            "UBR": 9168,
            "FullBuild": "26100.9168"
        }

    Returns None on failure.
    """
    try:
        key_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"

        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            key_path
        ) as key:

            # Product name
            try:
                product_name, _ = winreg.QueryValueEx(
                    key,
                    "ProductName"
                )
            except FileNotFoundError:
                product_name = "Unknown"

            # Windows edition
            try:
                edition_id, _ = winreg.QueryValueEx(
                    key,
                    "EditionID"
                )
            except FileNotFoundError:
                edition_id = None

            # Display version
            try:
                display_version, _ = winreg.QueryValueEx(
                    key,
                    "DisplayVersion"
                )
            except FileNotFoundError:
                display_version = None

            # Build number
            try:
                current_build, _ = winreg.QueryValueEx(
                    key,
                    "CurrentBuildNumber"
                )
            except FileNotFoundError:
                current_build, _ = winreg.QueryValueEx(
                    key,
                    "CurrentBuild"
                )

            # Revision / UBR
            try:
                ubr, _ = winreg.QueryValueEx(
                    key,
                    "UBR"
                )
            except FileNotFoundError:
                ubr = 0

            build = int(current_build)
            ubr = int(ubr)

            return {
                "ProductName": str(product_name),
                "EditionID": str(edition_id)
                    if edition_id else None,
                "DisplayVersion": str(display_version)
                    if display_version else None,
                "Build": build,
                "UBR": ubr,
                "FullBuild": f"{build}.{ubr}"
            }

    except Exception as e:
        print(f"[Windows Version] Error: {e}")
        return None

# --- Determine Windows edition ---
def get_windows_edition(edition_id):
    """
    Convert Windows EditionID into a user-friendly edition name.
    """

    editions = {
        "Core": "Home",
        "CoreN": "Home N",
        "CoreSingleLanguage": "Home Single Language",
        "CoreCountrySpecific": "Home China",
        "Professional": "Pro",
        "ProfessionalN": "Pro N",
        "ProfessionalWorkstation": "Pro for Workstations",
        "ProfessionalWorkstationN": "Pro N for Workstations",
        "ProfessionalEducation": "Pro Education",
        "ProfessionalEducationN": "Pro Education N",
        "Enterprise": "Enterprise",
        "EnterpriseN": "Enterprise N",
        "Education": "Education",
        "EducationN": "Education N"
    }

    return editions.get(
        edition_id,
        edition_id or "Unknown"
    )

# --- Determine Windows OS type ---
def get_windows_os_name(product_name, build):
    """
    Determine Windows client/server.

    Build number is used to distinguish Windows 10
    from Windows 11 because upgraded Windows 11 systems
    can still report "Windows 10" as ProductName.
    """

    product = (product_name or "").lower()

    # Server detection first
    if "server" in product:
        if "2025" in product:
            return "Windows Server 2025"
        elif "2022" in product:
            return "Windows Server 2022"
        elif "2019" in product:
            return "Windows Server 2019"
        elif "2016" in product:
            return "Windows Server 2016"

        return "Windows Server"

    # Windows 11
    if build >= 22000:
        return "Windows 11"

    # Windows 10
    if 10240 <= build < 22000:
        return "Windows 10"

    return "Unknown"

# --- Domain controller check ---
def is_domain_controller():
    """Return True if machine is a domain controller"""
    try:
        product_type = _read_reg_value(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\ProductOptions",
            "ProductType",
        )
        if isinstance(product_type, str) and product_type.strip():
            return product_type.strip().casefold() == "lanmannt"
    except Exception:
        pass

    try:
        role = _get_cim_value("Win32_ComputerSystem", "DomainRole")
        # DC roles: 4 = Primary DC, 5 = Backup DC
        return str(role).strip() in ("4", "5")
    except Exception:
        pass
    return False

# --- Domain/workgroup info ---
def _check_laps():
    """Check legacy Microsoft LAPS and built-in Windows LAPS configuration."""
    try:
        detected = False
        explicitly_disabled = False

        # --- Legacy Microsoft LAPS ---
        legacy_key = r"SOFTWARE\Policies\Microsoft Services\AdmPwd"

        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, legacy_key, 0, winreg.KEY_READ
            ) as key:
                try:
                    enabled, _ = winreg.QueryValueEx(key, "AdmPwdEnabled")
                    if enabled == 1:
                        return True, True
                    explicitly_disabled = True
                except FileNotFoundError:
                    if winreg.QueryInfoKey(key)[1] > 0:
                        detected = True
        except FileNotFoundError:
            pass

        # --- Built-in Windows LAPS (CSP / Policies / Config) ---
        for windows_laps_key in (
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config",
        ):
            try:
                with winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    windows_laps_key,
                    0,
                    winreg.KEY_READ,
                ) as key:
                    try:
                        backup_directory, _ = winreg.QueryValueEx(
                            key, "BackupDirectory"
                        )
                        if backup_directory in (1, 2):
                            return True, True
                        explicitly_disabled = True
                    except FileNotFoundError:
                        # Windows 10/11 creates an empty LAPS\Config key by default
                        # even when LAPS has never been configured.
                        if winreg.QueryInfoKey(key)[1] > 0:
                            detected = True
            except FileNotFoundError:
                pass

        if explicitly_disabled:
            return True, False

        if detected:
            return None, None  # Non-empty key exists, but enabled state isn't confirmed

        return False, False

    except OSError:
        return None, None

def get_domain_settings():
    """
    Returns a dictionary with domain/workgroup info and all local users.
    Keys:
        Type: "Domain", "Workgroup", "Local"
        Name: domain/workgroup name or None
        Computer Name
        Current User
        Domain Role
        Privileged Users: list of strings "username (Enabled/Disabled)"
        Regular Users: list of strings "username (Enabled/Disabled)"
        LAPS Status: "Enabled"/"Disabled"/"Not Detected"
    """
    global _domain_settings_cache
    global run_all_clicked
    global single_check
            
    if _domain_settings_cache is not None and not run_all_clicked and not single_check:
        return _domain_settings_cache
    
    data = {
        "Type": "Local",
        "Name": None,
        "Hostname": socket.gethostname(),
        "Current User": getpass.getuser(),
        "Domain Role": None,
        "NTP": None,
        "NTLM Policy": None,
        "LAPS Status": "Not Detected",
        "LAPS": "Not Detected",
        "Privileged Users": [],
        "Regular Users": []
    }

    # --- Azure AD / Entra ID detection (add-on, non-invasive) ---
    try:
        output = _run_check_output(["dsregcmd", "/status"], shell=False)

        azure_joined = "AzureAdJoined : YES" in output
        domain_joined = "DomainJoined : YES" in output

        if azure_joined and domain_joined:
            data["Type"] = "Hybrid Azure AD"
        elif azure_joined:
            data["Type"] = "Azure AD"
        elif domain_joined:
            data["Type"] = "Domain"
            
    except Exception:
        pass

    # --- Domain / Workgroup detection ---
    try:

        NetGetJoinInformation = ctypes.windll.netapi32.NetGetJoinInformation
        NetGetJoinInformation.argtypes = [
            wintypes.LPCWSTR,
            ctypes.POINTER(wintypes.LPWSTR),
            ctypes.POINTER(ctypes.c_int)
        ]
        NetGetJoinInformation.restype = wintypes.DWORD

        NetApiBufferFree = ctypes.windll.netapi32.NetApiBufferFree
        NetApiBufferFree.argtypes = [ctypes.c_void_p]
        NetApiBufferFree.restype = wintypes.DWORD

        # NETSETUP_JOIN_STATUS
        NETSETUP_JOIN_STATUS = {
            0: "Unknown",
            1: "Unjoined",
            2: "Workgroup",
            3: "Domain"
        }

        computer_name = socket.gethostname()

        name_buffer = wintypes.LPWSTR()
        join_status = ctypes.c_int()

        result = NetGetJoinInformation(
            computer_name,
            ctypes.byref(name_buffer),
            ctypes.byref(join_status)
        )

        if result == 0:  # NERR_Success
            join_type = NETSETUP_JOIN_STATUS.get(
                join_status.value,
                "Unknown"
            )

            if join_type == "Domain":
                if data["Type"] != "Hybrid Azure AD":
                    data["Type"] = "Domain"
                data["Name"] = name_buffer.value

            elif join_type == "Workgroup":
                if data["Type"] not in ("Azure AD", "Hybrid Azure AD"):
                    data["Type"] = "Workgroup"
                data["Name"] = name_buffer.value

            elif join_type == "Unjoined":
                if data["Type"] not in ("Azure AD", "Hybrid Azure AD"):
                    data["Type"] = "Local"
                data["Name"] = None

            else:
                if data["Type"] not in ("Azure AD", "Hybrid Azure AD"):
                    data["Type"] = "Local"
                data["Name"] = None

            if name_buffer:
                NetApiBufferFree(name_buffer)

    except Exception:
        pass

    # --- Domain Role ---
    try:
        role_map = {
            0: "Standalone Workstation",
            1: "Member Workstation",
            2: "Standalone Server",
            3: "Member Server",
            4: "Backup Domain Controller",
            5: "Primary Domain Controller"
        }

        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = subprocess.SW_HIDE

        role = subprocess.check_output(
            [
                _system_exe("powershell.exe"),
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "(Get-CimInstance Win32_ComputerSystem).DomainRole"
            ],
            text=True,
            stderr=subprocess.DEVNULL,
            env=_safe_subproc_env(),
            startupinfo=startupinfo,
            creationflags=subprocess.CREATE_NO_WINDOW
        ).strip()

        role_int = int(role)
        data["Domain Role"] = role_map.get(
            role_int,
            f"Unknown ({role_int})"
        )

    except Exception:
        data["Domain Role"] = "Unknown"

    # --- All local users ---
    try:
        output = _run_check_output(["net", "user"], shell=False)
        lines = output.splitlines()
        try:
            sep_index = next(i for i, line in enumerate(lines) if line.strip().startswith('---'))
        except StopIteration:
            sep_index = 0

        users = []
        for line in lines[sep_index+1:]:
            if line.strip() and not line.lower().startswith("the command completed successfully"):
                users.extend(line.split())

        # --- Check each user ---
        for user in users:
            status = "Unknown"
            is_admin = False
            try:
                info_output = _run_check_output(["net", "user", user], shell=False)
                match = re.search(r"Account active\s+(\w+)", info_output, re.IGNORECASE)
                if match:
                    status = "Enabled" if match.group(1).strip().lower() == "yes" else "Disabled"

                # Check if user is in Administrators group
                groups = re.findall(r"Local Group Memberships\s+(.*)", info_output)
                if groups and "Administrators" in groups[0]:
                    is_admin = True

            except Exception:
                pass

            user_entry = f"{user} ({status})"
            if is_admin:
                data["Privileged Users"].append(user_entry)
            else:
                data["Regular Users"].append(user_entry)
                
    except Exception:
        pass

    # --- Check NTLM ---
    try:
        data["NTLM Policy"] = check_ntlm_policy()
        
    except Exception:
        pass

    # --- NTP Server ---
    try:
        service_name = "Windows Time"
        status = None

        # 1. Service query (core state)
        output = _run(["sc", "query", "w32time"]).upper()

        if "SERVICE_NAME" not in output:
            data["NTP"] = f"Not Detected"

        elif "STOPPED" in output:
            status = "Stopped"

        elif "RUNNING" in output:
            status = "Running"

        elif "DISABLED" in output:
            status = "Disabled"

        else:
            status = "Unknown"

        # 2. Advanced role check (domain/NTP server behavior)
        if status == "Running":
            try:
                with winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SYSTEM\CurrentControlSet\Services\W32Time\Config"
                ) as key:
                    announce_flags = winreg.QueryValueEx(key, "AnnounceFlags")[0]

                    if announce_flags in (5, 10) and is_domain_controller():
                        status += " (Domain NTP Server)"

            except Exception:
                pass

        # Final output (clean format)
        if status:
            data["NTP"] = f"{service_name} is {status}"

    except Exception:
        data["NTP"] = "Unknown"

    # --- Check LAPS ---
    try:
        installed, enabled = _check_laps()
        if installed and enabled:
            laps_status = "Enabled"
        elif installed is False:
            laps_status = "Not Detected"
        elif installed is None:
            laps_status = "Unknown"
        else:
            laps_status = "Disabled"
    except Exception:
        laps_status = "Unknown"

    data["LAPS Status"] = laps_status
    data["LAPS"] = laps_status

    _domain_settings_cache = data
    
    return _domain_settings_cache

# --- NTLM policy checker ---
def _read_reg_value(root, path, name):
    try:
        with winreg.OpenKey(root, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
            value, _ = winreg.QueryValueEx(key, name)
            return value
    except Exception:
        return None

def read_reg(path, key):
    return _read_reg_value(winreg.HKEY_LOCAL_MACHINE, path, key)

def ntlm_verdict(
    lm,
    lmhash,
    audit,
    restrict_sending=None,
    restrict_receiving=None,
    block_ntlmv1_sso=None,
):
    """
    Produce a text verdict instead of a numeric score.
    """
    ntlm_restricted = (restrict_receiving == 2) or (restrict_sending == 2)

    # Explicit NTLM traffic blocking supersedes legacy LmCompatibilityLevel
    if ntlm_restricted:
        if audit == 2:
            return "Strong, NTLM restricted/blocked and NTLM audit enabled"
        return "Strong, NTLM restricted/blocked without NTLM auditing"

    # Worst case verdict (unless NTLMv1 SSO block prevents NTLMv1)
    if lm in [0, 1]:
        if block_ntlmv1_sso == 1:
            return "Moderate, Legacy LmCompatibilityLevel set but NTLMv1 SSO blocked"
        return "Critical, Weak NTLM policy (LM/NTLMv1 enabled)"

    # Good: Using strong NTLMv2 defaults but not hardened
    if lm in [None, 2, 3]:
        if lmhash == 0:
            return "Warning, NTLMv2 is enabled but LM hashes allowed"
        if block_ntlmv1_sso == 1:
            return "Moderate, NTLMv2 is used (NTLMv1 SSO blocked)"
        return "Moderate, NTLMv2 is used but not enforced"

    # Strongest settings
    if lm in [4, 5]:
        suffix = " (NTLMv1 SSO blocked)" if block_ntlmv1_sso == 1 else ""
        if audit == 2:
            return f"Strong, NTLMv2 enforced and NTLM audit enabled{suffix}"
        return f"Strong, NTLMv2 enforced without NTLM auditing{suffix}"

    return "Unknown NTLM configuration"

def check_ntlm_policy():
    global _ntlm_policy_cache
    global run_all_clicked
    global single_check

    if _ntlm_policy_cache is not None and not run_all_clicked and not single_check:
        return _ntlm_policy_cache

    lsa_path = r"SYSTEM\CurrentControlSet\Control\Lsa"
    msv1_0_path = r"SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"

    lm = read_reg(lsa_path, "LmCompatibilityLevel")
    lmhash = read_reg(lsa_path, "NoLMHash")
    audit = read_reg(msv1_0_path, "AuditReceivingNTLMTraffic")
    restrict_sending = read_reg(msv1_0_path, "RestrictSendingNTLMTraffic")
    if restrict_sending is None:
        restrict_sending = read_reg(lsa_path, "RestrictSendingNTLMTraffic")
    restrict_receiving = read_reg(msv1_0_path, "RestrictReceivingNTLMTraffic")
    if restrict_receiving is None:
        restrict_receiving = read_reg(lsa_path, "RestrictReceivingNTLMTraffic")
    block_ntlmv1_sso = read_reg(lsa_path, "BlockNtlmv1SSO")

    verdict_text = ntlm_verdict(
        lm,
        lmhash,
        audit,
        restrict_sending=restrict_sending,
        restrict_receiving=restrict_receiving,
        block_ntlmv1_sso=block_ntlmv1_sso,
    )

    # Return the verdict as a plain string
    _ntlm_policy_cache = verdict_text
    return _ntlm_policy_cache

# ===== Hardware Report =====
class HardwareReport:

    def _run_ps(self, ps_script):
        """Run PowerShell script safely (shell=False) and return JSON list or empty list."""
        try:
            out = subprocess.check_output(
                [_system_exe("powershell.exe"), "-NoProfile", "-NonInteractive", "-Command", ps_script],
                shell=False,
                text=True,
                encoding="utf-8",
                errors="replace",
                env=_safe_subproc_env(),
                creationflags=_CREATE_NO_WINDOW,
                startupinfo=_STARTUPINFO,
            ).strip()
            if not out:
                return []
            data = json.loads(out)
            return data if isinstance(data, list) else [data]
        except Exception:
            return []

    def scan_pnp_category(self, category_name):
        """Scan PnP devices for a specific category."""
        if not re.fullmatch(r"[A-Za-z0-9_-]+", str(category_name or "")):
            return []
        ps_script = (
            f"Get-PnpDevice -Class {category_name} | "
            "Select-Object Name,Status,InstanceId | ConvertTo-Json -Depth 2"
        )

        devices = self._run_ps(ps_script)
        unique_devices = []
        seen = set()

        for device in devices:
            instance_id = (
                device.get("InstanceId") or ""
            ).strip().casefold()

            key = instance_id or (
                (device.get("Name") or "").strip().casefold()
            )

            if key in seen:
                continue

            seen.add(key)

            unique_devices.append({
                "Name": device.get("Name"),
                "Status": device.get("Status"),
            })

        return unique_devices

    def scan_usb_devices(self):
        """Scan USB hubs."""
        ps_script = (
            "Get-CimInstance -ClassName Win32_USBHub | "
            "Select-Object DeviceID,PNPDeviceID,Description | ConvertTo-Json -Depth 2"
        )
        return self._run_ps(ps_script)

    def scan_network_adapters(self):
        """Scan network adapters and their IP addresses."""
        adapters = []
        try:
            # Adapters
            ps1 = "Get-NetAdapter | Select-Object Name,InterfaceDescription,MacAddress,Status | ConvertTo-Json -Depth 2"
            net_data = self._run_ps(ps1)
            for a in net_data:
                adapters.append({
                    "Name": a.get("Name"),
                    "Description": a.get("InterfaceDescription"),
                    "MAC": a.get("MacAddress"),
                    "Status": a.get("Status"),
                    "IPs": []
                })
            # IP addresses
            ps2 = "Get-NetIPAddress | Select-Object InterfaceAlias,IPAddress,AddressFamily | ConvertTo-Json -Depth 2"
            ip_data = self._run_ps(ps2)
            for ipinfo in ip_data:
                alias = ipinfo.get("InterfaceAlias")
                for a in adapters:
                    if a.get("Name") == alias:
                        a["IPs"].append(ipinfo.get("IPAddress"))
        except Exception:
            pass
        return adapters

    def get_hardware_report(self):
        """Return formatted report for selected device categories."""
        categories = {
            "Printers": self.scan_pnp_category("Printer") or [],
            "Cameras": self.scan_pnp_category("Camera") or [],
            "Bluetooth Devices": self.scan_pnp_category("Bluetooth") or [],
            "USB Devices": self.scan_usb_devices() or [],
            "Biometric Devices": self.scan_pnp_category("Biometric") or [],
            "Network Adapters": self.scan_network_adapters() or [],
        }

        lines = [""]

        category_keys = list(categories.keys())
        for i, category in enumerate(category_keys):
            items = categories[category]

            # Header
            lines.append(f"{category}:")

            if not items:
                lines.append("  (None)")
            else:
                seen_names = set()

                for item in items:
                    name = (
                        item.get("Name")
                        or item.get("Description")
                        or "(Unknown)"
                    )

                    key = name.strip().casefold()

                    if key in seen_names:
                        continue

                    seen_names.add(key)
                    lines.append(f"  {name}")

            # Only add separator if not the last category
            if i != len(category_keys) - 1:
                lines.append("–" * 50)

        return "\n".join(lines)

# ===== Network Settings =====
class NetworkSettings:

    def get_network_settings(self):
        """
        Get local IPs (IPv4 + IPv6), subnet masks, DNS servers,
        default gateways (IPv4 + IPv6), DHCP servers,
        MAC addresses, external IP, and Wi-Fi adapter status.
        """

        network_info = {
            "Local Ips": [],
            "Subnet Masks": [],
            "Default Gateways": [],
            "DNS Servers": [],
            "DHCP Servers": [],
            "MAC Addresses": [],
            "Wi-Fi": []
        }

        mac_pattern = re.compile(r"^([0-9A-F]{2}-){5}[0-9A-F]{2}$")

        def _normalize_mac(raw_mac):
            if not raw_mac:
                return "Unavailable"
            mac_norm = raw_mac.strip().replace(":", "-").upper()
            if (
                mac_pattern.match(mac_norm)
                and mac_norm not in ("00-00-00-00-00-00", "FF-FF-FF-FF-FF-FF")
            ):
                return mac_norm
            return "Unavailable"

        try:
            output_lines = _run_check_output(
                ["ipconfig", "/all"], shell=False
            ).splitlines()

            collecting_dns = False
            collecting_gateway = False
            current_adapter_ips = []  # list of tuples (ip, mask_or_none)
            current_adapter_has_ipv4 = False
            current_adapter_mac = None

            def _flush_adapter():
                if not current_adapter_ips:
                    return
                mac_display = _normalize_mac(current_adapter_mac)
                ips_to_emit = (
                    [
                        (ip, mask)
                        for ip, mask in current_adapter_ips
                        if ipaddress.ip_address(ip.split("/")[0]).version == 4
                    ]
                    if current_adapter_has_ipv4
                    else current_adapter_ips
                )
                for ip, mask in ips_to_emit:
                    network_info["Local Ips"].append(ip)
                    if current_adapter_has_ipv4 or mask:
                        network_info["Subnet Masks"].append(mask)
                    network_info["MAC Addresses"].append(mac_display)

            for idx, raw_line in enumerate(output_lines):
                line = raw_line.strip()

                # --- Adapter header detection ---
                if raw_line and not raw_line.startswith(" ") and "adapter" in raw_line.lower():
                    _flush_adapter()
                    # Reset per new adapter
                    current_adapter_ips = []
                    current_adapter_has_ipv4 = False
                    current_adapter_mac = None

                # --- DNS Servers (IPv4 only) ---
                if "DNS Servers" in line:
                    parts = line.split(":", 1)
                    if len(parts) > 1:
                        dns = parts[1].strip()
                        try:
                            ip_obj = ipaddress.ip_address(dns)
                            if isinstance(ip_obj, ipaddress.IPv4Address):
                                network_info["DNS Servers"].append(dns)
                        except ValueError:
                            pass
                    collecting_dns = True
                    continue

                if collecting_dns:
                    candidate = line.strip()
                    try:
                        ip_obj = ipaddress.ip_address(candidate)
                        if isinstance(ip_obj, ipaddress.IPv4Address):
                            network_info["DNS Servers"].append(candidate)
                    except ValueError:
                        collecting_dns = False

                # --- IPv4 Address ---
                if "IPv4 Address" in line:
                    ip = line.split(":")[-1].split("(")[0].strip()
                    if is_valid_ip(ip):
                        mask = "255.255.255.0"
                        for j in range(idx+1, min(idx+5, len(output_lines))):
                            l = output_lines[j].strip()
                            if "Subnet Mask" in l:
                                mask = l.split(":")[-1].strip()
                                break
                        current_adapter_ips.append((ip, mask))
                        current_adapter_has_ipv4 = True

                # --- IPv6 Address ---
                if ("IPv6 Address" in line or
                    "Temporary IPv6 Address" in line or
                    "Link-local IPv6 Address" in line):
                    parts = line.split(":", 1)
                    if len(parts) > 1:
                        ip_part = parts[1].split("(")
                        ip = ip_part[0].strip().split("%")[0]
                        if is_valid_ip(ip):
                            # default prefix
                            prefix = "64"
                            if len(ip_part) > 1 and "/" in ip_part[1]:
                                prefix = ip_part[1].split("/")[1].split(")")[0]

                            # store IP only in Local Ips
                            current_adapter_ips.append((ip, prefix))  # second element is prefix

                # --- Default Gateway ---
                if "Default Gateway" in line:
                    gw = line.split(":", 1)[-1].strip()
                    if is_valid_ip(gw):
                        network_info["Default Gateways"].append(gw)
                    collecting_gateway = True
                    continue

                if collecting_gateway:
                    if is_valid_ip(line):
                        network_info["Default Gateways"].append(line)
                    else:
                        collecting_gateway = False

                # --- DHCP Server ---
                if "DHCP Server" in line:
                    dhcp = line.split(":")[-1].strip()
                    if is_valid_ip(dhcp):
                        network_info["DHCP Servers"].append(dhcp)

                # --- Physical (MAC) Address ---
                if "Physical Address" in line and ":" in line:
                    current_adapter_mac = line.split(":", 1)[-1].strip()

            # Flush last adapter IPs and MACs
            _flush_adapter()
                            
            # ---- Wi-Fi detection (resilient to Win11 24H2-26H2 Location Privacy blocks) ----
            try:
                ps_script = (
                    "Get-NetAdapter -Physical | "
                    "Where-Object {$_.InterfaceDescription -Match 'Wireless|Wi-Fi'} | "
                    "Select-Object Name, Status | ConvertTo-Json"
                )
                adapters_json = _run_check_output(
                    ["powershell.exe", "-NoProfile", "-Command", ps_script], shell=False
                ).strip()

                adapters = json.loads(adapters_json) if adapters_json else []
                if isinstance(adapters, dict):
                    adapters = [adapters]
                elif not isinstance(adapters, list):
                    adapters = []

                ssid_interfaces = {}
                wlan_unavailable_reason = None
                try:
                    ssid_output = _run_check_output(
                        ["netsh", "wlan", "show", "interfaces"],
                        shell=False,
                        stderr=subprocess.STDOUT,
                    ).strip()
                    lower_out = ssid_output.lower()
                    if "location permission" in lower_out or "access is denied" in lower_out:
                        wlan_unavailable_reason = "Location permission required"
                    else:
                        current_name = None
                        for line in ssid_output.splitlines():
                            line = line.strip()
                            if line.startswith("Name") and ":" in line:
                                current_name = line.split(":", 1)[1].strip()
                                ssid_interfaces[current_name] = "Not Connected"
                            elif line.startswith("SSID") and ":" in line and current_name:
                                ssid_value = line.split(":", 1)[1].strip()
                                if ssid_value:
                                    ssid_interfaces[current_name] = ssid_value
                except subprocess.CalledProcessError as exc:
                    err_text = str(getattr(exc, "output", "") or exc).lower()
                    if "location permission" in err_text or "access is denied" in err_text or "error 5" in err_text:
                        wlan_unavailable_reason = "Location permission required"
                    else:
                        wlan_unavailable_reason = "SSID unavailable"
                except Exception:
                    wlan_unavailable_reason = "SSID unavailable"

                for adapter in adapters:
                    if not isinstance(adapter, dict):
                        continue
                    name = adapter.get("Name")
                    status = str(adapter.get("Status") or "Unknown")
                    if not name:
                        continue
                    adapter_str = f"{name} ({status})"

                    if status.lower() == "up":
                        if wlan_unavailable_reason:
                            adapter_str += f" - Up (SSID unavailable: {wlan_unavailable_reason})"
                        else:
                            ssid = ssid_interfaces.get(name, "Not Connected")
                            if ssid != "Not Connected":
                                adapter_str += f" - Connected ({ssid})"
                            else:
                                adapter_str += " - Not Connected"
                    elif status.lower() == "disabled":
                        adapter_str += " - Disabled"
                    else:
                        adapter_str += " - Not Connected"

                    network_info["Wi-Fi"].append(adapter_str)

                if not network_info["Wi-Fi"]:
                    network_info["Wi-Fi"].append("No adapters detected")

            except Exception:
                network_info["Wi-Fi"].append("No adapters detected")

        except Exception:
            pass

        # ---- Formatting unchanged ----
        report = [""]
        keys_order = [
            "MAC Addresses",
            "Local Ips",
            "Subnet Masks",
            "Default Gateways",
            "DHCP Servers",
            "DNS Servers",
            "Wi-Fi"
        ]
        
        for i, key in enumerate(keys_order):
            if key in network_info:
                report.append(f"{key}:")
                value = network_info[key]

                if isinstance(value, list):
                    for item in value:
                        report.append(f"  {item}")
                else:
                    report.append(f"  {value}")

                if i != len(keys_order) - 1:
                    report.append("–" * 50)

        return "\n".join(report)

# ===== Shared Folders =====
class SharedFolders:

    # --- Resolve SID to account name ---
    def resolve_sid(self, sid_str):
        try:
            sid = win32security.ConvertStringSidToSid(sid_str)
            name, domain, _ = win32security.LookupAccountSid(None, sid)
            return f"{domain}\\{name}" if domain else name
        except Exception:
            return sid_str

    # --- Get permissions for a folder ---
    def get_permissions(self, folder_path):
        perms = []
        everyone_detected = False
        try:
            sd = win32security.GetFileSecurity(folder_path, win32security.DACL_SECURITY_INFORMATION)
            dacl = sd.GetSecurityDescriptorDacl()
            if dacl:
                allow_types = {win32security.ACCESS_ALLOWED_ACE_TYPE}
                deny_types = {win32security.ACCESS_DENIED_ACE_TYPE}
                object_types = set()
                if hasattr(win32security, "ACCESS_ALLOWED_OBJECT_ACE_TYPE"):
                    allow_types.add(win32security.ACCESS_ALLOWED_OBJECT_ACE_TYPE)
                    object_types.add(win32security.ACCESS_ALLOWED_OBJECT_ACE_TYPE)
                if hasattr(win32security, "ACCESS_DENIED_OBJECT_ACE_TYPE"):
                    deny_types.add(win32security.ACCESS_DENIED_OBJECT_ACE_TYPE)
                    object_types.add(win32security.ACCESS_DENIED_OBJECT_ACE_TYPE)
                inherit_only_flag = getattr(win32security, "INHERIT_ONLY_ACE", 0x8)

                for i in range(dacl.GetAceCount()):
                    try:
                        ace = dacl.GetAce(i)
                        ace_type, ace_flags = ace[0]
                        if ace_type not in allow_types and ace_type not in deny_types:
                            continue
                        if ace_flags & inherit_only_flag:
                            continue

                        access_mask = ace[1]
                        sid = ace[4] if (ace_type in object_types and len(ace) >= 5) else ace[2]
                        sid_str = win32security.ConvertSidToStringSid(sid)
                        account = self.resolve_sid(sid_str)
                    except (TypeError, IndexError, win32security.error):
                        continue

                    if ace_type in deny_types:
                        if not account.startswith("NT AUTHORITY\\"):
                            perms.append(f"{account}: Denied")
                        continue

                    # Check for Everyone (S-1-1-0) on allow ACEs only
                    if sid_str == "S-1-1-0":
                        everyone_detected = True

                    if account.startswith("NT AUTHORITY\\"):
                        continue  # skip these accounts

                    rights = []
                    if (access_mask & con.FILE_ALL_ACCESS) == con.FILE_ALL_ACCESS:
                        rights = ["Full Control"]
                    else:
                        if (access_mask & con.FILE_GENERIC_READ) == con.FILE_GENERIC_READ:
                            rights.append("Read")
                        if (access_mask & con.FILE_GENERIC_WRITE) == con.FILE_GENERIC_WRITE:
                            rights.append("Write")
                        if (access_mask & con.FILE_GENERIC_EXECUTE) == con.FILE_GENERIC_EXECUTE:
                            rights.append("Execute")

                    perms.append(f"{account}: {', '.join(rights) if rights else 'Special Permissions'}")
            else:
                perms.append("(No DACL)")
        except Exception as e:
            perms.append(f"(Unable to read ACL: {e})")
        return perms, everyone_detected

    # --- Get shared folders with Everyone check ---
    def get_shared_folders(self):
        output = [""]
        shares_data = []
        com_initialized = False

        try:
            try:
                pythoncom.CoInitialize()
                com_initialized = True
            except pythoncom.com_error as ce:
                # RPC_E_CHANGED_MODE: thread already initialized with another apartment model
                if ce.hresult != -2147417850:
                    raise

            c = wmi.WMI()
            admin = is_admin()
            for s in c.Win32_Share():
                if s.Name.upper() in ("ADMIN$", "IPC$"):
                    continue

                if admin and s.Path:
                    permissions, everyone_flag = self.get_permissions(s.Path)
                else:
                    permissions = ["(Access denied)"]
                    everyone_flag = False

                shares_data.append({
                    "Name": s.Name,
                    "Path": s.Path or "",
                    "Description": s.Description or "None",
                    "Permissions": permissions,
                    "Everyone": everyone_flag
                })

        except Exception as e:
            output.append(f"Error: {e}")
            return "\n".join(output)
        finally:
            if com_initialized:
                try:
                    pythoncom.CoUninitialize()
                except Exception:
                    pass

        if not shares_data:
            output.append("No shared folders found.")
        else:
            for i, share in enumerate(shares_data):
                output.append(f"Share Name : {share['Name']}")
                output.append(f"Path       : {share['Path']}")
                output.append(f"Description: {share['Description']}")
                output.append("Permissions:")
                for perm in share["Permissions"]:
                    output.append(f"  {perm}")
                if share["Everyone"]:
                    output.append("⚠️ Warning: Folder accessible by Everyone!")
                
                # Only add the separator if not the last share
                if i != len(shares_data) - 1:
                    output.append("–" * 50)

        return "\n".join(output)

# ===== Gateway Discovery =====
class GatewayDiscovery:

    def get_default_gateway(self):
        global _gateway_ip_cache
        global run_all_clicked
        global single_check

        # Return cached result
        if _gateway_ip_cache is not None and not run_all_clicked and not single_check:
            return None if _gateway_ip_cache is _NOT_FOUND else _gateway_ip_cache

        try:
            output_lines = _run_check_output(
                ["ipconfig", "/all"], shell=False
            ).splitlines()

            gateways = {"IPv4": None, "IPv6": None}
            collecting_gateway = False

            for raw_line in output_lines:
                line = raw_line.strip()

                if "Default Gateway" in line:
                    gw = line.split(":", 1)[-1].strip()

                    if is_valid_ip(gw):
                        if ":" in gw:
                            gateways["IPv6"] = gw.split("%")[0]
                        else:
                            gateways["IPv4"] = gw

                    collecting_gateway = True
                    continue

                if collecting_gateway:
                    if is_valid_ip(line):
                        if ":" in line:
                            gateways["IPv6"] = line.split("%")[0]
                        else:
                            gateways["IPv4"] = line
                    else:
                        collecting_gateway = False

            # Nothing found
            if not gateways["IPv4"] and not gateways["IPv6"]:
                _gateway_ip_cache = _NOT_FOUND
                return None

            # Cache successful result
            _gateway_ip_cache = gateways
            return _gateway_ip_cache

        except Exception:
            _gateway_ip_cache = _NOT_FOUND
            return None

    def ping_device(self, ip):
        """Ping IPv4 or IPv6 device."""
        try:
            system = platform.system().lower()

            if ":" in ip:  # IPv6
                param = "-n" if system == "windows" else "-c"
                cmd = [_system_exe("ping"), "-6", param, "1", ip]
            else:  # IPv4
                param = "-n" if system == "windows" else "-c"
                cmd = [_system_exe("ping"), param, "1", ip]

            result = subprocess.run(cmd, capture_output=True, text=True, env=_safe_subproc_env(), creationflags=_CREATE_NO_WINDOW, startupinfo=_STARTUPINFO)
            output = result.stdout.strip()

            for line in output.splitlines():
                line = line.strip()
                if line.startswith("Reply from") or "TTL=" in line or "time=" in line:
                    return line
                if "Request timed out" in line:
                    return "Request timed out"

            return "No response"

        except Exception as e:
            return f"Ping failed: {e}"

    def get_mac_from_arp(self, ip):
        """Get MAC address for IPv4 only."""
        global _gateway_mac_cache
        global run_all_clicked
        global single_check

        if not ip or ":" in str(ip):
            return None  # IPv6 → no ARP

        ip_key = str(ip).strip()

        if (
            ip_key in _gateway_mac_cache
            and not run_all_clicked
            and not single_check
        ):
            cached = _gateway_mac_cache[ip_key]
            return None if cached is _NOT_FOUND else cached

        try:
            output = _run_check_output(["arp", "-a"], shell=False)

            for line in output.splitlines():

                if ip_key in line:

                    mac_match = re.search(
                        r"([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}",
                        line
                    )

                    if mac_match:
                        # Keep Windows' original hyphen format
                        _gateway_mac_cache[ip_key] = mac_match.group(0).upper()
                        return _gateway_mac_cache[ip_key]

        except Exception:
            pass

        print(f"Gateway IP: {ip_key}")
        print("Gateway MAC: None")
        
        _gateway_mac_cache[ip_key] = _NOT_FOUND
        return None

    def detect_management_ports(self, ip):
        """
        Detect accessible TCP management ports on the gateway.

        Port 80 is classified as:
            HTTP Redirected - redirects requests to HTTPS.
            HTTP Exposed    - does not redirect to HTTPS.

        Returns:
            Detected management ports
            No common management ports detected
            Unable to scan
        """
        global _management_ports_cache
        global run_all_clicked
        global single_check

        ip_key = str(ip or "").strip()
        if not ip_key:
            return "Unable to scan"

        # Return cached result
        if (
            ip_key in _management_ports_cache
            and not run_all_clicked
            and not single_check
        ):
            return _management_ports_cache[ip_key]

        # Common gateway management services
        management_ports = {
            22: "SSH",
            23: "Telnet Exposed",
            80: "HTTP Exposed",
            443: "HTTPS",
            2222: "SSH (Alternative)",
            4443: "HTTPS (Alternative)",
            7547: "TR-069",
            8080: "HTTP Exposed",
            8291: "MikroTik Winbox",
            8443: "HTTPS (Alternative)",
            8728: "MikroTik API Exposed",
            8729: "MikroTik API-SSL",
            9443: "HTTPS Management",
            10000: "Webmin",
            10443: "HTTPS Management"
        }

        def check_port(port):
            try:
                with socket.create_connection((ip, port), timeout=0.7):
                    return port
            except (socket.timeout, ConnectionRefusedError, OSError):
                return None

        def check_http_redirect(ip):
            """Check whether HTTP redirects to HTTPS."""
            try:
                with requests.Session() as session:
                    session.trust_env = False

                    response = session.get(
                        f"http://{ip}/",
                        timeout=(0.7, 1.5),
                        allow_redirects=False,
                        stream=True
                    )

                    location = response.headers.get("Location", "")
                    response.close()

                    if (
                        response.status_code in (301, 302, 303, 307, 308)
                        and location.lower().startswith("https://")
                    ):
                        return True

            except requests.RequestException:
                pass

            return False

        try:
            # Concurrent TCP connection checks
            with ThreadPoolExecutor(max_workers=10) as executor:
                results = executor.map(
                    check_port,
                    management_ports.keys()
                )

                open_ports = [
                    port for port in results
                    if port is not None
                ]

            if not open_ports:
                _management_ports_cache[ip_key] = "No common management ports detected"
                return _management_ports_cache[ip_key]

            # Sort ports numerically
            open_ports.sort()

            detected = []

            for port in open_ports:
                service = management_ports[port]

                # Check whether HTTP redirects to HTTPS
                if port == 80:
                    if check_http_redirect(ip_key):
                        service = "HTTP Redirected"

                detected.append(f"{service} ({port})")

            _management_ports_cache[ip_key] = ", ".join(detected)
            return _management_ports_cache[ip_key]

        except Exception as e:
            print(f"Management port detection error: {e}")
            _management_ports_cache[ip_key] = "Unable to scan"
            return _management_ports_cache[ip_key]

    def get_network_cidr(self):
        """Get the active network interface's IPv4 CIDR."""

        try:
            gateways = self.get_default_gateway()
            if not gateways:
                return "Unavailable"

            gateway_ip = gateways.get("IPv4")
            if not gateway_ip:
                return "IPv6 Only / Unavailable"

            for interface, addrs in psutil.net_if_addrs().items():

                for addr in addrs:

                    if addr.family != socket.AF_INET:
                        continue

                    if not addr.address or not addr.netmask:
                        continue

                    try:
                        interface_ip = ipaddress.ip_address(addr.address)

                        if interface_ip.is_loopback or interface_ip.is_link_local:
                            continue

                        network = ipaddress.IPv4Network(
                            f"{addr.address}/{addr.netmask}",
                            strict=False
                        )

                        if ipaddress.ip_address(gateway_ip) in network:
                            return str(network)

                    except ValueError:
                        continue

            return "Unavailable"

        except Exception as e:
            print(f"Network CIDR error: {e}")
            return "Unable to determine"

    def get_interface_mtu(self):
        """Get MTU of the interface associated with the default gateway."""

        try:
            gateways = self.get_default_gateway()
            if not gateways:
                return "Unavailable"

            gateway_ip = gateways.get("IPv4")

            if not gateway_ip:
                return "IPv6 Only / Unavailable"

            command = (
                "Get-NetRoute -DestinationPrefix '0.0.0.0/0' "
                "| Where-Object {$_.NextHop -eq '" + gateway_ip + "'} "
                "| Get-NetIPInterface "
                "| Select-Object -First 1 -ExpandProperty NlMtu"
            )

            output = subprocess.check_output(
                [_system_exe("powershell.exe"), "-NoProfile", "-Command", command],
                text=True,
                stderr=subprocess.DEVNULL,
                env=_safe_subproc_env(),
                creationflags=_CREATE_NO_WINDOW,
                startupinfo=_STARTUPINFO,
                timeout=5
            ).strip()

            if output.isdigit():
                return f"{output} bytes"

            return "Unavailable"

        except Exception as e:
            print(f"MTU detection error: {e}")
            return "Unable to determine"

    def get_proxy_configuration(self):
        """Detect Windows user and WinHTTP proxy configuration."""

        try:
            settings_path = (
                r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
            )

            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                settings_path
            ) as key:

                def read_value(name, default=None):
                    try:
                        return winreg.QueryValueEx(key, name)[0]
                    except OSError:
                        return default

                proxy_enabled = read_value("ProxyEnable", 0)
                proxy_server = read_value("ProxyServer")
                auto_config_url = read_value("AutoConfigURL")
                auto_detect = read_value("AutoDetect", 0)

            configurations = []

            if proxy_enabled and proxy_server:
                configurations.append(
                    f"Manual Proxy: {proxy_server}"
                )

            if auto_config_url:
                configurations.append(
                    f"PAC: {auto_config_url}"
                )

            if auto_detect:
                configurations.append("Automatic Proxy Detection: Enabled")

            # Check WinHTTP configuration separately
            try:
                winhttp = subprocess.check_output(
                    [_system_exe("netsh"), "winhttp", "show", "proxy"],
                    text=True,
                    stderr=subprocess.DEVNULL,
                    env=_safe_subproc_env(),
                    creationflags=_CREATE_NO_WINDOW,
                    startupinfo=_STARTUPINFO,
                    timeout=5
                )

                if "Direct access" in winhttp:
                    winhttp_result = "Direct Access"
                else:
                    proxy_match = re.search(
                        r"Proxy Server\(s\)\s*:\s*(.+)",
                        winhttp,
                        re.IGNORECASE
                    )

                    if proxy_match:
                        winhttp_result = proxy_match.group(1).strip()
                    else:
                        winhttp_result = "Configured / Unknown"

                configurations.append(
                    f"WinHTTP: {winhttp_result}"
                )

            except Exception:
                configurations.append("WinHTTP: Unable to determine")

            if not configurations:
                return "No Proxy Detected"

            return "\n".join(configurations)

        except Exception as e:
            print(f"Proxy detection error: {e}")
            return "Unable to determine"

    def classify_gateway_device(self, vendor, fingerprint_text=""):
        """
        Identify gateway device type.

        Supported types:
            Firewall
            Router
            Security Gateway
            Switch
            Wireless Access Point
            Wireless Controller
            Modem
            ONT
            VPN Gateway
            SD-WAN Gateway
            Load Balancer
            Proxy Gateway
            Cellular Gateway
            Other Type
            Unknown

        Uses product fingerprints first, then manufacturer-based
        fallback classification.
        """

        if not vendor or vendor == "Unknown":
            return "Unknown"

        vendor_lower = vendor.lower()
        fingerprint = (fingerprint_text or "").lower()

        # 1. PRODUCT FINGERPRINT IDENTIFICATION

        # Fortinet
        if any(x in fingerprint for x in (
            "fortigate",
            "fortios"
        )):
            return "Firewall"

        # Cisco
        if any(x in fingerprint for x in (
            "cisco adaptive security appliance",
            "cisco asa",
            "firepower"
        )):
            return "Firewall"

        if any(x in fingerprint for x in (
            "cisco ios",
            "integrated services router"
        )):
            return "Router"

        # Palo Alto
        if any(x in fingerprint for x in (
            "pan-os",
            "palo alto networks"
        )):
            return "Firewall"

        # Check Point
        if any(x in fingerprint for x in (
            "gaia portal",
            "check point"
        )):
            return "Firewall"

        # SonicWall
        if "sonicwall" in fingerprint:
            return "Firewall"

        # WatchGuard
        if any(x in fingerprint for x in (
            "fireware",
            "watchguard"
        )):
            return "Firewall"

        # MikroTik
        if any(x in fingerprint for x in (
            "mikrotik",
            "routeros"
        )):
            return "Router"

        # Ubiquiti
        if any(x in fingerprint for x in (
            "unifi security gateway",
            "unifi dream machine",
            "edgeos"
        )):
            return "Security Gateway"

        # 2. MANUFACTURER-BASED CLASSIFICATION

        # Firewall manufacturers
        firewall_vendors = (
            "fortinet",
            "palo alto",
            "check point",
            "sonicwall",
            "watchguard",
            "sophos",
            "barracuda"
        )

        if any(x in vendor_lower for x in firewall_vendors):
            return "Firewall"

        # Router manufacturers
        router_vendors = (
            "mikrotik",
            "draytek",
            "asus",
            "avm"
        )

        if any(x in vendor_lower for x in router_vendors):
            return "Router"

        # 3. UNKNOWN MANUFACTURER CATEGORY

        return "Other Type"

    def lookup_vendor(self, mac, device_ip=None, fingerprint_text=""):
        """
        Lookup vendor from MAC address.

        1. Check for locally administered / virtual MACs.
        2. Lookup OUI in local oui.csv.
        3. Use TTL heuristic only when vendor is unknown.
        4. Classify gateway device type using fingerprints.

        Device classification:
            Vendor (Firewall)
            Vendor (Router)
            Vendor (Other Type)

        Cache stores raw vendor information.
        """

        global _mac_vendor_cache
        global run_all_clicked
        global single_check

        if not mac:
            print("Vendor lookup: MAC is None")
            return "Unknown"

        # Keep MAC in Windows format
        mac_key = mac.strip().upper()

        vendor = "Unknown"

        # Check cached vendor
        if (
            mac_key in _mac_vendor_cache
            and not run_all_clicked
            and not single_check
        ):
            vendor = _mac_vendor_cache[mac_key]

        else:

            # Check for locally administered MAC
            try:
                first_byte = int(
                    mac_key.split("-")[0].split(":")[0],
                    16
                )

                if first_byte & 0b00000010:
                    vendor = "Virtual/Software MAC"

            except Exception:
                pass

            # OUI lookup
            if vendor == "Unknown":

                # Windows:
                # 90-6C-AC-A9-6E-ED
                #
                # OUI:
                # 90-6C-AC
                oui = mac_key[:8]

                oui_database = load_oui_database()

                vendor = oui_database.get(oui, "Unknown")

            # TTL-based fallback
            if vendor == "Unknown" and device_ip:

                try:
                    reply = self.ping_device(device_ip)

                    ttl_match = re.search(
                        r"TTL=(\d+)",
                        reply,
                        re.IGNORECASE
                    )

                    if ttl_match:

                        ttl = int(ttl_match.group(1))

                        if ttl <= 64:
                            vendor = "Likely Linux/Unix device"

                        elif ttl <= 128:
                            vendor = "Likely Windows device"

                        elif ttl <= 255:
                            vendor = "Likely network appliance / router"

                except Exception as e:
                    print(f"TTL lookup error: {e}")

            # Cache raw vendor
            _mac_vendor_cache[mac_key] = vendor

        # Skip classification for special results
        if vendor in (
            "Unknown",
            "Virtual/Software MAC",
            "Likely Linux/Unix device",
            "Likely Windows device",
            "Likely network appliance / router"
        ):
            return vendor

        # Gateway device type classification
        device_type = self.classify_gateway_device(
            vendor,
            fingerprint_text
        )

        return f"{vendor} ({device_type})"

    def check_http_access(self, ip):
        """Check HTTP/HTTPS for IPv4 or IPv6."""
        for scheme in ["http", "https"]:
            try:
                if ":" in ip:  # IPv6
                    url = f"{scheme}://[{ip}]"
                else:
                    url = f"{scheme}://{ip}"

                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", InsecureRequestWarning)
                    r = requests.get(url, timeout=3, verify=False)
                if r.status_code < 500:
                    return f"{scheme.upper()} Responding ({r.status_code})"
            except Exception:
                continue
        return "No web interface detected"

    def detect_nat(self):
        """
        Detect NAT by comparing local and external IPs.
        Fully independent: retrieves local and external IPs itself.

        Returns:
            str: NAT detection result.
        """
        global _nat_cache
        global run_all_clicked
        global single_check

        if _nat_cache is not None and not run_all_clicked and not single_check:
            return _nat_cache

        try:
            # --- Get local IPs via ipconfig ---
            output = _run_check_output(["ipconfig"], shell=False)
            local_ips = []
            for line in output.splitlines():
                line = line.strip()
                if "IPv4 Address" in line:
                    ip = line.split(":")[-1].split("(")[0].strip()
                    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
                        local_ips.append(ip)

            # --- Get external IP ---
            try:
                external_ip = requests.get('https://api.ipify.org', timeout=5).text.strip()
            except Exception:
                external_ip = "Unavailable"

            # --- NAT Detection ---
            if not local_ips or external_ip == "Unavailable":
                _nat_cache = "Unable to determine"
                return _nat_cache

            local_ip = local_ips[0]
            if local_ip != external_ip:
                _nat_cache = "Detected"
            else:
                _nat_cache = "NoDetect"
            return _nat_cache

        except Exception:
            _nat_cache = "Error during detection"
            return _nat_cache

    def get_external_ip(self):
        """Discover external/public IP."""
        try:
            return requests.get("https://api.ipify.org", timeout=5).text.strip()
        except Exception:
            return "Unavailable"

    def detect_gateway_device(self):
        """Main detection routine — returns a dict with gateway info."""
        result = {
            "Vendor": "Unknown",
            "MAC": "Unknown",
            "IP": "Unavailable",
            "PING": "Unknown",
            "Network CIDR": "Unknown",
            "MTU": "Unknown",
            "GUI": "Unknown",
            "Proxy Configuration": "Unknown",
            "Management Ports": "Unknown",
            "NAT": "Unknown",
            "VPN": "Unknown",
            "Public IP": "Unavailable"
        }

        gateways = self.get_default_gateway()
        if not gateways:
            result["IP"] = "Not Found"
            return result

        gw_ip = gateways.get("IPv4") or gateways.get("IPv6")

        # Gather gateway info
        result["IP"] = gw_ip
        result["Public IP"] = self.get_external_ip()
        result["PING"] = self.ping_device(gw_ip)

        mac = self.get_mac_from_arp(gw_ip)
        result["MAC"] = mac if mac else "Unknown"
        result["Vendor"] = self.lookup_vendor(mac)
        result["NAT"] = self.detect_nat()
        result["Management Ports"] = self.detect_management_ports(gw_ip)
        result["Network CIDR"] = self.get_network_cidr()
        result["MTU"] = self.get_interface_mtu()
        result["GUI"] = self.check_http_access(gw_ip)
        result["Proxy Configuration"] = self.get_proxy_configuration()
        
        # --- VPN Client check ---
        result["VPN"] = NetStatus().get_vpn_connection(
            keywords=("vpn", "ppp", "tap", "tun"),
            not_found_label="Not Detected",
        )

        output = [""]  # optional blank line at top
        keys = list(result.keys())

        for key in keys:
            value = result[key]

            # Treat dict values and single values uniformly
            if isinstance(value, dict):
                items = value.items()
            else:
                items = [(key, value)]

            sub_keys = list(items)
            for j, (sub_key, sub_value) in enumerate(sub_keys):
                output.append(f"{sub_key}: {sub_value}")
                if j != len(sub_keys) - 1:
                    output.append("–" * 50)

            # Optional separator between sections
            output.append("–" * 50)
        
        return "\n".join(output)

# ===== System Settings =====
class SystemSettings:

    # --- Get Windows Edition ---
    def _get_windows_edition(self):
        info = get_local_windows_info()
        if not info:
            return "Unknown"

        product = info["ProductName"]
        if "server" in product.casefold():
            return product

        os_name = get_windows_os_name(product, info["Build"])
        edition_name = get_windows_edition(info["EditionID"])
        return f"{os_name} {edition_name}"

    def _get_firmware_type(self):
        try:
            class FIRMWARE_TYPE(ctypes.c_int):
                pass

            firmware_type = FIRMWARE_TYPE()

            get_firmware_type = ctypes.windll.kernel32.GetFirmwareType
            get_firmware_type.argtypes = [ctypes.POINTER(FIRMWARE_TYPE)]
            get_firmware_type.restype = ctypes.c_bool

            if get_firmware_type(ctypes.byref(firmware_type)):
                return {
                    1: "BIOS",
                    2: "UEFI",
                }.get(firmware_type.value, "Unknown")

            return "Unknown"

        except (AttributeError, OSError):
            return "Unknown"

    def _get_bios_info(self):
        return _get_cim_value("Win32_BIOS", "SMBIOSBIOSVersion")

    # --- Collect basic OS and Resources info using platform module ---
    def get_system_settings(self):
        os_name = platform.system()
        os_release = platform.release()
        windows_edition = self._get_windows_edition()

        unified_os = (
            windows_edition
            if os_name == "Windows" and windows_edition != "Unknown"
            else f"{os_name}{os_release}"
        )
                
        firmware_type = self._get_firmware_type()
        bios_version = self._get_bios_info()

        firmware_version = (
            f"{firmware_type} {bios_version.split(' - ')[-1]}"
            if firmware_type != "Unknown" and bios_version != "Unknown"
            else bios_version
        )

        # --- Gather resources info ---
        memory = psutil.virtual_memory()
        cpu_freq = psutil.cpu_freq()

        machine_arch = (platform.machine() or "").strip().upper()
        resources = {
            "Machine": platform.machine(),
            "Processor": platform.processor() or "Unknown",
            "Architecture": (
                "ARM64"
                if machine_arch in ("ARM64", "AARCH64")
                else ("x64" if platform.architecture()[0] == "64bit" else "x86")
            ),
            "CPU Cores": psutil.cpu_count(logical=False),
            "Threads": psutil.cpu_count(logical=True),
            "CPU Frequency (MHz)": (
                round(cpu_freq.current) if cpu_freq else "Unknown"
            ),
            "RAM (GB)": round(memory.total / (1024**3), 2),
        }

        # --- Gather disks info safely ---
        disks = {}

        for part in psutil.disk_partitions(all=False):
            try:
                usage = psutil.disk_usage(part.mountpoint)

                disks[part.device] = {
                    "Mountpoint": part.mountpoint,
                    "File System": part.fstype,
                    "Total (GB)": round(usage.total / (1024**3), 2),
                    "Used (GB)": round(usage.used / (1024**3), 2),
                    "Free (GB)": round(usage.free / (1024**3), 2),
                    "Usage %": usage.percent,
                }

            except (PermissionError, FileNotFoundError, OSError):
                # Skip drives that are not ready or accessible
                continue

        return {
            "Hostname": socket.gethostname(),
            "OS": unified_os,
            "Firmware": firmware_version,
            "Resources": resources,
            "Disks": disks,
        }

    def format_system_settings(self, settings):
        output = [""]  # Upperline added
        keys = list(settings.keys())

        for i, key in enumerate(keys):
            value = settings[key]

            if isinstance(value, dict):
                # Add section header (special handling for Resources and Disks)
                if key == "Resources":
                    # Standard Resources section
                    output.append("–" * 50)
                    output.append(f"{key}:")
                    output.append("")
                elif key == "Disks":
                    # Always add a separator before Disks (even if after Resources)
                    output.append("–" * 50)
                    output.append(f"{key}:")
                    output.append("")
                else:
                    output.append(f"{key}:")

                sub_keys = list(value.keys())
                for j, (sub_key, sub_value) in enumerate(value.items()):
                    if isinstance(sub_value, dict):
                        output.append(f"{sub_key}:")
                        for k, v in sub_value.items():
                            output.append(f"  {k}: {v}")
                        # Separator between disks (except last)
                        if key == "Disks" and j != len(sub_keys) - 1:
                            output.append("–" * 50)
                    else:
                        output.append(f"{sub_key}: {sub_value}")

                # Section separator for non-Disk/Resource sections (except last)
                if key not in ("Disks", "Resources") and i != len(keys) - 1:
                    output.append("–" * 50)

            else:
                output.append(f"{key}: {value}")
                # Add separator if not last and next isn’t Resources/Disks
                if i != len(keys) - 1 and keys[i + 1] not in ("Resources", "Disks"):
                    output.append("–" * 50)

        return "\n".join(output)

    def get_formatted_system_settings(self):
        """Call get_system_settings and return formatted string"""
        settings = self.get_system_settings()
        return self.format_system_settings(settings)

# ===== Installed Apps =====
class InstalledApps:

    # --- Get installed applications from the Windows registry ---
    def get_installed_apps(self):
        """Get installed applications (32-bit + 64-bit), sorted A–Z."""

        apps = set()

        targets = [
            (
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                winreg.KEY_READ | winreg.KEY_WOW64_64KEY
            ),
            (
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                winreg.KEY_READ | winreg.KEY_WOW64_32KEY
            ),
            (
                winreg.HKEY_CURRENT_USER,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                winreg.KEY_READ
            )
        ]

        for root, subkey, access in targets:
            try:
                with winreg.OpenKey(root, subkey, 0, access) as hkey:
                    subkey_count = winreg.QueryInfoKey(hkey)[0]

                    for i in range(subkey_count):
                        try:
                            skey_name = winreg.EnumKey(hkey, i)

                            with winreg.OpenKey(hkey, skey_name) as skey:
                                try:
                                    app_name, _ = winreg.QueryValueEx(
                                        skey, "DisplayName"
                                    )

                                    if isinstance(app_name, str):
                                        app_name = app_name.strip()

                                        if app_name:
                                            apps.add(app_name)

                                except (FileNotFoundError, OSError):
                                    continue

                        except (FileNotFoundError, OSError):
                            continue

            except OSError:
                continue

        apps = sorted(apps, key=str.casefold)

        # --- Formatting WITH spacing ---
        output = [""]

        if apps:
            for app in apps:
                output.append(f"- {app}")
        else:
            output.append("No applications found.")

        return "\n".join(output)

# ===== Security Settings =====
class SecuritySettings:

    # --- Get the basic security settings ---
    # --- BitLocker check ---
    def check_bitlocker(self):
        """Return 'Enabled' if any volume is protected, 'Disabled' if off, or 'Unknown'."""
        try:
            output = subprocess.check_output(
                [
                    _system_exe("powershell.exe"),
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "Get-BitLockerVolume -ErrorAction Stop | Select-Object -ExpandProperty ProtectionStatus",
                ],
                shell=False, text=True, errors="ignore",
                stderr=subprocess.DEVNULL,
                env=_safe_subproc_env(),
                creationflags=_CREATE_NO_WINDOW,
                startupinfo=_STARTUPINFO,
            ).strip().splitlines()
            statuses = {line.strip().lower() for line in output if line.strip()}
            if statuses & {"1", "on"}:
                return "Enabled"
            if statuses & {"0", "off"}:
                return "Disabled"
        except Exception:
            pass

        # Fallback without requiring admin privileges via Shell.Application
        try:
            ps_shell = (
                "$s = New-Object -ComObject Shell.Application; "
                "Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object { "
                "$p = ($_.DeviceID + '\\'); "
                "$s.NameSpace($p).Self.ExtendedProperty('System.Volume.BitLockerProtection') }"
            )
            output = subprocess.check_output(
                [_system_exe("powershell.exe"), "-NoProfile", "-NonInteractive", "-Sta", "-Command", ps_shell],
                text=True, errors="ignore",
                stderr=subprocess.DEVNULL,
                env=_safe_subproc_env(),
                creationflags=_CREATE_NO_WINDOW,
                startupinfo=_STARTUPINFO,
            ).strip().splitlines()
            vals = set()
            for line in output:
                s = line.strip()
                if s.isdigit():
                    vals.add(int(s))
            if vals & {1, 3, 6, 7}:
                return "Enabled"
            if vals:
                return "Disabled"
        except Exception:
            pass

        return "Unknown"

    # --- Helper: detect system restore ---
    def check_system_restore(self):
        """
        Check if System Restore is enabled.
        Returns: str ("Enabled", "Disabled", "Unusable (Server)", or "Unknown").
        """
        try:
            with winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE) as hklm:
                # 1. Group Policy override takes precedence
                policy_path = r"SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore"
                try:
                    with winreg.OpenKey(hklm, policy_path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as pkey:
                        for val_name in ("DisableSR", "DisableConfig"):
                            try:
                                val, _ = winreg.QueryValueEx(pkey, val_name)
                                if int(val) == 1:
                                    return "Disabled"
                            except (FileNotFoundError, TypeError, ValueError):
                                continue
                except FileNotFoundError:
                    pass

                # 2. Local SystemRestore configuration (client editions only)
                key_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore"
                try:
                    with winreg.OpenKey(hklm, key_path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
                        try:
                            disable_sr, _ = winreg.QueryValueEx(key, "DisableSR")
                            return "Disabled" if int(disable_sr) == 1 else "Enabled"
                        except (FileNotFoundError, TypeError, ValueError):
                            pass

                        # Modern Windows 10/11 omits DisableSR and toggles RPSessionInterval (0 = Off, >=1 = On)
                        try:
                            rp_interval, _ = winreg.QueryValueEx(key, "RPSessionInterval")
                            return "Enabled" if int(rp_interval) >= 1 else "Disabled"
                        except (FileNotFoundError, TypeError, ValueError):
                            pass
                except FileNotFoundError:
                    return "Unusable (Server)"
        except Exception:
            return "Unknown"

        # 3. Fallback: check if the System Restore service (SDRSVC) is explicitly disabled
        sc_out = _run(["sc", "qc", "SDRSVC"]).upper()
        if "DISABLED" in sc_out:
            return "Disabled"

        return "Unknown"

    # --- Helper: detect secure boot ---
    def check_secure_boot(self):
        """
        Secure Boot detection without admin rights.
        Priority:
          1. Registry (user-readable)
          2. WMI CIM fallback
        Returns: Enabled / Disabled / Unsupported / Unknown
        """
        # --- 1) Try registry (works on all modern Windows, no admin needed) ---
        try:
            reg_script = (
                "Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State' "
                "-Name UEFISecureBootEnabled | Select-Object -ExpandProperty UEFISecureBootEnabled"
            )

            output = subprocess.check_output(
                [_system_exe("powershell.exe"), "-NoProfile", "-NonInteractive", "-Command", reg_script],
                shell=False, text=True, encoding="utf-8",
                stderr=subprocess.STDOUT,
                env=_safe_subproc_env(),
                creationflags=_CREATE_NO_WINDOW,
                startupinfo=_STARTUPINFO,
            ).strip()

            if output == "1":
                return "Enabled"
            if output == "0":
                return "Disabled"
        except subprocess.CalledProcessError as e:
            # Registry path missing = unsupported BIOS / Legacy boot
            if "cannot find path" in str(e.output).lower():
                pass  # fallback to WMI
            else:
                pass

        # --- 2) Fallback: WMI SecureBoot class (usually works, but not always installed) ---
        try:
            wmi_script = (
                "Get-CimInstance -Namespace root\\Microsoft\\Windows\\HardwareManagement "
                "-ClassName MS_SecureBoot | Select-Object -ExpandProperty SecureBootEnabled"
            )

            wmi_output = subprocess.check_output(
                [_system_exe("powershell.exe"), "-NoProfile", "-NonInteractive", "-Command", wmi_script],
                shell=False, text=True, encoding="utf-8",
                stderr=subprocess.STDOUT,
                env=_safe_subproc_env(),
                creationflags=_CREATE_NO_WINDOW,
                startupinfo=_STARTUPINFO,
            ).strip()

            if wmi_output.lower() == "true":
                return "Enabled"
            if wmi_output.lower() == "false":
                return "Disabled"
        except:
            pass

        # Neither registry nor WMI worked
        return "Unsupported"

    # --- Helper: detect Host-based Firewall ---
    def firewall_managed_by_safe(self):
        """
        Detects which product (if any) is managing Windows Firewall.
        Fully safe, no WMI, no PowerShell, no console windows.
        Returns a dict: {"managed": True/False, "product_name": str or None}
        """
        result = {"managed": False, "product_name": None}

        # List of common AV/firewall products that can manage Windows Firewall
        known_fw_managers = [
            "AVG Antivirus", "Avast", "Kaspersky", "McAfee",
            "Bitdefender", "Norton", "Trend Micro", "Sophos"
        ]

        # Use psutil to check running processes safely
        for proc in psutil.process_iter(["name"]):
            try:
                pname = proc.info.get("name")
                if pname:
                    for av in known_fw_managers:
                        if av.lower() in pname.lower():
                            result["managed"] = True
                            result["product_name"] = av
                            return result
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return result

    @staticmethod
    def get_windows_firewall_state():
        """Return Windows Firewall aggregate profile status ('On', 'Partially', 'Off', or 'Unknown')."""
        try:
            profiles = {"Domain": True, "Private": True, "Public": True}
            gpo_reg_path = r"SOFTWARE\Policies\Microsoft\WindowsFirewall"
            reg_path = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"
            profile_keys = {
                "Domain": "DomainProfile",
                "Private": "StandardProfile",
                "Public": "PublicProfile",
            }

            with winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE) as hklm:
                with winreg.OpenKey(hklm, reg_path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY):
                    pass

                for name, subkey in profile_keys.items():
                    resolved = None
                    for base_path in (gpo_reg_path, reg_path):
                        try:
                            key_path = f"{base_path}\\{subkey}"
                            with winreg.OpenKey(hklm, key_path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
                                enabled, _ = winreg.QueryValueEx(key, "EnableFirewall")
                                resolved = bool(int(enabled))
                                break
                        except (FileNotFoundError, TypeError, ValueError):
                            continue
                    profiles[name] = True if resolved is None else resolved

            if all(profiles.values()):
                return "On"
            if any(profiles.values()):
                return "Partially"
            return "Off"
        except Exception:
            return "Unknown"

    @staticmethod
    def _parse_sc2_products(entries):
        """Parse SecurityCenter2 AntiVirusProduct/FirewallProduct items into [(name, active_bool_or_None)]."""
        parsed = []
        if isinstance(entries, dict):
            items = [entries]
        elif isinstance(entries, list):
            items = entries
        else:
            items = []

        for item in items:
            if not isinstance(item, dict):
                continue
            name = str(item.get("displayName") or "").strip()
            if not name:
                continue
            try:
                state = int(item.get("productState"))
                active = (state & 0xF000) == 0x1000
            except (TypeError, ValueError):
                active = None
            parsed.append((name, active))
        return parsed

    def get_quick_endpoint_status(self):
        """
        Lightweight non-cached endpoint AV and local firewall summary for the welcome view.
        Uses in-process WMI SecurityCenter2 first (with PowerShell fallback) and does not touch _security_settings_cache.
        """
        av_products = []
        fw_products = []
        queried_sc2 = False

        com_initialized = False
        try:
            import gc
            import win32com.client

            try:
                pythoncom.CoInitialize()
                com_initialized = True
            except Exception:
                com_initialized = False

            def _read_sc2_in_com():
                sc2 = win32com.client.GetObject(r"winmgmts:\\.\root\SecurityCenter2")
                av_list = [
                    (
                        str(getattr(av, "displayName", "") or "").strip(),
                        getattr(av, "productState", None),
                    )
                    for av in sc2.InstancesOf("AntiVirusProduct")
                ]
                fw_list = [
                    (
                        str(getattr(fw, "displayName", "") or "").strip(),
                        getattr(fw, "productState", None),
                    )
                    for fw in sc2.InstancesOf("FirewallProduct")
                ]
                return av_list, fw_list

            def _normalize_sc2(rows):
                out = []
                for name, raw_state in rows:
                    if not name:
                        continue
                    try:
                        active = (int(raw_state) & 0xF000) == 0x1000
                    except (TypeError, ValueError):
                        active = None
                    out.append((name, active))
                return out

            raw_av, raw_fw = _read_sc2_in_com()
            av_products = _normalize_sc2(raw_av)
            fw_products = _normalize_sc2(raw_fw)
            queried_sc2 = True
        except Exception as exc:
            # Skip PowerShell fallback if SecurityCenter2 namespace does not exist (e.g. Server editions)
            if "invalid namespace" in str(exc).lower() or "-2147217394" in str(exc):
                queried_sc2 = True
        finally:
            if com_initialized:
                try:
                    gc.collect()
                    pythoncom.CoUninitialize()
                except Exception:
                    pass

        if not queried_sc2:
            ps_query = (
                "$av = @(Get-CimInstance -Namespace 'root/SecurityCenter2' "
                "-ClassName AntiVirusProduct -ErrorAction SilentlyContinue "
                "| Select-Object displayName, productState); "
                "$fw = @(Get-CimInstance -Namespace 'root/SecurityCenter2' "
                "-ClassName FirewallProduct -ErrorAction SilentlyContinue "
                "| Select-Object displayName, productState); "
                "[PSCustomObject]@{ av = $av; fw = $fw } | ConvertTo-Json -Depth 3 -Compress"
            )
            try:
                out = subprocess.check_output(
                    [_system_exe("powershell.exe"), "-NoProfile", "-NonInteractive", "-Command", ps_query],
                    shell=False,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=6,
                    stderr=subprocess.DEVNULL,
                    env=_safe_subproc_env(),
                    creationflags=_CREATE_NO_WINDOW,
                    startupinfo=_STARTUPINFO,
                ).strip()
                if out:
                    payload = json.loads(out)
                    if isinstance(payload, dict):
                        av_products = self._parse_sc2_products(payload.get("av"))
                        fw_products = self._parse_sc2_products(payload.get("fw"))
            except Exception:
                pass

        third_party_active = [n for n, act in av_products if act is True and n.lower() != "windows defender"]
        third_party_inactive = [n for n, act in av_products if act is False and n.lower() != "windows defender"]
        defender_states = [act for n, act in av_products if n.lower() == "windows defender"]

        if third_party_active:
            av_line = f"{', '.join(third_party_active)} is: Active"
        elif True in defender_states:
            av_line = "Windows Defender is: Active"
        elif third_party_inactive:
            av_line = f"{third_party_inactive[0]} is: Inactive"
        elif False in defender_states:
            av_line = "Windows Defender is: Inactive"
        else:
            # Fallback for Server editions / unavailable SecurityCenter2
            win_def = _run(["sc", "query", "WinDefend"]).upper()
            if "RUNNING" in win_def:
                av_line = "Windows Defender is: Active"
            elif "STOPPED" in win_def:
                av_line = "Windows Defender is: Inactive"
            else:
                av_line = "Antivirus status is: Unknown"

        fw_active_3p = any(
            act is True and n.lower() != "windows firewall"
            for n, act in fw_products
        )
        if fw_active_3p:
            fw_line = "Host-based FW is: Active"
        else:
            wf_state = self.get_windows_firewall_state()
            if wf_state == "On":
                fw_line = "Host-based FW is: Active"
            elif wf_state == "Partially":
                fw_line = "Host-based FW is: Partially Active"
            elif wf_state == "Off":
                fw_line = "Host-based FW is: Inactive"
            else:
                fw_line = "Host-based FW status is: Unknown"

        return {"av_line": av_line, "fw_line": fw_line}

    # --- Main Security Settings ---
    def get_security_settings(self):
        global _security_settings_cache
        global run_all_clicked
        global single_check
        
        if _security_settings_cache is not None and not run_all_clicked and not single_check:
            return _security_settings_cache
        
        result = {
            "Windows Defender": [],
            "Endpoint Protection": [],
            "Host-based Firewall": "Unknown",
            "Auto Screen Lock": "Unknown",
            "Office Macro Policy": "Unknown",
            "Defender ASR Rules": "Unknown",
            "UAC Elevation": "Unknown",
            "Core Isolation": "Unknown",
            "PowerShell Scripts": "Unknown",
            "Anonymous Access": "Unknown",
            "Data Execution Prevention": "Unknown",
            "Encrypted File System": "Unknown",
            "BitLocker Drive Encryption": "Unknown",
            "UEFI Secure Boot": "Unknown",
            "Removable Storage": "Unknown",
            "USB AutoRun": "Unknown",
            "System Restore": "Unknown",
        }

        # --- Windows Defender ---
        try:
            output = subprocess.check_output(
                [
                    _system_exe("powershell.exe"),
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "Get-MpComputerStatus | Select-Object -ExpandProperty AMServiceEnabled",
                ],
                shell=False, text=True, errors="ignore",
                env=_safe_subproc_env(),
                creationflags=_CREATE_NO_WINDOW,
                startupinfo=_STARTUPINFO,
            ).strip()
            defender_active = output.lower() == "true"
            result["Windows Defender"].append(f"Windows Defender ({'Active' if defender_active else 'Inactive'})")
        except Exception:
            result["Windows Defender"].append("Windows Defender (Unknown)")

        # --- Third-party AV products ---
        try:
            ps_av = (
                'Get-CimInstance -Namespace "root/SecurityCenter2" '
                '-ClassName AntiVirusProduct | Select-Object displayName,productState | '
                'ConvertTo-Json -Compress'
            )
            output = subprocess.check_output(
                [_system_exe("powershell.exe"), "-NoProfile", "-NonInteractive", "-Command", ps_av],
                shell=False,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=10,
                env=_safe_subproc_env(),
                creationflags=_CREATE_NO_WINDOW,
                startupinfo=_STARTUPINFO,
            ).strip()
            if output:
                data = json.loads(output)
                if isinstance(data, dict):
                    av_items = [data]
                elif isinstance(data, list):
                    av_items = data
                else:
                    av_items = []

                for item in av_items:
                    if not isinstance(item, dict):
                        continue
                    name = str(item.get("displayName") or "").strip()
                    if not name or name.lower() == "windows defender":
                        continue
                    try:
                        state = int(item.get("productState"))
                    except (TypeError, ValueError):
                        result["Endpoint Protection"].append(f"{name} (Unknown)")
                        continue

                    # SecurityCenter2 scanner-state nibble (0xF000): 0x1000 = enabled/active
                    active = (state & 0xF000) == 0x1000
                    result["Endpoint Protection"].append(
                        f"{name} ({'Active' if active else 'Inactive'})"
                    )
        except Exception:
            pass

        # --- Host-based Firewall (safe, no WMI / SecurityCenter2) ---
        try:
            # Detect controller
            fw_info = self.firewall_managed_by_safe()
            controller = fw_info["product_name"] if fw_info["managed"] else "Windows Firewall"

            status = self.get_windows_firewall_state()
            result["Host-based Firewall"] = f"{controller} ({status})" if status != "Unknown" else "Unknown"

        except Exception:
            result["Host-based Firewall"] = "Unknown"

        # --- Data Execution Prevention (DEP) ---
        try:
            dep_result = subprocess.run(
                [
                    _system_exe("powershell.exe"),
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "(Get-CimInstance Win32_OperatingSystem).DataExecutionPrevention_SupportPolicy"
                ],
                capture_output=True,
                text=True,
                env=_safe_subproc_env(),
                creationflags=_CREATE_NO_WINDOW,
                startupinfo=_STARTUPINFO,
                timeout=10
            )

            dep_policy = dep_result.stdout.strip()

            if dep_policy == "0":
                result["Data Execution Prevention"] = "Disabled"
            elif dep_policy == "1":
                result["Data Execution Prevention"] = "Enabled (Always On)"
            elif dep_policy == "2":
                result["Data Execution Prevention"] = "Enabled (Opt In)"
            elif dep_policy == "3":
                result["Data Execution Prevention"] = "Enabled (Opt Out)"
            else:
                result["Data Execution Prevention"] = "Unknown"

        except Exception:
            result["Data Execution Prevention"] = "Unknown"

        # --- Auto Screen Lock (Windows 10/11) ---
        try:
            inactivity = None
            lock_disabled_by_policy = False
            screen_lock = False
            lock_on_sleep = True  # Modern Windows requires sign-in on wake by default unless disabled

            # 1. Machine policy: InactivityTimeoutSecs & DisableLockWorkstation
            sys_pol_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            for root in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
                try:
                    with winreg.OpenKey(root, sys_pol_path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
                        if root == winreg.HKEY_LOCAL_MACHINE:
                            try:
                                val, _ = winreg.QueryValueEx(key, "InactivityTimeoutSecs")
                                inactivity = int(val)
                            except (FileNotFoundError, TypeError, ValueError):
                                pass

                        try:
                            disable_lock, _ = winreg.QueryValueEx(key, "DisableLockWorkstation")
                            if int(disable_lock) == 1:
                                lock_disabled_by_policy = True
                        except (FileNotFoundError, TypeError, ValueError):
                            pass
                except Exception:
                    pass

            # 2. Console lock on wake (GPO power setting first, then active power scheme overrides)
            console_lock_guid = "0e796bdb-100d-47d6-a2d5-f7d2daa51f51"
            gpo_wake_path = rf"SOFTWARE\Policies\Microsoft\Power\PowerSettings\{console_lock_guid}"
            wake_configured = False
            try:
                with winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE, gpo_wake_path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY
                ) as key:
                    indices = []
                    for idx_name in ("ACSettingIndex", "DCSettingIndex"):
                        try:
                            val, _ = winreg.QueryValueEx(key, idx_name)
                            indices.append(int(val))
                        except (FileNotFoundError, TypeError, ValueError):
                            pass
                    if indices:
                        lock_on_sleep = all(v != 0 for v in indices)
                        wake_configured = True
            except Exception:
                pass

            if not wake_configured:
                try:
                    schemes_path = r"SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes"
                    with winreg.OpenKey(
                        winreg.HKEY_LOCAL_MACHINE, schemes_path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY
                    ) as s_key:
                        active_guid, _ = winreg.QueryValueEx(s_key, "ActivePowerScheme")
                    user_wake_path = (
                        rf"{schemes_path}\{active_guid}\fea3413e-7e05-4911-9a71-700331f1c294\{console_lock_guid}"
                    )
                    with winreg.OpenKey(
                        winreg.HKEY_LOCAL_MACHINE, user_wake_path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY
                    ) as w_key:
                        indices = []
                        for idx_name in ("ACSettingIndex", "DCSettingIndex"):
                            try:
                                val, _ = winreg.QueryValueEx(w_key, idx_name)
                                indices.append(int(val))
                            except (FileNotFoundError, TypeError, ValueError):
                                pass
                        if indices:
                            lock_on_sleep = all(v != 0 for v in indices)
                except Exception:
                    pass

            # 3. Secure screen saver lock (GPO Desktop policy overrides user Desktop settings; requires ScreenSaveActive == "1")
            desktop_paths = (
                r"Software\Policies\Microsoft\Windows\Control Panel\Desktop",
                r"Control Panel\Desktop",
            )
            ss_active = None
            ss_secure = None
            ss_timeout = None
            for d_path in desktop_paths:
                try:
                    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, d_path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
                        if ss_active is None:
                            try:
                                ss_active = str(winreg.QueryValueEx(key, "ScreenSaveActive")[0]).strip()
                            except FileNotFoundError:
                                pass
                        if ss_secure is None:
                            try:
                                ss_secure = str(winreg.QueryValueEx(key, "ScreenSaverIsSecure")[0]).strip()
                            except FileNotFoundError:
                                pass
                        if ss_timeout is None:
                            try:
                                ss_timeout = int(str(winreg.QueryValueEx(key, "ScreenSaveTimeOut")[0]).strip())
                            except (FileNotFoundError, TypeError, ValueError):
                                pass
                except Exception:
                    pass

            screen_lock = (
                ss_active == "1"
                and ss_secure == "1"
                and (ss_timeout is None or ss_timeout > 0)
            )

            # 4. Human-readable verdict (preserving first-word contract for scoring)
            if lock_disabled_by_policy:
                result["Auto Screen Lock"] = "Disabled (Workstation locking disabled by policy)"
            elif inactivity is not None and inactivity > 0:
                timeout_label = f"{round(inactivity / 60)}min" if inactivity >= 60 else f"{inactivity}s"
                result["Auto Screen Lock"] = f"Enforced ({timeout_label} inactivity timeout)"
            elif inactivity == 0:
                if screen_lock:
                    result["Auto Screen Lock"] = "Default (Secure screen saver lock; inactivity policy 0s)"
                else:
                    result["Auto Screen Lock"] = "Disabled (Inactivity timeout set to 0s)"
            elif lock_on_sleep:
                if screen_lock:
                    result["Auto Screen Lock"] = "Default (Sleep lock + secure screen lock)"
                else:
                    result["Auto Screen Lock"] = "Default (Sleep lock enabled)"
            elif screen_lock:
                result["Auto Screen Lock"] = "Default (Secure screen saver lock)"
            else:
                result["Auto Screen Lock"] = "Disabled (No policy enforced)"

        except Exception:
            result["Auto Screen Lock"] = "Unknown"

        # --- Anonymous Access ---
        try:
            registry_checks = [
                (
                    r"SYSTEM\CurrentControlSet\Control\Lsa",
                    "RestrictAnonymous (Legacy default)",
                    lambda value: value == 0
                ),
                (
                    r"SYSTEM\CurrentControlSet\Control\Lsa",
                    "RestrictAnonymousSAM (Anonymous SAM enumeration – Exposed)",
                    lambda value: value == 0
                ),
                (
                    r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
                    "RestrictNullSessAccess (Null-session access – Exposed)",
                    lambda value: value == 0
                )
            ]

            findings = []
            all_restricted = True

            for key_path, setting, is_finding in registry_checks:
                value_name, remark = setting.split(" (", 1)
                remark = remark.rstrip(")")

                try:
                    with winreg.OpenKey(
                        winreg.HKEY_LOCAL_MACHINE,
                        key_path
                    ) as key:
                        value, _ = winreg.QueryValueEx(key, value_name)

                    value = int(value)

                    if is_finding(value):
                        all_restricted = False
                        findings.append((value_name, value, remark))

                except FileNotFoundError:
                    all_restricted = False

            if all_restricted:
                result["Anonymous Access"] = "Restricted"
            elif findings:
                result["Anonymous Access"] = "\n".join(
                    f"{name} = {value}: {remark}"
                    for name, value, remark in findings
                )
            else:
                result["Anonymous Access"] = "Unknown (Policy Values Missing)"

        except Exception:
            result["Anonymous Access"] = "Unknown"
                
        # --- Defender ASR Rules ---
        try:
            asr_paths = (
                r"SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules",
                r"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules",
            )
            rules = {}
            found_key = False

            for path in asr_paths:
                try:
                    with winreg.OpenKey(
                        winreg.HKEY_LOCAL_MACHINE,
                        path,
                        0,
                        winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
                    ) as key:
                        found_key = True
                        i = 0
                        while True:
                            try:
                                name, value, _ = winreg.EnumValue(key, i)
                                i += 1
                            except OSError:
                                break
                            guid = str(name).strip().lower()
                            if not guid:
                                continue
                            try:
                                rules[guid] = int(str(value).strip())
                            except (ValueError, TypeError):
                                continue
                except FileNotFoundError:
                    continue

            if not found_key or not rules:
                result["Defender ASR Rules"] = "Not Configured"
            else:
                enabled = sum(1 for v in rules.values() if v == 1)
                audit = sum(1 for v in rules.values() if v == 2)
                warn = sum(1 for v in rules.values() if v == 6)
                disabled = sum(1 for v in rules.values() if v == 0)

                details = f"Block: {enabled}, Audit: {audit}"
                if warn:
                    details += f", Warn: {warn}"
                details += f", Disabled: {disabled}"

                result["Defender ASR Rules"] = f"Configured ({len(rules)} rules - {details})"

        except Exception:
            result["Defender ASR Rules"] = "Unknown"
        
        # --- UAC ---
        try:
            key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            with winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE) as hklm:
                with winreg.OpenKey(hklm, key_path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
                    enable_uac, _ = winreg.QueryValueEx(key, "EnableLUA")
                    if int(enable_uac) != 0:
                        # UAC is enabled, check level (Windows defaults to 5 when absent)
                        try:
                            raw_consent, _ = winreg.QueryValueEx(key, "ConsentPromptBehaviorAdmin")
                            consent_behavior = int(raw_consent)
                        except FileNotFoundError:
                            consent_behavior = 5
                        except (TypeError, ValueError):
                            consent_behavior = None

                        try:
                            raw_approval_mode, _ = winreg.QueryValueEx(key, "TypeOfAdminApprovalMode")
                            admin_protection = int(raw_approval_mode) == 2
                        except (FileNotFoundError, TypeError, ValueError):
                            admin_protection = False

                        uac_levels = {
                            0: "Without prompting (Potentially Dangerous)",
                            1: "Prompt for credentials (Desktop Environment)",
                            2: "Prompt for consent (Desktop Environment)",
                            3: "Prompt for credentials",
                            4: "Prompt for consent",
                            5: "Prompt for consent (Non-Windows binaries)",
                        }
                        if consent_behavior is None:
                            level_desc = f"Invalid ({raw_consent})"
                        else:
                            level_desc = uac_levels.get(consent_behavior, f"Invalid ({consent_behavior})")

                        if admin_protection:
                            if level_desc.endswith(")"):
                                level_desc = f"{level_desc[:-1]}, Administrator Protection)"
                            else:
                                level_desc = f"{level_desc} (Administrator Protection)"

                        result["UAC Elevation"] = level_desc
                    else:
                        result["UAC Elevation"] = "Disabled"
        except FileNotFoundError:
            result["UAC Elevation"] = "Not Found"
        except PermissionError:
            result["UAC Elevation"] = "Access Denied"
        except Exception:
            result["UAC Elevation"] = "Unknown"

        # --- Core Isolation ---
        try:
            key_path = r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"

            def _read_hvci_reg():
                try:
                    with winreg.OpenKey(
                        winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY
                    ) as key:
                        val, _ = winreg.QueryValueEx(key, "Enabled")
                        return int(val)
                except (FileNotFoundError, TypeError, ValueError):
                    return None

            ps_script = (
                "$dg = Get-CimInstance -Namespace root\\Microsoft\\Windows\\DeviceGuard "
                "-ClassName Win32_DeviceGuard -ErrorAction Stop; "
                "if ($dg.SecurityServicesRunning -contains 2) {'Enabled'} else {'Disabled'}"
            )
            cim_status = None
            try:
                out = subprocess.check_output(
                    [_system_exe("powershell.exe"), "-NoProfile", "-NonInteractive", "-Command", ps_script],
                    shell=False,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    stderr=subprocess.DEVNULL,
                    env=_safe_subproc_env(),
                    creationflags=_CREATE_NO_WINDOW,
                    startupinfo=_STARTUPINFO,
                    timeout=10,
                ).strip().lower()
                if out in ("enabled", "disabled"):
                    cim_status = out.capitalize()
            except Exception:
                cim_status = None

            reg_val = _read_hvci_reg()
            if cim_status == "Enabled":
                result["Core Isolation"] = "Enabled"
            elif cim_status == "Disabled":
                if reg_val == 1:
                    result["Core Isolation"] = "Disabled (Configured, not running)"
                else:
                    result["Core Isolation"] = "Disabled"
            else:
                # CIM unavailable/failed: fall back to registry without asserting runtime enforcement
                if reg_val == 0:
                    result["Core Isolation"] = "Disabled"
                elif reg_val == 1:
                    result["Core Isolation"] = "Unknown (Runtime unverified)"
                else:
                    result["Core Isolation"] = "Unknown"
        except Exception:
            result["Core Isolation"] = "Unknown"

        # --- Macro Security ---
        try:
            def get_macro_security_summary():
                results = []

                # Check Group Policy precedence before user Office settings
                macro_paths = (
                    (winreg.HKEY_CURRENT_USER, r"Software\Policies\Microsoft\Office\16.0\Word\Security"),
                    (winreg.HKEY_LOCAL_MACHINE, r"Software\Policies\Microsoft\Office\16.0\Word\Security"),
                    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Office\16.0\Word\Security"),
                )

                raw_macro_value = None
                for root, path in macro_paths:
                    raw_macro_value = _read_reg_value(root, path, "VBAWarnings")
                    if raw_macro_value is not None:
                        break

                if raw_macro_value is None:
                    macro_status = "Default (System controlled)"
                else:
                    try:
                        macro_value = int(str(raw_macro_value).strip())
                    except (TypeError, ValueError):
                        macro_value = raw_macro_value

                    # Microsoft Office VBAWarnings values:
                    # 4 = Disable all macros without notification (most secure)
                    # 3 = Disable all macros except digitally signed macros
                    # 2 = Disable all macros with notification
                    # 1 = Enable all macros (unsafe)
                    if macro_value == 4:
                        macro_status = "Disabled (No macros)"
                    elif macro_value == 3:
                        macro_status = "Disabled (Except digitally signed)"
                    elif macro_value == 2:
                        macro_status = "Disabled (With notification)"
                    elif macro_value == 1:
                        macro_status = "Enabled (All macros allowed - Unsafe)"
                    else:
                        macro_status = f"Unknown ({raw_macro_value})"

                results.append(macro_status)
                return results

            result["Office Macro Policy"] = get_macro_security_summary()

        except Exception:
            result["Office Macro Policy"] = "Unknown"
            
        # --- PowerShell Scripts ---
        try:
            output = subprocess.check_output(
                [_system_exe("powershell.exe"), "-NoProfile", "-NonInteractive", "-Command", "Get-ExecutionPolicy"],
                shell=False, text=True, stderr=subprocess.DEVNULL,
                env=_safe_subproc_env(), creationflags=_CREATE_NO_WINDOW, startupinfo=_STARTUPINFO
            ).strip()

            # Normalize common values
            valid_policies = ["Restricted", "RemoteSigned", "AllSigned", "Unrestricted", "Bypass", "Undefined"]
            if output in valid_policies:
                result["PowerShell Scripts"] = output
            else:
                result["PowerShell Scripts"] = "Unknown"

        except Exception:
            result["PowerShell Scripts"] = "Unknown"

        # --- BitLocker ---
        result["BitLocker Drive Encryption"] = self.check_bitlocker()

        # --- System Restore ---
        result["System Restore"] = self.check_system_restore()

        # --- UEFI Secure Boot ---
        result["UEFI Secure Boot"] = self.check_secure_boot()

        # --- Removable Storage ---
        try:
            def get_removable_storage():
                usb_value = _read_reg_value(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SYSTEM\CurrentControlSet\Services\USBSTOR",
                    "Start"
                )

                if usb_value is None:
                    return "Unknown"
                elif usb_value == 4:
                    return "Disabled"
                else:
                    return "Enabled"

            result["Removable Storage"] = get_removable_storage()

        except Exception:
            result["Removable Storage"] = "Unknown"

        # --- USB AutoRun ---
        try:
            def get_usb_autorun():
                autorun_value = _read_reg_value(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
                    "NoDriveTypeAutoRun"
                )

                if autorun_value is None:
                    return "Default"
                elif autorun_value == 255:
                    return "Disabled"
                else:
                    return "Partially Disabled"

            result["USB AutoRun"] = get_usb_autorun()

        except Exception:
            result["USB AutoRun"] = "Unknown"

        # --- Encrypted File System ---
        try:
            INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF
            FILE_ATTRIBUTE_REPARSE_POINT = 0x400
            FILE_ATTRIBUTE_ENCRYPTED = 0x4000
            get_file_attrs = ctypes.windll.kernel32.GetFileAttributesW
            skip_dirs = {"appdata", "application data", ".git", "node_modules", "__pycache__"}

            efs_found = False
            checked_files = 0
            max_files = 25000
            deadline = time.monotonic() + 5.0

            for root, dirs, files in os.walk(os.path.expanduser("~"), followlinks=False):
                # Prune cache/system/reparse directories
                kept_dirs = []
                for d in dirs:
                    if d.lower() in skip_dirs:
                        continue
                    d_path = os.path.join(root, d)
                    d_attrs = get_file_attrs(d_path)
                    if d_attrs in (-1, INVALID_FILE_ATTRIBUTES):
                        continue
                    if d_attrs & FILE_ATTRIBUTE_REPARSE_POINT:
                        continue
                    kept_dirs.append(d)
                dirs[:] = kept_dirs

                for file in files:
                    if checked_files >= max_files or time.monotonic() > deadline:
                        break
                    checked_files += 1
                    file_path = os.path.join(root, file)
                    try:
                        attrs = get_file_attrs(file_path)
                        if attrs not in (-1, INVALID_FILE_ATTRIBUTES) and (attrs & FILE_ATTRIBUTE_ENCRYPTED):
                            efs_found = True
                            break
                    except Exception:
                        continue
                if efs_found or checked_files >= max_files or time.monotonic() > deadline:
                    break
            result["Encrypted File System"] = "Encrypted files found" if efs_found else "No encrypted files"
        except Exception:
            result["Encrypted File System"] = "Unknown"

        _security_settings_cache = result
        return _security_settings_cache

    def format_security_settings(self, settings):
        """Formats security settings as a clean table."""

        lines = [""]

        headers = ("Setting", "Status", "Remarks")
        rows = []

        for key, value in settings.items():
            items = value if isinstance(value, list) else [value]

            if not items:
                rows.append((key, "Unknown", "-"))
                continue

            for i, item in enumerate(items):
                item = str(item or "Unknown")

                # Handle Anonymous Access findings
                if key == "Anonymous Access":
                    for j, entry in enumerate(item.splitlines()):
                        entry = entry.strip()

                        if ":" in entry:
                            status, remarks = entry.split(":", 1)
                            status = status.strip()
                            remarks = remarks.strip() or "-"
                        else:
                            status = entry or "Unknown"
                            remarks = "-"

                        rows.append((
                            key if i == 0 and j == 0 else "",
                            status,
                            remarks
                        ))
                    continue

                remarks = "-"

                if "(" in item and ")" in item:
                    status, remainder = item.split("(", 1)
                    remarks = remainder.rsplit(")", 1)[0].strip()
                    status = status.strip()
                else:
                    status = item.strip()

                rows.append((
                    key if i == 0 else "",
                    status or "Unknown",
                    remarks or "-"
                ))

        if rows:
            lines.append(
                f"{headers[0]:<30}"
                f"{headers[1]:<25}"
                f"{headers[2]}"
            )
            lines.append("–" * 80)

            for i, (key, status, remarks) in enumerate(rows):
                lines.append(
                    f"{key:<30}"
                    f"{status:<25}"
                    f"{remarks}"
                )

                if i < len(rows) - 1 and rows[i + 1][0]:
                    lines.append("–" * 80)
        else:
            lines.append("    None Detected")

        return "\n".join(lines)

    def show_security_settings(self):
        raw = self.get_security_settings()            # collect raw data
        formatted = self.format_security_settings(raw)  # format it for display
        return formatted  # only show formatted output

# ===== Remote Access Settings =====
class RemoteAccessSettings:

    # --- WinRM Settings ---
    def check_winrm_service(self):
        output = _run(["sc", "qc", "WinRM"])

        if "SERVICE_NAME" not in output:
            return {
                "status": "Disabled",
                "running": False
            }

        if "DISABLED" in output:
            return {
                "status": "Disabled",
                "running": False
            }

        running = "RUNNING" in _run(["sc", "query", "WinRM"])

        return {
            "status": "Enabled",
            "running": running
        }

    def check_winrm_startup(self):
        output = _run(["sc", "qc", "WinRM"])
        if "AUTO_START" in output:
            return "Automatic"
        if "DEMAND_START" in output:
            return "Manual"
        if "DISABLED" in output:
            return "Disabled"
        return "Unknown"

    def check_listeners(self):
        try:
            output = subprocess.check_output(
                [
                    _system_exe("powershell.exe"),
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "Get-ChildItem WSMan:\\localhost\\Listener -ErrorAction Stop | ForEach-Object { $_.Keys }",
                ],
                shell=False,
                text=True,
                encoding="utf-8",
                errors="replace",
                stderr=subprocess.DEVNULL,
                timeout=10,
                env=_safe_subproc_env(),
                creationflags=_CREATE_NO_WINDOW,
                startupinfo=_STARTUPINFO,
            )
        except (subprocess.SubprocessError, OSError):
            output = ""
        return {
            "http": bool(re.search(r"\bTransport\s*=\s*HTTP\b", output, re.IGNORECASE)),
            "https": bool(re.search(r"\bTransport\s*=\s*HTTPS\b", output, re.IGNORECASE)),
        }

    def check_ports(self):
        ports = []
        for port in (5985, 5986):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                if s.connect_ex(("127.0.0.1", port)) == 0:
                    ports.append(port)
        return ports

    def check_auth(self):
        auth = {}
        value_map = {
            "Basic": ("AllowBasic", "auth_basic"),
            "Kerberos": ("AllowKerberos", "auth_kerberos"),
            "Negotiate": ("AllowNegotiate", "auth_negotiate"),
            "Certificate": (None, "auth_certificate"),
        }
        policy_key = None
        wsman_key = None
        try:
            try:
                policy_key = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SOFTWARE\Policies\Microsoft\Windows\WinRM\Service",
                    0,
                    winreg.KEY_READ | winreg.KEY_WOW64_64KEY
                )
            except OSError:
                policy_key = None

            try:
                wsman_key = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Service",
                    0,
                    winreg.KEY_READ | winreg.KEY_WOW64_64KEY
                )
            except OSError:
                wsman_key = None

            if policy_key is None and wsman_key is None:
                return {}

            for display_name, (gpo_name, local_name) in value_map.items():
                val = None
                if policy_key is not None and gpo_name:
                    try:
                        val = bool(winreg.QueryValueEx(policy_key, gpo_name)[0])
                    except FileNotFoundError:
                        val = None
                if val is None and wsman_key is not None and local_name:
                    try:
                        val = bool(winreg.QueryValueEx(wsman_key, local_name)[0])
                    except FileNotFoundError:
                        val = False
                auth[display_name] = bool(val) if val is not None else False
            return auth
        except Exception:
            return {}
        finally:
            if policy_key is not None:
                winreg.CloseKey(policy_key)
            if wsman_key is not None:
                winreg.CloseKey(wsman_key)

    def check_encryption(self):
        for path, val_name in (
            (r"SOFTWARE\Policies\Microsoft\Windows\WinRM\Service", "AllowUnencryptedTraffic"),
            (r"SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Service", "allow_unencrypted"),
        ):
            try:
                with winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    path,
                    0,
                    winreg.KEY_READ | winreg.KEY_WOW64_64KEY
                ) as key:
                    allow = winreg.QueryValueEx(key, val_name)[0]
                    return not bool(allow)
            except FileNotFoundError:
                continue
            except Exception:
                continue
        return True

    def assess_risk(self, service, listeners, auth, encrypted):
        if not service["running"]:
            return "None"

        if auth.get("Basic"):
            return "Critical"

        if listeners["http"] and not encrypted:
            return "High"

        if listeners["http"] and listeners["https"]:
            return "Medium"

        if listeners["https"]:
            return "Low"

        return "Medium"

    def audit_winrm(self):
        global _audit_winrm_cache
        global run_all_clicked
        global single_check

        if _audit_winrm_cache is not None and not run_all_clicked and not single_check:
            return _audit_winrm_cache
        
        service = self.check_winrm_service()
        startup = self.check_winrm_startup()
        listeners = self.check_listeners()
        ports = self.check_ports()
        auth = self.check_auth()
        encrypted = self.check_encryption()
        risk = self.assess_risk(service, listeners, auth, encrypted)
        verdict = self.winrm_verdict(service, listeners, ports, risk)

        _audit_winrm_cache = {
            "service": service,
            "startup": startup,
            "listeners": listeners,
            "ports": ports,
            "authentication": auth,
            "encryption": encrypted,
            "risk": risk,
            "verdict": verdict
        }

        return _audit_winrm_cache

    def winrm_verdict(self, service, listeners, ports, risk):
        status = service.get("status", "Unknown").lower()

        if status != "enabled":
            return "Disabled"

        if not listeners.get("http") and not listeners.get("https"):
            return "Enabled, Low Risk (No listeners)"

        if not ports:
            return "Enabled, Low Risk (No ports listeners)"

        if risk == "Low":
            return "Enabled, Moderate Risk (Restricted exposure)"

        if risk == "Medium":
            return "Enabled, Moderate Risk (Network exposure)"

        if risk in ("High", "Critical"):
            return "Enabled, High Risk (Remote access exposed)"

        return "Enabled, Unknown Risk (Exposure unknown)"

    def check_bluetooth(self):
        try:
            ps_script = r"""
            $ErrorActionPreference = 'Stop'

            $devices = @(
                Get-PnpDevice -Class Bluetooth -ErrorAction Stop |
                Select-Object Status, FriendlyName, InstanceId,
                    @{Name='ProblemCode'; Expression={
                        try {
                            (Get-PnpDeviceProperty `
                                -InstanceId $_.InstanceId `
                                -KeyName 'DEVPKEY_Device_ProblemCode' `
                                -ErrorAction Stop).Data
                        }
                        catch {
                            $null
                        }
                    }}
            )

            # --- Bluetooth driver signature status ---
            $signedDrivers = @(
                Get-CimInstance -ClassName Win32_PnPSignedDriver `
                    -ErrorAction Stop |
                Select-Object DeviceID, IsSigned, Signer, DriverVersion
            )

            foreach ($device in $devices) {
                $driver = $signedDrivers |
                    Where-Object {
                        $_.DeviceID -eq $device.InstanceId
                    } |
                    Select-Object -First 1

                if ($null -ne $driver) {
                    $device | Add-Member -NotePropertyName DriverIsSigned `
                        -NotePropertyValue $driver.IsSigned -Force
                    $device | Add-Member -NotePropertyName DriverSigner `
                        -NotePropertyValue $driver.Signer -Force
                    $device | Add-Member -NotePropertyName DriverVersion `
                        -NotePropertyValue $driver.DriverVersion -Force
                }
                else {
                    $device | Add-Member -NotePropertyName DriverIsSigned `
                        -NotePropertyValue $null -Force
                    $device | Add-Member -NotePropertyName DriverSigner `
                        -NotePropertyValue $null -Force
                    $device | Add-Member -NotePropertyName DriverVersion `
                        -NotePropertyValue $null -Force
                }
            }

            $serviceStatus = 'Unknown'

            try {
                $serviceStatus = (
                    Get-Service -Name bthserv -ErrorAction Stop
                ).Status.ToString()
            }
            catch {
                $serviceStatus = 'Unknown'
            }

            [PSCustomObject]@{
                QuerySucceeded = $true
                Devices = @($devices)
                ServiceStatus = $serviceStatus
            } | ConvertTo-Json -Depth 5 -Compress
            """

            output = subprocess.check_output(
                [
                    _system_exe("powershell.exe"),
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    ps_script,
                ],
                shell=False,
                text=True,
                encoding="utf-8",
                errors="replace",
                env=_safe_subproc_env(),
                stderr=subprocess.DEVNULL,
                timeout=15,
                creationflags=_CREATE_NO_WINDOW,
                startupinfo=_STARTUPINFO,
            ).strip()

            if not output:
                raise ValueError("Empty PowerShell response")

            data = json.loads(output)

            if not data.get("QuerySucceeded", False):
                raise ValueError("Bluetooth device query failed")

            devices = data.get("Devices", [])

            if isinstance(devices, dict):
                devices = [devices]

            if not devices:
                return "Not detected"

            # --- Check device status ---
            operational_devices = [
                device for device in devices
                if str(device.get("Status", "")).strip().upper() == "OK"
            ]

            disabled_devices = [
                device for device in devices
                if str(device.get("ProblemCode", "")).strip() == "22"
            ]

            if not operational_devices:
                if disabled_devices:
                    return "Disabled"
                return "Not detected"

            # Driver signature information is now available in each
            # device dictionary for reporting or further assessment.
            service_status = data.get("ServiceStatus", "Unknown")

           # --- Check connectability ---
            try:
                bluetooth_api = ctypes.WinDLL(_system_exe("bthprops.cpl"))

                is_connectable = bluetooth_api.BluetoothIsConnectable
                is_connectable.argtypes = [ctypes.c_void_p]
                is_connectable.restype = ctypes.c_int

                connectable = bool(is_connectable(None))

            except (OSError, AttributeError):
                connectable = False

            # --- Assess driver signature ---
            signed_status = (
                "Signed"
                if all(
                    device.get("DriverIsSigned") is True
                    for device in operational_devices
                )
                else "Unknown"
            )
            
            if signed_status != "Signed":
                signed_error = True
            else:
                signed_error = False

            # --- Assess risk ---
            if connectable and signed_error:
                return "Enabled, Moderate Risk (Bluetooth driver unknown or unsigned)"

            elif connectable and service_status == "Running":
                return "Enabled, Low Risk (Default settings)"

            elif connectable and service_status == "Stopped":
                return "Enabled, Moderate Risk (Support Service stopped)"

            elif service_status == "Stopped":
                return "Enabled, Exposure status unknown"

            return "Enabled, Exposure status unknown"

        except (
            subprocess.SubprocessError,
            OSError,
            ValueError,
            json.JSONDecodeError,
        ):
            return "Unknown"

        except Exception:
            return "Unknown"

    # --- Remote Access Settings ---
    def _get_firewall_profile_states(self):
        """Return lowercase enabled flags for the 3 Windows Firewall profiles."""
        return subprocess.check_output(
            [
                _system_exe("powershell.exe"),
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "(Get-NetFirewallProfile | "
                "Select-Object -ExpandProperty Enabled) -join ','",
            ],
            shell=False,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=_safe_subproc_env(),
            stderr=subprocess.DEVNULL,
            timeout=10,
            creationflags=_CREATE_NO_WINDOW,
            startupinfo=_STARTUPINFO,
        ).strip().lower().split(",")

    @staticmethod
    def _evaluate_smb2_service_verdict(data: dict) -> str:
        """Evaluate SMB2 server service configuration without checking share permissions."""
        if not isinstance(data, dict):
            return "Unknown"

        svc = data.get("Service") if isinstance(data.get("Service"), dict) else {}
        cfg = data.get("Config") if isinstance(data.get("Config"), dict) else {}

        svc_status = str(svc.get("Status") or "").strip().lower()
        svc_start = str(svc.get("StartType") or "").strip().lower()
        if svc_start == "disabled" or svc_status == "stopped":
            return "Disabled"

        enable_smb2 = cfg.get("EnableSMB2Protocol")
        if enable_smb2 is None:
            return "Unknown"
        if not enable_smb2:
            return "Disabled"

        null_shares_raw = cfg.get("NullSessionShares")
        if isinstance(null_shares_raw, str):
            has_null_shares = any(s.strip() for s in null_shares_raw.splitlines())
        elif isinstance(null_shares_raw, list):
            has_null_shares = any(str(s).strip() for s in null_shares_raw if s is not None)
        else:
            has_null_shares = False

        restrict_null_sess = data.get("RestrictNullSessAccess")
        unrestricted_null_sess = (
            restrict_null_sess is not None
            and str(restrict_null_sess).strip().lower() in ("0", "false")
        )
        auth_user_sharing = bool(cfg.get("EnableAuthenticateUserSharing"))
        reject_unencrypted = cfg.get("RejectUnencryptedAccess")
        strict_name = cfg.get("EnableStrictNameChecking")

        if (
            has_null_shares
            or unrestricted_null_sess
            or auth_user_sharing
            or reject_unencrypted is False
            or strict_name is False
        ):
            return "Enabled, Potentially Dangerous (Insecure SMB service settings)"

        if bool(cfg.get("RequireSecuritySignature")) or bool(cfg.get("EncryptData")):
            return "Enabled, Low Risk (Signing/Encryption enforced)"

        return "Enabled, Moderate Risk (Signing/Encryption not required)"

    def get_remote_access_settings(self):
        global _remote_access_cache
        global run_all_clicked
        global single_check
        
        if _remote_access_cache is not None and not run_all_clicked and not single_check:
            return _remote_access_cache
        
        result = {
            "Remote Desktop": "Unknown",
            "Remote Registry": "Unknown",
            "Remote Assistance": "Unknown",
            "PowerShell Remoting": "Unknown",
            "FTP Service": "Unknown",
            "Rsync Service": "Unknown",
            "RPC Print Spooler": "Unknown",
            "Bluetooth": "Unknown",
            "UPnPHost": "Unknown",
            "NetBIOS": "Unknown",
            "DCOM": "Unknown",
            "WinRM": "Unknown",
            "SMB1": "Unknown",
            "SMB2": "Unknown",
        }

        # --- Remote Desktop (RDP) ---
        try:
            key_path = r"SYSTEM\CurrentControlSet\Control\Terminal Server"
            with winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE) as hklm:
                with winreg.OpenKey(hklm, key_path) as key:
                    # --- Check if RDP is enabled ---
                    fDenyTSConnections, _ = winreg.QueryValueEx(key, "fDenyTSConnections")
                    rdp_enabled = fDenyTSConnections == 0

                    if rdp_enabled:
                        # --- Check Network Level Authentication (NLA) ---
                        try:
                            key_sec_path = r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
                            with winreg.OpenKey(hklm, key_sec_path) as sec_key:
                                nla, _ = winreg.QueryValueEx(sec_key, "UserAuthentication")
                                min_encryption, _ = winreg.QueryValueEx(sec_key, "MinEncryptionLevel")

                                # Assess security
                                if nla == 1 and min_encryption >= 2:  # 2 or higher = moderate/strong
                                    verdict = "Enabled, Low Risk (Default settings)"
                                else:
                                    verdict = "Enabled, Potentially Exposed (Without NLA or weak encryption)"
                        except FileNotFoundError:
                            verdict = "Enabled, Potentially Exposed (Configuration missing or insecure)"
                    else:
                        verdict = "Disabled"

                    result["Remote Desktop"] = verdict

        except FileNotFoundError:
            result["Remote Desktop"] = "Disabled"
        except PermissionError:
            result["Remote Desktop"] = "Unknown"
        except Exception:
            result["Remote Desktop"] = "Unknown"

        # --- SMB1 ---
        try:
            if is_admin():
                ps_smb1 = (
                    "Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol | "
                    "Select-Object -ExpandProperty State"
                )
                output = subprocess.check_output(
                    [_system_exe("powershell.exe"), "-NoProfile", "-NonInteractive", "-Command", ps_smb1],
                    shell=False, text=True, encoding="utf-8",
                    env=_safe_subproc_env(), creationflags=_CREATE_NO_WINDOW, startupinfo=_STARTUPINFO
                ).strip()

                out_l = output.lower()
                if out_l == "enabled":
                    verdict = "Enabled, High Risk"  # SMB1 enabled → insecure
                elif out_l.startswith("disabled"):
                    verdict = "Disabled"  # Covers Disabled and DisabledWithPayloadRemoved
                else:
                    verdict = output or "Unknown"
            else:
                # Non-admin fallback without requiring DISM elevation
                srv_smb1 = _read_reg_value(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
                    "SMB1",
                )
                mrx_start = _read_reg_value(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SYSTEM\CurrentControlSet\Services\mrxsmb10",
                    "Start",
                )
                mrx_enabled = False
                try:
                    mrx_enabled = mrx_start is not None and int(mrx_start) in (0, 1, 2, 3)
                except (TypeError, ValueError):
                    mrx_enabled = False

                if srv_smb1 == 1 or mrx_enabled:
                    verdict = "Enabled, High Risk"
                else:
                    verdict = "Disabled"

            result["SMB1"] = verdict

        except subprocess.CalledProcessError:
            result["SMB1"] = "Unknown"
        except Exception:
            result["SMB1"] = "Unknown"

        # --- SMB2 ---
        try:
            result["SMB2"] = "Unknown"

            ps_smb2 = (
                "$svc = Get-Service -Name LanmanServer -ErrorAction SilentlyContinue; "
                "$cfg = Get-SmbServerConfiguration -ErrorAction SilentlyContinue | "
                "Select-Object EnableSMB2Protocol, RequireSecuritySignature, EnableSecuritySignature, "
                "EncryptData, RejectUnencryptedAccess, EnableStrictNameChecking, "
                "EnableAuthenticateUserSharing, NullSessionShares, NullSessionPipes, "
                "SmbServerNameHardeningLevel; "
                "$reg = Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' "
                "-ErrorAction SilentlyContinue; "
                "[PSCustomObject]@{"
                "Service = if ($svc) { @{ Status = $svc.Status.ToString(); StartType = $svc.StartType.ToString() } } else { $null }; "
                "Config = $cfg; "
                "RestrictNullSessAccess = if ($reg -and ($reg.PSObject.Properties.Name -contains 'restrictnullsessaccess')) { $reg.restrictnullsessaccess } else { $null }"
                "} | ConvertTo-Json -Depth 3 -Compress"
            )
            output = subprocess.check_output(
                [_system_exe("powershell.exe"), "-NoProfile", "-NonInteractive", "-Command", ps_smb2],
                shell=False, text=True, encoding="utf-8", errors="replace",
                env=_safe_subproc_env(), creationflags=_CREATE_NO_WINDOW, startupinfo=_STARTUPINFO
            ).strip()
            data = json.loads(output) if output else {}
            result["SMB2"] = self._evaluate_smb2_service_verdict(data)

        except Exception:
            result["SMB2"] = "Unknown"

        # --- Bluetooth ---
        result["Bluetooth"] = self.check_bluetooth()

        # --- DCOM ---
        try:
            # --- Check if DCOM is enabled ---
            reg_output = _run_check_output(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    r"Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Ole -ErrorAction SilentlyContinue | Select-Object -ExpandProperty EnableDCOM",
                ],
                shell=False,
            ).strip()

            # --- Check Windows Firewall profiles ---
            try:
                fw_status = self._get_firewall_profile_states()

                if len(fw_status) != 3 or any(
                    value not in ("true", "false") for value in fw_status
                ):
                    firewall_state = "Unknown"
                elif all(value == "true" for value in fw_status):
                    firewall_state = "Fully Enabled"
                elif all(value == "false" for value in fw_status):
                    firewall_state = "Fully Disabled"
                else:
                    firewall_state = "Partially Enabled"

            except (subprocess.SubprocessError, OSError):
                firewall_state = "Unknown"

            if reg_output == "Y":
                # 🔹 Check authentication level
                try:
                    auth_output = _run_check_output(
                        [
                            "powershell.exe",
                            "-NoProfile",
                            "-NonInteractive",
                            "-Command",
                            r"Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Ole -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LegacyAuthenticationLevel",
                        ],
                        shell=False,
                    ).strip()
                    level_map = {
                        "1": "None (Dangerous)",
                        "2": "Connect",
                        "3": "Call",
                        "4": "Packet",
                        "5": "Packet Integrity (Safe)",
                        "6": "Packet Privacy (Best)"
                    }
                    auth_state = level_map.get(auth_output, "Unknown")
                except Exception:
                    auth_state = "Unknown"

                # 🔹 Check for Microsoft DCOM Hardening flag
                try:
                    harden_output = _run_check_output(
                        [
                            "powershell.exe",
                            "-NoProfile",
                            "-NonInteractive",
                            "-Command",
                            r"Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Ole -ErrorAction SilentlyContinue | Select-Object -ExpandProperty RequireIntegrityActivationAuthenticationLevel",
                        ],
                        shell=False,
                    ).strip()
                    harden_state = "Enabled" if harden_output == "1" else "Disabled"
                except Exception:
                    harden_state = "Unknown"

                # 🔹 Determine final verdict
                if auth_state in ["Packet Integrity (Safe)", "Packet Privacy (Best)"]:
                    reg_state = "Enabled, Low Risk (Secured authentication)"
                elif harden_state == "Enabled":
                    reg_state = "Enabled, Hardened by Patch"
                else:
                    # Weak authentication / no hardening → potentially dangerous
                    if firewall_state in ("Fully Enabled", "Partially Enabled"):
                        reg_state = "Enabled, Moderate Risk (Firewall On)"
                    elif firewall_state == "Fully Disabled":
                        reg_state = "Enabled, Potentially Dangerous (Firewall Off)"
                    else:
                        reg_state = "Enabled, Moderate Risk (Firewall Status Unknown)"

            elif reg_output == "N":
                reg_state = "Remote Disabled"  # ✅ safest option
            else:
                reg_state = "Unknown"

        except Exception:
            reg_state = "Unknown"

        result["DCOM"] = reg_state

        # --- NetBIOS ---
        try:
            output = _run_check_output(["ipconfig", "/all"], shell=False, timeout=10)

            result["NetBIOS"] = "Unknown"

            for line in output.splitlines():
                if "NetBIOS over Tcpip" in line:
                    status = line.split(":", 1)[-1].strip()

                    if status.lower() == "enabled":
                        result["NetBIOS"] = "Enabled, Legacy default"
                    elif status.lower() == "disabled":
                        result["NetBIOS"] = "Disabled"
                    else:
                        result["NetBIOS"] = status

                    break

        except Exception:
            result["NetBIOS"] = "Unknown"

        # --- Remote Assistance ---
        try:
            key_path = r"SYSTEM\CurrentControlSet\Control\Remote Assistance"
            with winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE) as hklm:
                with winreg.OpenKey(hklm, key_path) as key:
                    ra_value, _ = winreg.QueryValueEx(key, "fAllowToGetHelp")
                    result["Remote Assistance"] = "Enabled, Moderate Risk" if ra_value == 1 else "Disabled"
        except FileNotFoundError:
            result["Remote Assistance"] = "Disabled"
        except PermissionError:
            result["Remote Assistance"] = "Unknown"
        except Exception:
            result["Remote Assistance"] = "Unknown"

        # --- PowerShell Remoting (WinRM) ---
        try:
            # Check if WinRM service exists and status
            ps_status = (
                "if (Get-Service -Name WinRM -ErrorAction SilentlyContinue) "
                "{ (Get-Service -Name WinRM).Status } else { 'NotInstalled' }"
            )
            winrm_status = _run_check_output(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps_status],
                shell=False,
            ).strip().lower()

            if not winrm_status or winrm_status == "notinstalled":
                result["PowerShell Remoting"] = "Disabled"
            elif winrm_status != "running":
                result["PowerShell Remoting"] = "Disabled"
            else:
                # Check if any WSMan listener exists (Server 2022 reliable method)
                ps_listener = r"if (Get-ChildItem WSMan:\localhost\Listener -ErrorAction SilentlyContinue) {'Enabled'} else {'Disabled'}"
                listener_status = _run_check_output(
                    ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps_listener],
                    shell=False,
                ).strip().lower()

                if "enabled" in listener_status:
                    result["PowerShell Remoting"] = "Enabled, Potentially Dangerous"
                else:
                    # Fallback: AllowRemoteShellAccess registry
                    ps_reg = (
                        r"$val = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Service -ErrorAction SilentlyContinue).AllowRemoteShellAccess; "
                        r"if ($val -eq $null) {'Unknown'} elseif ($val -eq 1 -or $val -eq 'true') {'Enabled'} else {'Disabled'}"
                    )
                    reg_status = _run_check_output(
                        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps_reg],
                        shell=False,
                    ).strip().lower()
                    if reg_status in ("enabled", "1", "true"):
                        result["PowerShell Remoting"] = "Enabled, Potentially Dangerous"
                    elif reg_status == "disabled":
                        result["PowerShell Remoting"] = "Disabled"
                    else:
                        result["PowerShell Remoting"] = "Unknown"

        except Exception:
            result["PowerShell Remoting"] = "Unknown"

        # --- RPC Print Spooler ---
        try:
            key_path = r"SYSTEM\CurrentControlSet\Control\Print"
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                key_path,
                0,
                winreg.KEY_READ | winreg.KEY_WOW64_64KEY
            ) as key:
                try:
                    rpc_value, _ = winreg.QueryValueEx(key, "RpcEnabled")
                except FileNotFoundError:
                    rpc_value = None

                if rpc_value == 1:
                    try:
                        restrict_clients, _ = winreg.QueryValueEx(key, "RestrictRemoteClients")
                    except FileNotFoundError:
                        restrict_clients = 0

                    try:
                        privacy_enabled, _ = winreg.QueryValueEx(key, "RpcAuthnLevelPrivacyEnabled")
                    except FileNotFoundError:
                        privacy_enabled = 0

                    if restrict_clients == 1 and privacy_enabled == 1:
                        verdict = "Enabled, Low Risk (Restricted access)"
                    elif restrict_clients == 1 or privacy_enabled == 1:
                        verdict = "Enabled, Moderate Risk (Partially restricted)"
                    else:
                        verdict = "Enabled, Potentially Dangerous (Unrestricted network access)"
                else:
                    verdict = "Disabled"

            result["RPC Print Spooler"] = verdict

        except FileNotFoundError:
            result["RPC Print Spooler"] = "Disabled"
        except Exception:
            result["RPC Print Spooler"] = "Unknown"

        # --- Rsync Service ---
        try:
            ps_script = (
                "$svc = Get-CimInstance Win32_Service "
                "-Filter \"Name='rsync'\" -ErrorAction Stop; "
                "if ($null -eq $svc) { 'Not Detected' } "
                "else { \"$($svc.State)|$($svc.StartMode)\" }"
            )

            output = subprocess.check_output(
                [
                    _system_exe("powershell.exe"),
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    ps_script,
                ],
                shell=False,
                text=True,
                encoding="utf-8",
                errors="replace",
                env=_safe_subproc_env(),
                stderr=subprocess.DEVNULL,
                timeout=10,
                creationflags=_CREATE_NO_WINDOW,
                startupinfo=_STARTUPINFO,
            ).strip()

            if output == "Not Detected":
                result["Rsync Service"] = "Not Detected"

            elif "|" in output:
                state, start_mode = output.split("|", 1)

                if state == "Running":
                    result["Rsync Service"] = "Running"
                elif start_mode == "Disabled":
                    result["Rsync Service"] = "Disabled"
                elif state == "Stopped":
                    result["Rsync Service"] = "Stopped"
                else:
                    result["Rsync Service"] = "Unknown"

            else:
                result["Rsync Service"] = "Unknown"

        except (subprocess.SubprocessError, OSError):
            result["Rsync Service"] = "Unknown"

        except Exception:
            result["Rsync Service"] = "Unknown"

        # --- UPnP Service ---
        try:
            ps_script = (
                "$svc = Get-CimInstance Win32_Service "
                "-Filter \"Name='upnphost'\" -ErrorAction Stop; "
                "if ($null -eq $svc) { 'Not Detected' } "
                "else { \"$($svc.State)|$($svc.StartMode)\" }"
            )

            output = subprocess.check_output(
                [
                    _system_exe("powershell.exe"),
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    ps_script,
                ],
                shell=False,
                text=True,
                encoding="utf-8",
                errors="replace",
                env=_safe_subproc_env(),
                stderr=subprocess.DEVNULL,
                timeout=10,
                creationflags=_CREATE_NO_WINDOW,
                startupinfo=_STARTUPINFO,
            ).strip()

            if output == "Not Detected":
                result["UPnPHost"] = "Not Detected"

            elif "|" in output:
                state, start_mode = output.split("|", 1)

                if state == "Running":
                    result["UPnPHost"] = "Running, Moderate Risk"
                elif start_mode == "Disabled":
                    result["UPnPHost"] = "Disabled"
                elif state == "Stopped":
                    result["UPnPHost"] = "Stopped"
                else:
                    result["UPnPHost"] = "Unknown"
            else:
                result["UPnPHost"] = "Unknown"

        except (subprocess.SubprocessError, OSError):
            result["UPnPHost"] = "Unknown"

        except Exception:
            result["UPnPHost"] = "Unknown"

        # --- Remote Registry ---
        try:
            # --- Check RemoteRegistry service startup type ---
            config_output = _run_check_output(
                ["sc", "qc", "RemoteRegistry"],
                shell=False,
                stderr=subprocess.DEVNULL,
                timeout=10,
            ).lower()

            if "start_type" not in config_output:
                reg_state = "Unknown"

            elif "disabled" in config_output:
                reg_state = "Disabled"

            elif "auto_start" in config_output or "demand_start" in config_output:
                # --- Check whether the service is currently running ---
                try:
                    state_output = _run_check_output(
                        ["sc", "query", "RemoteRegistry"],
                        shell=False,
                        stderr=subprocess.DEVNULL,
                        timeout=10,
                    ).lower()

                    if "running" in state_output:
                        service_running = True
                    elif "stopped" in state_output:
                        service_running = False
                    else:
                        service_running = None

                except Exception:
                    service_running = None

                # --- Check all Windows Firewall profiles ---
                try:
                    fw_status = self._get_firewall_profile_states()

                    if (
                        len(fw_status) == 3
                        and all(value in ("true", "false") for value in fw_status)
                    ):
                        firewall_on = all(value == "true" for value in fw_status)
                    else:
                        firewall_on = None

                except Exception:
                    firewall_on = None

                # --- Determine final verdict ---
                if service_running is False:
                    reg_state = "Enabled, Low Risk (Service stopped)"

                elif service_running is None:
                    reg_state = "Enabled, Unknown (Service state unavailable)"

                elif firewall_on is True:
                    reg_state = "Enabled, Moderate Risk (Firewall On)"

                elif firewall_on is False:
                    reg_state = "Enabled, Potentially Dangerous"

                else:
                    reg_state = "Enabled, Potentially Dangerous"

            else:
                reg_state = "Unknown"

        except (subprocess.SubprocessError, OSError, Exception):
            reg_state = "Unknown"

        result["Remote Registry"] = reg_state

        # --- FTP Service ---
        try:
            service_state = None
            ftp_detected = False
            ftp_port = None
            sftp = False
            tftp_detected = False

            # 1. Known FTP services
            ftp_services = {
                "ftpsvc": "IIS FTP Service",
                "filezilla": "FileZilla Server"
            }

            try:
                ps_services = (
                    "Get-Service | Where-Object { $_.Name -match 'ftpsvc|filezilla' } | "
                    "Select-Object Name, Status | ConvertTo-Json"
                )
                services = _run_check_output(
                    ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps_services],
                    shell=False,
                ).strip()

                if services:
                    data = json.loads(services)

                    if isinstance(data, dict):
                        data = [data]

                    for svc in data:
                        name = svc.get("Name", "").lower()
                        status = svc.get("Status")

                        if "filezilla" in name or "ftpsvc" in name:
                            ftp_detected = True

                            if status == "Running":
                                service_state = "Running"
                            elif status == "Stopped" and service_state is None:
                                service_state = "Stopped"

            except Exception:
                pass

            # 2. TCP port detection (FTP/FTPS/HTTP)
            try:
                netstat = _run_check_output(["netstat", "-ano"], shell=False)

                for line in netstat.splitlines():
                    if not re.search(r"\bLISTENING\b", line, re.IGNORECASE):
                        continue

                    match = re.search(
                        r"^\s*TCP\s+\S+:(\d+)\s+\S+\s+LISTENING\b",
                        line,
                        re.IGNORECASE
                    )

                    if not match:
                        continue

                    port = int(match.group(1))

                    if port in (21, 990):
                        ftp_port = port

                        if not (ftp_detected and service_state == "Stopped"):
                            ftp_detected = True
                            service_state = "Running"

                        break

            except Exception:
                pass

            # 3. FileZilla process detection
            if not ftp_detected:
                try:
                    tasklist = _run_check_output(["tasklist"], shell=False).lower()

                    if "filezilla server.exe" in tasklist:
                        ftp_detected = True
                        service_state = "Running"

                except Exception:
                    pass

            # 4. SFTP detection (OpenSSH Server + TCP 22)
            try:
                ssh_service = _run_check_output(
                    [
                        "powershell.exe",
                        "-NoProfile",
                        "-NonInteractive",
                        "-Command",
                        "Get-Service -Name sshd -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Status",
                    ],
                    shell=False,
                ).strip()

                if ssh_service == "Running":
                    try:
                        netstat = _run_check_output(["netstat", "-ano"], shell=False)

                        if re.search(r":22\s+.*LISTENING", netstat, re.IGNORECASE):
                            sftp = True

                    except Exception:
                        pass

            except Exception:
                pass

            # 5. TFTP detection (UDP port 69 + process)
            try:
                netstat = _run_check_output(["netstat", "-ano", "-p", "udp"], shell=False)

                for line in netstat.splitlines():
                    match = re.search(
                        r"^\s*UDP\s+\S+:69\s+\S+\s+(\d+)\s*$",
                        line,
                        re.IGNORECASE
                    )

                    if not match:
                        continue

                    tftp_pid = int(match.group(1))

                    try:
                        tasklist = _run_check_output(
                            ["tasklist", "/FI", f"PID eq {tftp_pid}", "/FO", "CSV", "/NH"],
                            shell=False,
                        ).strip().lower()

                        # Confirm the process belongs to a known TFTP server
                        if any(name in tasklist for name in (
                            "tftpd.exe",
                            "tftpserver.exe",
                            "tftpsrv.exe",
                            "solarwinds tftp server.exe"
                        )):
                            tftp_detected = True
                            break

                    except Exception:
                        pass

            except Exception:
                pass

            # 6. Final normalization
            if ftp_detected and service_state == "Stopped":
                result["FTP Service"] = "Stopped"

            elif ftp_detected and ftp_port == 21:
                result["FTP Service"] = (
                    "Running, Potentially Exposed (FTP Port 21)"
                )

            elif sftp:
                result["FTP Service"] = (
                    "Running, Potentially Exposed (SSH/SFTP Port 22)"
                )

            elif ftp_detected and ftp_port == 990:
                result["FTP Service"] = (
                    "Running, Potentially Exposed (FTPS Port 990)"
                )

            elif tftp_detected:
                result["FTP Service"] = (
                    "Running, Potentially Exposed (TFTP Port 69)"
                )

            elif ftp_detected and service_state == "Running":
                result["FTP Service"] = "Running, Unknown Port"

            else:
                result["FTP Service"] = "Not Detected"

        except Exception:
            result["FTP Service"] = "Unknown"
        
        # --- WinRM ---
        winrm_data = self.audit_winrm()         # run full WinRM audit
        result["WinRM"] = winrm_data["verdict"]

        _remote_access_cache = result
        
        return _remote_access_cache

    def format_remote_access_settings(self, settings):
        """Formats remote access settings as a clean table."""

        lines = [""]

        headers = ("Setting", "Status", "Remarks")
        rows = []

        for key, value in settings.items():
            value = str(value or "Unknown")

            if value.startswith("Enabled, "):
                status = "Enabled"
                remarks = value[len("Enabled, "):]

            elif value.startswith("Running, "):
                status = "Running"
                remarks = value[len("Running, "):]

            elif value.startswith("Remote Disabled"):
                status = "Disabled"
                remarks = "-"

            elif value.startswith("Disabled"):
                status = "Disabled"
                remarks = value[len("Disabled"):].strip(" ,()") or "-"

            else:
                status = value
                remarks = "-"

            rows.append((key, status, remarks))

        if rows:
            lines.append(
                f"{headers[0]:<30}"
                f"{headers[1]:<20}"
                f"{headers[2]}"
            )
            lines.append("–" * 80)

            for i, (key, status, remarks) in enumerate(rows):
                lines.append(
                    f"{key:<30}"
                    f"{status:<20}"
                    f"{remarks}"
                )

                if i < len(rows) - 1 and rows[i + 1][0]:
                    lines.append("–" * 80)
        else:
            lines.append("    None Detected")

        return "\n".join(lines)

    def show_remote_access_settings(self):
        raw = self.get_remote_access_settings()            # collect raw data
        formatted = self.format_remote_access_settings(raw)  # format it for display
        return formatted  # only show formatted output

# ===== Domain Settings =====
class DomainSettings:

    def format_domain_settings(self, data):
        report = [""]

        # Basic info
        for key in ["Type", "Name", "Hostname", "Current User", "Domain Role"]:
            report.append(f"{key}:")
            report.append(f"  {data.get(key, 'Unknown')}")
            report.append("–" * 50)

        # Privileged Users
        report.append("Privileged Users:")
        privileged = data.get("Privileged Users", [])
        if privileged:
            for user in privileged:
                report.append(f"  {user}")
        else:
            report.append("  (None)")
        report.append("–" * 50)

        # Regular Users
        report.append("Regular Users:")
        regular = data.get("Regular Users", [])
        if regular:
            for user in regular:
                report.append(f"  {user}")
        else:
            report.append("  (None)")
        report.append("–" * 50)

        # LAPS Status
        laps_status = data.get("LAPS Status", "Not Detected")
        report.append("LAPS Status:")
        report.append(f"  {laps_status}")
        report.append("–" * 50)

        # NTLM Policy
        ntlm_policy = data.get("NTLM Policy") or "Unknown"
        report.append("NTLM Policy:")
        report.append(f"  {ntlm_policy}")
        report.append("–" * 50)
        
        # NTP Role
        ntp = data.get("NTP", "None")
        report.append("NTP:")
        report.append(f"  {ntp}")
        
        return "\n".join(report)

    def show_domain_settings(self):
        raw = get_domain_settings()            # collect raw data
        formatted = self.format_domain_settings(raw)  # format it for display
        return formatted  # only show formatted output

# ===== Password Policy =====
class PasswordPolicy:

    @staticmethod
    def _safe_int(value):
        """Convert a value to int without raising an exception."""
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _is_timeq_forever(value):
        """Check the Windows TIMEQ_FOREVER value."""
        try:
            return int(value) in (-1, 0xFFFFFFFF)
        except (TypeError, ValueError):
            return False

    @staticmethod
    def _query_domain_complexity():
        """
        Read the default Active Directory domain password complexity setting.

        This does not evaluate fine-grained password policies (FGPP).
        Returns True, False, or 'Unknown'.
        """
        com_initialized = False
        try:
            import win32com.client

            try:
                pythoncom.CoInitialize()
                com_initialized = True
            except pythoncom.com_error as ce:
                # RPC_E_CHANGED_MODE: thread already initialized with another apartment model
                if ce.hresult != -2147417850:
                    raise

            root_dse = win32com.client.GetObject("LDAP://RootDSE")
            naming_context = root_dse.Get("defaultNamingContext")

            if not naming_context:
                return "Unknown"

            domain = win32com.client.GetObject(f"LDAP://{naming_context}")
            pwd_properties = int(domain.Get("pwdProperties"))

            # ADS_UF_PASSWD_COMPLEX = 0x00000001
            return bool(pwd_properties & 0x00000001)

        except Exception:
            return "Unknown"
        finally:
            if com_initialized:
                try:
                    pythoncom.CoUninitialize()
                except Exception:
                    pass

    @staticmethod
    def _query_local_complexity():
        """
        Read local PasswordComplexity via secedit when running elevated.
        Returns True, False, or 'Unknown'.
        """
        if not is_admin():
            return "Unknown"

        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                inf_path = os.path.join(tmpdir, "secpol.inf")
                proc = subprocess.run(
                    [
                        _system_exe("secedit.exe"),
                        "/export",
                        "/cfg",
                        inf_path,
                        "/areas",
                        "SECURITYPOLICY",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=15,
                    env=_safe_subproc_env(),
                    creationflags=_CREATE_NO_WINDOW,
                    startupinfo=_STARTUPINFO,
                )
                if proc.returncode == 0 and os.path.exists(inf_path):
                    with open(inf_path, "r", encoding="utf-16", errors="replace") as f:
                        for line in f:
                            if line.strip().lower().startswith("passwordcomplexity"):
                                val = line.split("=", 1)[-1].strip()
                                if val in ("0", "1"):
                                    return val == "1"
        except Exception:
            pass

        return "Unknown"

    # --- Main password policy checker ---
    def get_password_policy_nonadmin(self):
        """
        Retrieve password policy information without requiring
        administrator privileges.

        Uses Windows NetAPI, ADSI/LDAP for domain complexity, and
        secedit (when elevated) for local complexity.
        Unavailable information is reported as Unknown.
        """
        global _password_policy_cache
        global run_all_clicked
        global single_check

        if (
            _password_policy_cache is not None
            and not run_all_clicked
            and not single_check
        ):
            return _password_policy_cache

        result = {
            "Policy Affiliation": "Unknown",
            "Password History": "Unknown",
            "Password MinLength": None,
            "Password Complexity": "Unknown",
            "Password Required": "Unknown",
            "Password Expires": "Unknown",
            "Lockout Threshold": "Unknown",
            "Lockout Duration": "Unknown",
            "Lockout Observed": "Unknown",
            "LAPS": "Unknown",
            "Verdict": "Unknown",
        }

        # --- Domain / workgroup / Entra / local ---
        try:
            domain_info = get_domain_settings()
            if not isinstance(domain_info, dict):
                domain_info = {}
        except Exception:
            domain_info = {}

        ptype = domain_info.get("Type")
        name = domain_info.get("Name")
        is_domain_joined = ptype in ("Domain", "Hybrid Azure AD")

        if ptype in ("Domain", "Workgroup", "Hybrid Azure AD", "Azure AD"):
            result["Policy Affiliation"] = f"{ptype} ({name})" if name else ptype
        else:
            result["Policy Affiliation"] = "Local"

        # --- LAPS (reuse get_domain_settings result when available) ---
        cached_laps = domain_info.get("LAPS")
        if cached_laps in ("Enabled", "Disabled", "Not Detected", "Unknown"):
            result["LAPS"] = cached_laps
        else:
            try:
                installed, enabled = _check_laps()
                if installed is True and enabled is True:
                    result["LAPS"] = "Enabled"
                elif installed is True and enabled is False:
                    result["LAPS"] = "Disabled"
                elif installed is False:
                    result["LAPS"] = "Not Detected"
                else:
                    result["LAPS"] = "Unknown"
            except Exception:
                result["LAPS"] = "Unknown"

        # --- Determine the correct policy server ---
        target_server = None
        if is_domain_joined:
            try:
                target_server = win32net.NetGetDCName(None, None)
            except Exception:
                target_server = None

        # Never fall back to local policy when domain DC lookup fails.
        if is_domain_joined and not target_server:
            policy_servers = []
        else:
            policy_servers = [target_server]

        # --- Password history, minimum length and expiration age ---
        max_password_age = None

        for server in policy_servers:
            try:
                policy = win32net.NetUserModalsGet(server, 0)
                if not isinstance(policy, dict):
                    continue

                history = self._safe_int(policy.get("password_hist_len"))
                if history is not None and history >= 0:
                    result["Password History"] = (
                        "Not Enforced" if history == 0 else f"Last {history} Enforced"
                    )

                min_length = self._safe_int(policy.get("min_passwd_len"))
                if min_length is not None and min_length >= 0:
                    result["Password MinLength"] = min_length

                max_password_age = self._safe_int(policy.get("max_passwd_age"))
                break
            except Exception:
                continue

        # --- Lockout policy ---
        for server in policy_servers:
            try:
                lockout = win32net.NetUserModalsGet(server, 3)
                if not isinstance(lockout, dict):
                    continue

                threshold = self._safe_int(lockout.get("lockout_threshold"))
                duration = self._safe_int(lockout.get("lockout_duration"))

                if threshold is not None and threshold >= 0:
                    result["Lockout Threshold"] = str(threshold)
                    result["Lockout Observed"] = "Yes" if threshold > 0 else "No"

                    if threshold == 0:
                        result["Lockout Duration"] = "Not Applicable"
                    elif duration == 0 or self._is_timeq_forever(duration):
                        result["Lockout Duration"] = "Until Admin Unlocks"
                    elif duration is not None and duration > 0:
                        if duration % 60 == 0:
                            result["Lockout Duration"] = f"{duration // 60} minutes"
                        else:
                            result["Lockout Duration"] = f"{duration} seconds"

                break
            except Exception:
                continue

        # --- Password complexity ---
        if is_domain_joined:
            result["Password Complexity"] = self._query_domain_complexity()
        else:
            result["Password Complexity"] = self._query_local_complexity()

        # --- Determine whether the current account is local or domain ---
        username = getpass.getuser()
        user_domain = os.environ.get("USERDOMAIN", "").strip()
        computer_name = os.environ.get("COMPUTERNAME", "").strip()

        account_server = None
        account_username = username
        acct_domain = user_domain

        if "\\" in username:
            acct_domain, account_username = username.split("\\", 1)
            acct_domain = acct_domain.strip()

        is_local_account = (
            not acct_domain
            or (computer_name and acct_domain.casefold() == computer_name.casefold())
        )
        is_cloud_account = acct_domain.casefold() in ("azuread", "microsoftaccount")

        if is_local_account:
            account_server = None
            account_query_allowed = True
        elif is_domain_joined and not is_cloud_account:
            try:
                account_server = win32net.NetGetDCName(None, acct_domain)
            except Exception:
                account_server = target_server
            account_query_allowed = bool(account_server)
        else:
            account_query_allowed = False

        # --- Current user's account information ---
        if account_query_allowed and account_username:
            try:
                user_info = win32net.NetUserGetInfo(
                    account_server,
                    account_username,
                    2,
                )
                flags = self._safe_int(user_info.get("flags"))

                if flags is not None:
                    if flags & win32netcon.UF_PASSWD_NOTREQD:
                        result["Password Required"] = "No"
                    else:
                        result["Password Required"] = "Yes"

                    account_never_expires = bool(
                        flags & win32netcon.UF_DONT_EXPIRE_PASSWD
                    )

                    if account_never_expires:
                        result["Password Expires"] = "No"
                    elif max_password_age == 0 or self._is_timeq_forever(max_password_age):
                        result["Password Expires"] = "No"
                    elif max_password_age is not None and max_password_age > 0:
                        result["Password Expires"] = "Yes"
            except Exception:
                pass

        # --- Verdict ---
        min_length = result["Password MinLength"]
        complexity = result["Password Complexity"]
        required = result["Password Required"]
        lockout = result["Lockout Observed"]

        if required == "No":
            result["Verdict"] = "Weak"
        elif required == "Yes":
            if min_length is None or min_length < 0:
                result["Verdict"] = "Unknown"
            elif min_length < 8:
                result["Verdict"] = "Weak"
            elif complexity is False:
                result["Verdict"] = "Weak"
            elif complexity == "Unknown":
                result["Verdict"] = "Moderate" if lockout == "Yes" else "Unknown"
            elif complexity is True:
                if lockout == "Yes":
                    result["Verdict"] = "Strong"
                elif lockout == "No":
                    result["Verdict"] = "Moderate"
                else:
                    result["Verdict"] = "Unknown"
        else:
            result["Verdict"] = "Unknown"

        _password_policy_cache = result
        return _password_policy_cache

    def format_password_policy(self, policy):
        """
        Returns a formatted multi-line report for password policy with dashed lines.
        """
        if not isinstance(policy, dict):
            return ""

        report = [""]

        keys = list(policy.keys())
        for i, key in enumerate(keys):
            value = policy[key]

            report.append(f"{key}:")
            report.append(f"  {value}")

            # Add separator only if not the last item
            if i != len(keys) - 1:
                report.append("–" * 50)

        return "\n".join(report)

    def show_password_policy_nonadmin(self):
        raw = self.get_password_policy_nonadmin()            # collect raw data
        formatted = self.format_password_policy(raw)  # format it for display
        return formatted  # only show formatted output

# ===== Credential Integrity =====
class CredentialIntegrity:

    # --- Credential Security Check ---
    def run_hidden_command(self, cmd_list, env=None):
        """
        Run a command completely hidden (no CMD/PowerShell window flashes)
        Returns the command output as a string
        """
        try:
            resolved_cmd = [_system_exe(str(cmd_list[0])), *cmd_list[1:]] if cmd_list else cmd_list
            result = subprocess.run(
                resolved_cmd,
                capture_output=True,
                text=True,
                env=_safe_subproc_env(env),
                creationflags=_CREATE_NO_WINDOW,
                startupinfo=_STARTUPINFO
            )
            return result.stdout.strip()
        except Exception as e:
            return ""

    # --- Hive Access Check ---
    def check_hive_access(self):
        paths = [
            r"C:\Windows\System32\config\SAM",
            r"C:\Windows\System32\config\SECURITY"
        ]

        results = []
        admin = is_admin()

        for path in paths:

            # --- NON-ADMIN: try real access ---
            if not admin:
                try:
                    with open(path, "rb"):
                        status = "Accessible ⚠️"
                except PermissionError:
                    status = "Protected (SYSTEM only)"
                except Exception:
                    status = "Unknown"

                results.append(f"{path}\n    {status}")
                continue

            # --- ADMIN: full ACL check ---
            try:
                output = subprocess.check_output(
                    [_system_exe("icacls"), path],
                    shell=False,
                    text=True,
                    errors="ignore",
                    env=_safe_subproc_env(),
                    creationflags=_CREATE_NO_WINDOW,
                    startupinfo=_STARTUPINFO,
                )

                ace_entries = []
                for raw_line in output.splitlines():
                    line = raw_line.strip()
                    if not line or line.lower().startswith("successfully processed"):
                        continue
                    if line.lower().startswith(path.lower()):
                        line = line[len(path):].strip()
                    if ":" in line:
                        principal = line.split(":", 1)[0].strip().upper()
                        perms = line.split(":", 1)[1].strip().upper()
                        ace_entries.append((principal, perms))

                risky_principals = ("EVERYONE", "BUILTIN\\USERS", "USERS", "AUTHENTICATED USERS", "NT AUTHORITY\\AUTHENTICATED USERS")
                overly_permissive = any(
                    (p in risky_principals or p.endswith("\\USERS")) and "(DENY)" not in perms
                    for p, perms in ace_entries
                )
                has_system = any(p == "NT AUTHORITY\\SYSTEM" for p, _ in ace_entries)
                unexpected_principals = any(
                    p not in ("NT AUTHORITY\\SYSTEM", "BUILTIN\\ADMINISTRATORS")
                    and not p.endswith("\\ADMINISTRATORS")
                    for p, perms in ace_entries
                    if "(DENY)" not in perms
                )

                if overly_permissive or unexpected_principals:
                    status = "Accessible ⚠️"
                elif has_system:
                    status = "Protected (SYSTEM only)"
                else:
                    status = "Unknown"

                results.append(f"{path}\n    {status}")

            except Exception:
                results.append(f"{path}\n    Unknown")

        return "\n  ".join(results)

    # --- Windows Credential Manager ---
    def check_credential_manager(self):
        """
        Check whether Windows Credential Manager contains stored credentials.
        Does not access or expose credential contents.
        """
        try:
            output = self.run_hidden_command([
                "cmdkey",
                "/list"
            ])

            if not output:
                return "No stored credentials detected"

            # cmdkey normally reports stored credentials using
            # entries such as "Target:".
            credential_count = output.count("Target:")

            if credential_count > 0:
                return f"{credential_count} stored credentials detected"

            return "No stored credentials detected"

        except Exception:
            return "Unknown"

    # --- Credential Guard ---
    def check_credential_guard(self):
        global _credential_guard_cache
        global run_all_clicked
        global single_check

        if _credential_guard_cache is not None and not run_all_clicked and not single_check:
            return _credential_guard_cache

        if sys.platform != "win32":
            _credential_guard_cache = "Not supported by current Windows edition"
            return "Not supported by current Windows edition"

        ps_cmd = [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-WindowStyle", "Hidden",
            "-Command",
            "$dg = Get-CimInstance -Namespace root\\Microsoft\\Windows\\DeviceGuard "
            "-ClassName Win32_DeviceGuard -ErrorAction SilentlyContinue; "
            "if ($null -eq $dg) { '{\"supported\": false}' } "
            "else { @{ supported = $true; running = @($dg.SecurityServicesRunning) } | ConvertTo-Json -Compress }"
        ]

        output = self.run_hidden_command(ps_cmd)
        if not output:
            return "Unknown"

        try:
            data = json.loads(output)
            if not data.get("supported"):
                _credential_guard_cache = "Not supported by current Windows edition"
                return _credential_guard_cache

            running = data.get("running") or []
            if not isinstance(running, list):
                running = [running]
            services = {int(x) for x in running if str(x).strip().isdigit()}
            # Win32_DeviceGuard: 1 = Credential Guard, 2 = HVCI (Core Isolation)
            _credential_guard_cache = "Enabled" if 1 in services else "Disabled"
            return _credential_guard_cache
        except Exception:
            return "Unknown"

    # --- WDigest ---
    def check_wdigest(self):
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
            )
            value, _ = winreg.QueryValueEx(key, "UseLogonCredential")
            if value == 1:
                return "WDigest plaintext logon enabled (INSECURE)"
        except FileNotFoundError:
            return "WDigest key not present (safe)"
        return "WDigest plaintext disabled (safe)"

    # --- LSASS Integrity ---
    def hash_file(self, filepath, algo='sha256'):
        h = hashlib.new(algo)
        try:
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return None

    def verify_signature(self, filepath):
        ps_cmd = [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-WindowStyle", "Hidden",
            "-Command",
            "(Get-AuthenticodeSignature -LiteralPath $env:SECUDITOR_SIG_PATH).Status"
        ]
        output = self.run_hidden_command(ps_cmd, env={"SECUDITOR_SIG_PATH": str(filepath)})
        return output.lower() == "valid"

    def check_lsass_integrity(self):
        details = {}
        lsass_path = r"C:\Windows\System32\lsass.exe"

        # Path
        details['Path'] = lsass_path if os.path.exists(lsass_path) else "lsass.exe not found"

        # SHA256
        details['SHA256'] = self.hash_file(lsass_path)

        # Suspicious processes
        suspicious = []
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                if proc.info['pid'] == os.getpid():
                    continue
                proc_name = proc.info.get('name') or ''
                if proc_name.lower() in ['procdump.exe', 'mimikatz.exe', 'dumpertool.exe']:
                    suspicious.append(proc_name)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        if suspicious:
            details['SuspiciousProcesses'] = suspicious

        return details

    # --- LSASS Protection ---
    def check_lsass_protection(self):
        global _lsass_protection_cache
        global run_all_clicked
        global single_check

        if _lsass_protection_cache is not None and not run_all_clicked and not single_check:
            return _lsass_protection_cache

        # Confirm LSASS is running
        lsass_running = any(
            (proc.info.get('name') or '').lower() == 'lsass.exe'
            for proc in psutil.process_iter(['name'])
        )
        if not lsass_running:
            _lsass_protection_cache = "Disabled (LSASS not running)"
            return _lsass_protection_cache

        # Check RunAsPPL / RunAsPPLBoot registry keys (Win11 22H2+ may use RunAsPPLBoot)
        try:
            key_path = r"SYSTEM\CurrentControlSet\Control\Lsa"
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                key_path,
                0,
                winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
            ) as key:
                value = None
                for val_name in ("RunAsPPL", "RunAsPPLBoot"):
                    try:
                        value, _ = winreg.QueryValueEx(key, val_name)
                        break
                    except FileNotFoundError:
                        continue
                if value is None:
                    status = "Disabled (RunAsPPL key not found)"
                elif value in (1, 2):
                    status = "Enabled (Protected Process Light)"
                else:
                    status = "Disabled (LSASS not PPL-protected)"
        except FileNotFoundError:
            status = "Disabled (RunAsPPL key not found)"
        except Exception as e:
            status = f"Unknown (Error: {e})"

        _lsass_protection_cache = status
        return _lsass_protection_cache

    # --- LSASS Signature ---
    def check_lsass_signature(self):
        lsass_path = r"C:\Windows\System32\lsass.exe"
        if not os.path.exists(lsass_path):
            return "lsass.exe not found"
        return "Valid" if self.verify_signature(lsass_path) else "Invalid"

    # --- Run all credential checks ---
    def run_credential_integrity_checks(self):
        check_hive_access_status = self.check_hive_access()
        credential_guard_status = self.check_credential_guard()
        wdigest_status = self.check_wdigest()
        lsass_details = self.check_lsass_integrity()
        lsass_protection_status = self.check_lsass_protection()
        lsass_signature_status = self.check_lsass_signature()
        credential_manager_status = self.check_credential_manager()

        report = [""]

        # Credential Guard
        report.append("Credential Guard:")
        report.append(f"  {credential_guard_status}")
        report.append("–" * 50)

        # LSASS details
        report.append("LSASS Validation:")
        for key, value in lsass_details.items():
            report.append(f"  {key}:")
            report.append(f"    {value}")
            if key.lower() == "sha256":
                report.append("  WDigest:")
                report.append(f"    {wdigest_status}")
        report.append("–" * 50)

        # LSASS Protection
        report.append("LSASS Protection (RunAsPPL):")
        report.append(f"  {lsass_protection_status}")
        report.append("–" * 50)

        # LSASS Signature
        report.append("LSASS Signature:")
        report.append(f"  {lsass_signature_status}")
        report.append("–" * 50)

        # SAM Hive
        report.append("SAM Hive:")
        report.append(f"  {check_hive_access_status}")
        report.append("–" * 50)

        # Credential Manager
        report.append("Windows Credential Manager:")
        report.append(f"  {credential_manager_status}")

        return "\n".join(report)

# ===== Windows Events =====
class WindowsEvents:
    """Query and format 24-hour Windows Security and System event log counts."""

    SECURITY_EVENTS = {
        # --- Logon/Logoff ---
        4624: "Successful logon",
        4625: "Failed logon",
        4634: "Logoff",
        4647: "User initiated logoff",
        4648: "Logon with explicit credentials",
        4672: "Special privileges assigned to new logon",

        # --- Account Management ---
        4720: "New user account created",
        4722: "User account enabled",
        4725: "User account disabled",
        4726: "User account deleted",
        4738: "User account changed",
        4740: "User account locked out",

        # --- Group Membership Changes ---
        4727: "Security-enabled global group created",
        4728: "User added to global group",
        4729: "User removed from global group",
        4730: "Global group deleted",
        4731: "Security-enabled local group created",
        4732: "User added to local group",
        4733: "User removed from local group",
        4734: "Local group deleted",
        4756: "Universal group created",
        4757: "User added to universal group",
        4758: "User removed from universal group",
        4759: "Universal group deleted",

        # --- Policy & Privilege Changes ---
        4670: "Permissions on an object changed",
        4719: "System audit policy changed",
        4739: "Domain policy changed",
        4782: "Password hash accessed",

        # --- Service & Scheduled Task Events ---
        4697: "Service installed",
        4698: "Scheduled task created",
        4699: "Scheduled task deleted",
        4700: "Scheduled task enabled",
        4701: "Scheduled task disabled",

        # --- Audit & Log Tampering ---
        1102: "Security log cleared",
        4614: "Security log retention settings changed",
        4713: "Kerberos policy changed",
    }

    SYSTEM_EVENTS = {
        # --- System Startup / Shutdown ---
        12: "Operating system started",
        13: "Operating system shutdown",
        6005: "Event Log service started",
        6006: "Event Log service stopped",
        6008: "Unexpected shutdown",

        # --- Driver / Service Issues ---
        7000: "Service failed to start",
        7001: "Dependent service failed",
        7009: "Service start timeout",
        7011: "Service timeout",
        7022: "Service hung during startup",
        7023: "Service terminated with error",
        7024: "Service terminated (application error)",
        7026: "Boot/system driver failed",
        7031: "Service terminated unexpectedly",
        7034: "Service unexpectedly terminated",
        7036: "Service state changed",

        # --- System Stability ---
        41: "Kernel-Power unexpected restart",
        55: "File system corruption detected",
        98: "Volume mount issue",
        1001: "BugCheck (Blue Screen)",
        1014: "DNS name resolution failure",

        # --- Hardware / Disk ---
        7: "Disk bad block detected",
        11: "Disk controller error",
        15: "Disk not ready",
        51: "Disk paging error",
        129: "Storage reset",
        153: "Disk retry operation",

        # --- Power & Sleep ---
        1: "System resumed from sleep",
        42: "System entering sleep",

        # --- Time Service ---
        35: "Time service synchronization failed",
        36: "Time service synchronized",
        37: "Time provider error",

        # --- Network ---
        4201: "Network adapter connected",
        4202: "Network adapter disconnected",

        # --- User Profile / Registry ---
        1500: "User profile cannot be loaded",
        1501: "User profile restored from backup",
        1508: "Registry file could not be loaded",
        1511: "Temporary user profile loaded",

        # --- NTFS / File System ---
        50: "Delayed write failed",
        57: "File system data corruption detected",

        # --- Storage / Disk ---
        140: "Disk configuration changed",
        157: "Disk has been removed unexpectedly",
        161: "Dump file creation failed",

        # --- Boot / Startup ---
        18: "System boot performance issue",
        27: "Boot device initialization problem",

        # --- Driver Framework ---
        20001: "Driver Framework initialization failed",
        20003: "Device driver failure",

        # --- Windows Update ---
        19: "Windows Update installation successful",
        20: "Windows Update installation failed",
        21: "Windows Update restart required",

        # --- Resource Exhaustion ---
        2004: "Resource exhaustion detected (low memory)",
    }

    @staticmethod
    def _get_event_counts(log_name, event_map, heading, report_widget=None):
        """Query event counts for the last 24 hours for the given Windows log."""
        result = {"Last 24 Hours": []}

        def _append_widget(text):
            if report_widget:
                report_widget.config(state="normal")
                report_widget.insert("end", text)
                report_widget.see("end")
                report_widget.config(state="disabled")

        try:
            events = []

            for event_id, desc in event_map.items():
                cmd = [
                    _system_exe("wevtutil"),
                    "qe",
                    log_name,
                    f"/q:*[System[(EventID={int(event_id)}) and TimeCreated[timediff(@SystemTime) <= 86400000]]]",
                    "/f:text",
                ]

                try:
                    output = subprocess.check_output(
                        cmd,
                        shell=False,
                        text=True,
                        env=_safe_subproc_env(),
                        creationflags=_CREATE_NO_WINDOW,
                        startupinfo=_STARTUPINFO,
                    ).strip()

                    count = sum(1 for line in output.splitlines() if line.startswith("Event[")) if output else 0
                    events.append({
                        "Event ID": event_id,
                        "Description": desc,
                        "Count": count
                    })

                except subprocess.CalledProcessError:
                    _append_widget("  Access denied\n")
                    return None

            result["Last 24 Hours"] = events

            if report_widget:
                report_widget.config(state="normal")
                report_widget.insert("end", heading)
                for event in events:
                    report_widget.insert(
                        "end",
                        f"  {event['Description']} ({event['Event ID']}): {event['Count']}\n"
                    )
                report_widget.see("end")
                report_widget.config(state="disabled")

        except Exception:
            result["Last 24 Hours"] = "Access denied"
            _append_widget("  Access denied\n")

        return result

    @staticmethod
    def _format_events(data):
        """Formats the event counts as a clean table."""
        lines = ["", "–" * 80, "Last 24 Hours:", "–" * 80]

        events = data.get("Last 24 Hours", [])

        if isinstance(events, str):
            lines.append(f"    {events}")
        elif events:
            lines.append(
                f"    {'Event Description':<45}"
                f"{'Event ID':>14}"
                f"{'Cases':>14}"
            )
            lines.append("    " + "–" * 76)

            for event in events:
                lines.append(
                    f"    {event['Description']:<45}"
                    f"{event['Event ID']:>14}"
                    f"{event['Count']:>14}"
                )
        else:
            lines.append("    None Detected")

        return "\n".join(lines)

    def _collect_and_format(self, log_name, event_map, heading, report_widget=None):
        result = self._get_event_counts(
            log_name,
            event_map,
            heading,
            report_widget=report_widget,
        )
        if result is None:
            return {"Last 24 Hours": "Access denied"}
        return self._format_events(result)

    def get_security_events(self, report_widget=None):
        """
        Return security event counts for the last 24 hours.
        Prints live output to report_widget if provided.
        """
        return self._collect_and_format(
            "Security",
            self.SECURITY_EVENTS,
            "  Security Events — Last 24 Hours\n\n",
            report_widget=report_widget,
        )

    def get_system_events(self, report_widget=None):
        """
        Return system event counts for the last 24 hours.
        Prints live output to report_widget if provided.
        """
        return self._collect_and_format(
            "System",
            self.SYSTEM_EVENTS,
            "  System Events — Last 24 Hours\n\n",
            report_widget=report_widget,
        )

# ===== Windows Updates =====
class WindowsUpdates:
    """Query Windows release metadata, latest Microsoft builds, and installed updates."""

    WIN11_RELEASES = {
        22000: "21H2",
        22621: "22H2",
        22631: "23H2",
        26100: "24H2",
        26200: "25H2",
        28000: "26H1",
        26300: "26H2",
    }

    WIN10_RELEASES = {
        19042: "20H2",
        19043: "21H1",
        19044: "21H2",
        19045: "22H2",
    }

    RELEASE_DATES = {
        # Windows 10
        ("Windows 10", "1507"): "July 29, 2015",
        ("Windows 10", "1511"): "November 10, 2015",
        ("Windows 10", "1607"): "August 2, 2016",
        ("Windows 10", "1703"): "April 11, 2017",
        ("Windows 10", "1709"): "October 17, 2017",
        ("Windows 10", "1803"): "April 30, 2018",
        ("Windows 10", "1809"): "November 13, 2018",
        ("Windows 10", "1903"): "May 21, 2019",
        ("Windows 10", "1909"): "November 12, 2019",
        ("Windows 10", "2004"): "May 27, 2020",
        ("Windows 10", "20H2"): "October 20, 2020",
        ("Windows 10", "21H1"): "May 18, 2021",
        ("Windows 10", "21H2"): "November 16, 2021",
        ("Windows 10", "22H2"): "October 18, 2022",

        # Windows 11
        ("Windows 11", "21H2"): "October 4, 2021",
        ("Windows 11", "22H2"): "September 20, 2022",
        ("Windows 11", "23H2"): "October 31, 2023",
        ("Windows 11", "24H2"): "October 1, 2024",
        ("Windows 11", "25H2"): "September 30, 2025",
        ("Windows 11", "26H1"): "February 10, 2026",
        ("Windows 11", "26H2"): "September 29, 2026",

        # Windows Server
        ("Windows Server 2016", "1607"): "August 2, 2016",
        ("Windows Server 2019", "1809"): "November 13, 2018",
        ("Windows Server 2022", "21H2"): "August 18, 2021",
        ("Windows Server 2025", "24H2"): "November 1, 2024",
    }

    RELEASE_HEALTH_SOURCES = (
        (
            "https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information",
            {
                "Windows 11 23H2": r"\b22631\.\d{1,6}\b",
                "Windows 11 24H2": r"\b26100\.\d{1,6}\b",
                "Windows 11 25H2": r"\b26200\.\d{1,6}\b",
                "Windows 11 26H1": r"\b28000\.\d{1,6}\b",
                "Windows 11 26H2": r"\b26300\.\d{1,6}\b",
            },
        ),
        (
            "https://learn.microsoft.com/en-us/windows/release-health/release-information",
            {
                "Windows 10 22H2": r"\b19045\.\d{1,6}\b",
            },
        ),
        (
            "https://learn.microsoft.com/en-us/windows/release-health/windows-server-release-info",
            {
                "Server 2016": r"\b14393\.\d{1,6}\b",
                "Server 2019": r"\b17763\.\d{1,6}\b",
                "Server 2022": r"\b20348\.\d{1,6}\b",
                "Server 2025": r"\b26100\.\d{1,6}\b",
            },
        ),
    )

    SERVER_BUILD_KEYS = {
        "Windows Server 2016": "Server 2016",
        "Windows Server 2019": "Server 2019",
        "Windows Server 2022": "Server 2022",
        "Windows Server 2025": "Server 2025",
    }

    @classmethod
    def get_windows_11_release(cls, build):
        """Determine Windows 11 release from OS build."""
        return cls.WIN11_RELEASES.get(build)

    @classmethod
    def get_windows_10_release(cls, build):
        """Determine Windows 10 release from OS build."""
        return cls.WIN10_RELEASES.get(build)

    @classmethod
    def get_windows_release_date(cls, os_name, release):
        """Return initial release date string for a Windows OS release."""
        return cls.RELEASE_DATES.get((os_name, release))

    @classmethod
    def fetch_latest_builds(cls):
        """Fetch latest Windows builds from Microsoft's release-health pages."""
        builds = {}

        try:
            for url, patterns in cls.RELEASE_HEALTH_SOURCES:
                resp = requests.get(url, timeout=10)
                resp.raise_for_status()
                text = resp.text

                for name, pattern in patterns.items():
                    matches = re.findall(pattern, text)
                    if matches:
                        builds[name] = max(
                            matches,
                            key=lambda x: tuple(int(v) for v in x.split(".")),
                        )

        except Exception as e:
            print(f"[Windows Build Fetch] Error: {e}")

        return builds

    @classmethod
    def _parse_release_date(cls, os_name, release):
        date_str = cls.RELEASE_DATES.get((os_name, release))
        if not date_str:
            return datetime.min
        try:
            return datetime.strptime(date_str, "%B %d, %Y")
        except ValueError:
            return datetime.min

    @classmethod
    def _select_latest_build(cls, os_name, builds, release=None):
        if os_name in ("Windows 11", "Windows 10"):
            prefix = f"{os_name} "
            matching = {
                key: value
                for key, value in builds.items()
                if key.startswith(prefix)
            }
            if not matching:
                return None

            # Compare within the host's own serviced release channel when available
            if release:
                own_key = f"{os_name} {release}"
                if own_key in matching:
                    return matching[own_key]

            # Fallback for EOL/unlisted releases: pick the chronologically newest release
            # rather than max build number (Win11 26H1=28000 Feb 2026 vs 26H2=26300 Sept 2026)
            _, latest_build = max(
                matching.items(),
                key=lambda item: (
                    cls._parse_release_date(os_name, item[0][len(prefix):]),
                    tuple(int(v) for v in item[1].split(".")),
                ),
            )
            return latest_build

        server_key = cls.SERVER_BUILD_KEYS.get(os_name)
        return builds.get(server_key) if server_key else None

    @staticmethod
    def _determine_status(local_build, local_ubr, latest_build):
        if not latest_build:
            # Local information is still valid; only the online comparison failed.
            return "Unable to check online"

        try:
            latest_base, latest_ubr = [int(x) for x in latest_build.split(".")]

            # Different base build = different release/build
            if local_build < latest_base:
                return "Outdated"
            if local_build > latest_base:
                # Local build newer than the currently known Microsoft build.
                return "Updated"
            # Same base build -- compare revision.
            return "Outdated" if local_ubr < latest_ubr else "Updated"

        except Exception as e:
            print(f"[Windows Version Compare] Error: {e}")
            return "Unknown"

    def check_windows_version_status(self, run_all_clicked=None, single_check=None):
        """Check local Windows version/build against latest Microsoft builds."""
        global _windows_version_cache

        if run_all_clicked is None:
            run_all_clicked = globals()["run_all_clicked"]
        if single_check is None:
            single_check = globals()["single_check"]

        if (
            _windows_version_cache is not None
            and not run_all_clicked
            and not single_check
        ):
            return _windows_version_cache

        # Get local Windows information
        local_info = get_local_windows_info()

        if not local_info:
            _windows_version_cache = {
                "OS": None,
                "Version": None,
                "Local Build": None,
                "Latest Build": None,
                "Status": "Unknown",
            }
            return _windows_version_cache

        product_name = local_info["ProductName"]
        display_version = local_info["DisplayVersion"]
        edition_id = local_info["EditionID"]
        edition = get_windows_edition(edition_id)
        local_build = local_info["Build"]
        local_ubr = local_info["UBR"]
        local_build_full = local_info["FullBuild"]

        # Determine OS
        os_name = get_windows_os_name(product_name, local_build)

        # Determine release
        release = None
        if os_name == "Windows 11":
            release = self.get_windows_11_release(local_build)
        elif os_name == "Windows 10":
            release = self.get_windows_10_release(local_build)

        # Fetch Microsoft information
        builds = self.fetch_latest_builds()
        latest_build = self._select_latest_build(os_name, builds, release=release or display_version)
        status = self._determine_status(local_build, local_ubr, latest_build)

        # Combine OS and edition into one row
        os_edition = f"{os_name} {edition}" if edition else os_name

        # Format Windows release and initial release date
        version = release or display_version
        release_date = self.get_windows_release_date(os_name, version)

        if release_date:
            version = f"{version} (Released {release_date})"

        # Cache result
        _windows_version_cache = {
            "OS": os_edition,
            "Version": version,
            "Local Build": local_build_full,
            "Latest Build": latest_build,
            "Status": status,
        }

        return _windows_version_cache

    @staticmethod
    def get_windows_updates():
        """Get installed Windows updates."""
        installed_updates = []

        try:
            pythoncom.CoInitialize()
        except Exception:
            pass

        try:
            c = wmi.WMI()

            for hotfix in c.Win32_QuickFixEngineering():
                installed_on = hotfix.InstalledOn if hotfix.InstalledOn else "Unknown"
                installed_updates.append(f"{hotfix.HotFixID} {installed_on}")

        except Exception as e:
            installed_updates.append(f"Error retrieving installed updates: {e}")

        finally:
            try:
                pythoncom.CoUninitialize()
            except Exception:
                pass

        return installed_updates

    def display_windows_update_info(self):
        """
        Retrieves Windows updates, version status,
        and returns a formatted multi-line report.
        """
        updates = self.get_windows_updates()
        version_status = self.check_windows_version_status()

        info = {
            "Version Status": version_status,
            "Installed Updates": updates,
        }

        report = [""]
        keys = list(info.keys())

        for i, key in enumerate(keys):
            value = info[key]
            report.append(f"{key}:")

            if isinstance(value, dict):
                subkeys = list(value.keys())

                for j, (k, v) in enumerate(value.items()):
                    report.append(f"  {k}:")

                    if isinstance(v, dict):
                        subsubkeys = list(v.keys())
                        for subk_i, (subk, subv) in enumerate(v.items()):
                            report.append(f"    {subk}:")
                            for item in subv:
                                report.append(f"      - {item}")
                            if subk_i != len(subsubkeys) - 1:
                                report.append("–" * 50)
                    elif isinstance(v, list):
                        for item in v:
                            report.append(f"    - {item}")
                    else:
                        report.append(f"    {v}")

                    if j != len(subkeys) - 1:
                        report.append("–" * 50)

            elif isinstance(value, list):
                for item in value:
                    report.append(f"  - {item}")

            else:
                report.append(f"  {value}")

            if i != len(keys) - 1:
                report.append("–" * 50)

        return "\n".join(report)
