# MIT License – Copyright (c) 2025 Menny Levinski

"""
Reviews core Windows security posture settings.

Third-party: psutil
"""

import os
import re
import sys
import subprocess
import ctypes
import string
import winreg
import psutil
import datetime

# --- Helper ---
def _run(cmd):
    try:
        return subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
    except Exception:
        return ""

# --- Get the basic security settings ---
# --- BitLocker check ---
def check_bitlocker():
    """Return 'Enabled' if any volume is protected, else 'Disabled'."""
    try:
        output = subprocess.check_output(
            'powershell -Command "Get-BitLockerVolume | Select-Object -ExpandProperty ProtectionStatus"',
            shell=True, text=True, errors="ignore"
        ).strip().splitlines()
        if any(line.strip() == "1" for line in output):
            return "Enabled"
    except Exception:
        pass
    return "Disabled"

# --- Helper: detect removable drives ---
def get_removable_storage():
    """
    Detect removable storage (USB, CD/DVD, etc.).
    Returns a list like: ['E:\\ (USB)', 'D:\\ (CD/DVD)'] or "None Detected"
    """
    drives = []
    bitmask = ctypes.windll.kernel32.GetLogicalDrives()
    for letter in string.ascii_uppercase:
        if bitmask & 1:
            drive = f"{letter}:\\"
            try:
                drive_type = ctypes.windll.kernel32.GetDriveTypeW(drive)
                # DRIVE_REMOVABLE=2 (USB, floppy), DRIVE_CDROM=5
                if drive_type == 2:
                    drives.append(f"{drive} (USB/Removable)")
                elif drive_type == 5:
                    drives.append(f"{drive} (CD/DVD)")
            except Exception:
                continue
        bitmask >>= 1
    return drives if drives else "None Detected"

# --- Helper: detect system restore ---
def check_system_restore():
    """
    Check if System Restore is enabled and when last restore point was created.
    Returns: (status, last_restore)
    """
    result = "Unknown"
    last_restore = "N/A"

    # --- Check registry (client only) ---
    try:
        key_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore"
        with winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE) as hklm:
            with winreg.OpenKey(hklm, key_path) as key:
                try:
                    disable_sr, _ = winreg.QueryValueEx(key, "DisableSR")
                    result = "Disabled" if disable_sr == 1 else "Enabled"
                except FileNotFoundError:
                    result = "Enabled"
    except FileNotFoundError:
        result = "Unusable (Server)"
    except Exception:
        result = "Unknown"

    # --- Check last restore point via event log ---
    try:
        cmd = [
            "wevtutil", "qe", "System",
            "/q:*[System[Provider[@Name='Microsoft-Windows-SystemRestore']]]",
            "/c:1", "/f:text", "/rd:true"
        ]
        output = subprocess.check_output(cmd, text=True, errors="ignore")

        for line in output.splitlines():
            if "TimeCreated" in line:
                raw = line.split('"')[1]
                dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
                last_restore = dt.strftime("%Y-%m-%d %H:%M:%S")
                break
    except subprocess.CalledProcessError:
        pass
    except PermissionError:
        pass
    except Exception:
        pass

    return result

# --- Helper: detect secure boot ---
def check_secure_boot():
    """
    Secure Boot detection without admin rights.
    Priority:
      1. Registry (user-readable)
      2. WMI CIM fallback
    Returns: Enabled / Disabled / Unsupported / Unknown
    """
    # --- 1) Try registry (works on all modern Windows, no admin needed) ---
    try:
        reg_cmd = (
            'powershell -Command '
            '"Get-ItemProperty -Path '
            '\'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State\' '
            ' -Name UEFISecureBootEnabled | Select-Object -ExpandProperty UEFISecureBootEnabled"'
        )

        output = subprocess.check_output(
            reg_cmd, shell=True, text=True, encoding="utf-8",
            stderr=subprocess.STDOUT
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
        wmi_cmd = (
            'powershell -Command '
            '"Get-CimInstance -Namespace root\\Microsoft\\Windows\\HardwareManagement '
            ' -ClassName MS_SecureBoot | Select-Object -ExpandProperty SecureBootEnabled"'
        )

        wmi_output = subprocess.check_output(
            wmi_cmd, shell=True, text=True, encoding="utf-8",
            stderr=subprocess.STDOUT
        ).strip()

        if wmi_output.lower() == "true":
            return "Enabled"
        if wmi_output.lower() == "false":
            return "Disabled"
    except:
        pass

    # Neither registry nor WMI worked
    return "Unsupported"

# --- Helper: detect local firewall ---
def firewall_managed_by_safe():
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

# --- Main security settings ---
def get_security_settings():
    
    result = {
        "Windows Defender": [],
        "Endpoint Protection": [],
        "Local Firewall": "Unknown",
        "EFS Usage": "Unknown",
        "PATH Variables": "Unknown",
        "UAC Elevation": "Unknown",
        "Core Isolation": "Unknown",
        "PowerShell Scripts": "Unknown",
        "BitLocker": "Unknown",
        "Secure Boot": "Unknown",
        "Removable Storage": "Unknown",
        "System Restore": "Unknown",
    }

    # --- Windows Defender ---
    try:
        output = subprocess.check_output(
            'powershell -Command "Get-MpComputerStatus | Select-Object -ExpandProperty AMServiceEnabled"',
            shell=True, text=True, errors="ignore"
        ).strip()
        defender_active = output.lower() == "true"
        result["Windows Defender"].append(f"Windows Defender ({'Active' if defender_active else 'Inactive'})")
    except Exception:
        result["Windows Defender"].append("Windows Defender (Unknown)")

    # --- Third-party AV products ---
    try:
        command = (
            'powershell -Command "Get-CimInstance -Namespace \\"root/SecurityCenter2\\" '
            '-ClassName AntiVirusProduct | Select-Object displayName,productState"'
        )
        output = subprocess.check_output(command, shell=True, text=True, errors="ignore").strip()
        if output:
            lines = [line.strip() for line in output.splitlines() if line.strip() and "displayName" not in line]
            for line in lines:
                match = re.match(r"^(.*)\s+(\d+)$", line)
                if match:
                    name, state = match.groups()
                    name = name.strip()
                    if name.lower() == "windows defender":
                        continue
                    state = int(state)
                    active = (state & 0x10000) != 0 or (state & 0x40000) != 0
                    result["Endpoint Protection"].append(f"{name} ({'Active' if active else 'Inactive'})")
    except Exception:
        pass

    # --- Local Firewall (safe, no WMI / SecurityCenter2) ---
    try:
        # Detect controller
        fw_info = firewall_managed_by_safe()
        controller = fw_info["product_name"] if fw_info["managed"] else "Windows Firewall"

        # Check status via registry
        profiles = {"Domain": False, "Private": False, "Public": False}
        reg_path = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"
        profile_keys = {"Domain": "DomainProfile", "Private": "StandardProfile", "Public": "PublicProfile"}

        with winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE) as hklm:
            for name, subkey in profile_keys.items():
                try:
                    key_path = f"{reg_path}\\{subkey}"
                    with winreg.OpenKey(hklm, key_path) as key:
                        enabled, _ = winreg.QueryValueEx(key, "EnableFirewall")
                        profiles[name] = bool(enabled)
                except FileNotFoundError:
                    profiles[name] = False

        if all(profiles.values()):
            status = "On"
        elif any(profiles.values()):
            status = "Partially On"
        else:
            status = "Off"

        result["Local Firewall"] = f"{controller} ({status})"

    except Exception:
        result["Local Firewall"] = "Unknown"
    
    # --- UAC ---
    try:
        key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        with winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE) as hklm:
            with winreg.OpenKey(hklm, key_path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
                enable_uac, _ = winreg.QueryValueEx(key, "EnableLUA")
                if enable_uac:
                    # UAC is enabled, check level
                    consent_behavior, _ = winreg.QueryValueEx(key, "ConsentPromptBehaviorAdmin")
                    uac_levels = {
                        0: "Do not Prompt",
                        1: "Elevate without prompting",
                        2: "Prompt for credentials on secure desktop",
                        3: "Prompt for consent on secure desktop",
                        4: "Prompt for credentials",
                        5: "Prompt for consent"
                    }
                    level_desc = uac_levels.get(consent_behavior, f"Invalid ({consent_behavior})")
                    result["UAC Elevation"] = f"{level_desc}"
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
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
                value, _ = winreg.QueryValueEx(key, "Enabled")
                if value == 1:
                    result["Core Isolation"] = "Enabled"
                elif value == 0:
                    result["Core Isolation"] = "Disabled"
                else:
                    result["Core Isolation"] = "Unknown"
        except FileNotFoundError:
            cmd = (
                'powershell -Command '
                '"$dg = Get-CimInstance -ClassName Win32_DeviceGuard -ErrorAction SilentlyContinue; '
                'if ($dg) { '
                'if ($dg.SecurityServicesRunning -contains 1) {\'Enabled\'} '
                'else {\'Disabled\'} '
                '} else {\'Disabled\'}"'
            )
            status = subprocess.check_output(cmd, shell=True, text=True, encoding="utf-8").strip()
            if status.lower() in ("enabled", "disabled", "unknown"):
                result["Core Isolation"] = status.capitalize()
            else:
                result["Core Isolation"] = "Unknown"
    except Exception as e:
        result["Core Isolation"] = f"Error: {e}"

    # --- PATH Variables ---
    try:
        path = os.environ.get("PATH", "")
        path_dirs = path.split(os.pathsep)
        
        result["PATH Variables"] = "Default"  # default
        for p in path_dirs:
            p = p.strip()
            if not p:
                continue
            # Flag non-existent directories or Downloads folders in PATH
            if not os.path.exists(p) or ("downloads" in p.lower() and "users" in p.lower()):
                result["PATH Variables"] = "Suspicious"
                break  # stop after first suspicious entry

    except Exception:
        result["PATH Variables"] = "Unknown"

    # --- PowerShell Scripts ---
    try:
        cmd = 'powershell -NoProfile -Command "Get-ExecutionPolicy"'
        output = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.DEVNULL).strip()

        # Normalize common values
        valid_policies = ["Restricted", "RemoteSigned", "AllSigned", "Unrestricted", "Bypass", "Undefined"]
        if output in valid_policies:
            result["PowerShell Scripts"] = output
        else:
            result["PowerShell Scripts"] = "Unknown"

    except Exception:
        result["PowerShell Scripts"] = "Unknown"

    # --- BitLocker ---
    result["BitLocker"] = check_bitlocker()

    # --- System Restore ---
    result["System Restore"] = check_system_restore()

    # --- Secure Boot ---
    result["Secure Boot"] = check_secure_boot()

    # --- Removable Storage (USB / CD/DVD) ---
    try:
        removable = get_removable_storage()
        if isinstance(removable, list):
            result["Removable Storage"] = ", ".join(removable)
        else:
            result["Removable Storage"] = removable
    except Exception:
        result["Removable Storage"] = "Unknown"

    # --- EFS Usage ---
    try:
        efs_found = False
        for root, dirs, files in os.walk(os.path.expanduser("~")):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    attrs = ctypes.windll.kernel32.GetFileAttributesW(file_path)
                    if attrs & 0x4000:  # FILE_ATTRIBUTE_ENCRYPTED
                        efs_found = True
                        break
                except Exception:
                    continue
            if efs_found:
                break
        result["EFS Usage"] = "Encrypted files found" if efs_found else "No encrypted files"
    except Exception:
        result["EFS Usage"] = "Unknown"

    return format_security_settings(result)

def format_security_settings(settings):
    report = [""]

    keys = list(settings.keys())
    for i, key in enumerate(keys):
        value = settings[key]

        # Section header
        report.append(f"{key}:")

        # Handle lists (e.g., Defender, Endpoint Protection)
        if isinstance(value, list):
            if not value:
                report.append("  (None)")
            else:
                for item in value:
                    report.append(f"  {item}")
        else:
            report.append(f"  {value}")

        # Add separator only if not last section
        if i != len(keys) - 1:
            report.append("–" * 40)

    return "\n".join(report)

# --- Output ---
if __name__ == "__main__":
    print("Security Settings Report")
    print("–" * len("Security Settings Report"))
    print(get_security_settings())
    print("")

    os.system("pause")
