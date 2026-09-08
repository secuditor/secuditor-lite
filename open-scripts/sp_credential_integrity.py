# MIT License – Copyright (c) 2025 Menahem Levinski

"""
Audits Windows credential protection mechanisms.

Third-party: psutil
"""

import os
import sys
import subprocess
import winreg
import hashlib
import psutil
import ctypes

_CREATE_NO_WINDOW = 0x08000000

_STARTUPINFO = subprocess.STARTUPINFO()
_STARTUPINFO.dwFlags |= subprocess.STARTF_USESHOWWINDOW
_STARTUPINFO.wShowWindow = subprocess.SW_HIDE

# --- Hide ps blue screens ---
def run_hidden_command(cmd_list):
    """
    Run a command completely hidden (no CMD/PowerShell window flashes)
    Returns the command output as a string
    """
    try:
        result = subprocess.run(
            cmd_list,
            capture_output=True,
            text=True,
            creationflags=_CREATE_NO_WINDOW,
            startupinfo=_STARTUPINFO
        )
        return result.stdout.strip()
    except Exception as e:
        return ""

# --- Hive Access Check ---
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def check_hive_access():
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
                f'icacls "{path}"',
                shell=True,
                text=True,
                errors="ignore"
            )

            if "NT AUTHORITY\\SYSTEM" in output:
                status = "Protected (SYSTEM only)"
            else:
                status = "Unknown"

            results.append(f"{path}\n    {status}")

        except Exception:
            results.append(f"{path}\n    Unknown")

    return "\n  ".join(results)

# --- Windows Credential Manager ---
def check_credential_manager():
    """
    Check whether Windows Credential Manager contains stored credentials.
    Does not access or expose credential contents.
    """
    try:
        output = run_hidden_command([
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
def check_credential_guard():
    if sys.platform != "win32":
        return "Not supported by current Windows edition"

    ps_cmd = [
        "powershell",
        "-NoProfile",
        "-NonInteractive",
        "-WindowStyle", "Hidden",
        "-Command",
        "Get-CimInstance -ClassName Win32_DeviceGuard | "
        "Select-Object -ExpandProperty SecurityServicesConfigured"
    ]

    output = run_hidden_command(ps_cmd)
    if not output:
        return "Not supported by current Windows edition"

    try:
        services = [int(x) for x in output.split() if x.isdigit()]
        return "Enabled" if 2 in services else "Disabled"
    except Exception:
        return "Unknown"

# --- WDigest ---
def check_wdigest():
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
def hash_file(filepath, algo='sha256'):
    h = hashlib.new(algo)
    try:
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

def verify_signature(filepath):
    ps_cmd = [
        "powershell",
        "-NoProfile",
        "-NonInteractive",
        "-WindowStyle", "Hidden",
        "-Command",
        f"(Get-AuthenticodeSignature '{filepath}').Status"
    ]
    output = run_hidden_command(ps_cmd)
    return output.lower() == "valid"

def check_lsass_integrity():
    details = {}
    lsass_path = r"C:\Windows\System32\lsass.exe"

    # Path
    details['Path'] = lsass_path if os.path.exists(lsass_path) else "lsass.exe not found"

    # SHA256
    details['SHA256'] = hash_file(lsass_path)

    # Suspicious processes
    suspicious = []
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if proc.info['pid'] == os.getpid():
                continue
            if proc.info['name'].lower() in ['procdump.exe', 'mimikatz.exe', 'dumpertool.exe']:
                suspicious.append(proc.info['name'])
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    if suspicious:
        details['SuspiciousProcesses'] = suspicious

    return details

# --- LSASS Protection ---
def check_lsass_protection():
    # Confirm LSASS is running
    lsass_running = any(proc.info['name'].lower() == 'lsass.exe' for proc in psutil.process_iter(['name']))
    if not lsass_running:
        return "Disabled (LSASS not running)"

    # Check RunAsPPL registry key
    try:
        key_path = r"SYSTEM\CurrentControlSet\Control\Lsa"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
            value, _ = winreg.QueryValueEx(key, "RunAsPPL")
            if value == 1:
                return "Enabled (Protected Process Light)"
            else:
                return "Disabled (LSASS not PPL-protected)"
    except FileNotFoundError:
        return "Disabled (RunAsPPL key not found)"
    except Exception as e:
        return f"Unknown (Error: {e})"

# --- LSASS Signature ---
def check_lsass_signature():
    lsass_path = r"C:\Windows\System32\lsass.exe"
    if not os.path.exists(lsass_path):
        return "lsass.exe not found"
    return "Valid" if verify_signature(lsass_path) else "Invalid"

# --- Run all credential checks ---
def run_credential_integrity_checks():
    check_hive_access_status = check_hive_access()
    credential_guard_status = check_credential_guard()
    wdigest_status = check_wdigest()
    lsass_details = check_lsass_integrity()
    lsass_protection_status = check_lsass_protection()
    lsass_signature_status = check_lsass_signature()
    credential_manager_status = check_credential_manager()

    report = [""]

    # LSASS details
    report.append("LSASS Integrity:")
    for key, value in lsass_details.items():
        report.append(f"  {key}:")
        report.append(f"    {value}")
        if key.lower() == "sha256":
            report.append("  WDigest:")
            report.append(f"    {wdigest_status}")
    report.append("–" * 40)

    # Credential Guard
    report.append("Credential Guard:")
    report.append(f"  {credential_guard_status}")
    report.append("–" * 40)

    # LSASS Protection
    report.append("LSASS Protection (RunAsPPL):")
    report.append(f"  {lsass_protection_status}")
    report.append("–" * 40)

    # LSASS Signature
    report.append("LSASS Signature:")
    report.append(f"  {lsass_signature_status}")
    report.append("–" * 40)

    # SAM Hive
    report.append("SAM Hive:")
    report.append(f"  {check_hive_access_status}")
    report.append("–" * 40)

    # Credential Manager
    report.append("Windows Credential Manager:")
    report.append(f"  {credential_manager_status}")

    return "\n".join(report)

# --- Output ---
if __name__ == "__main__":
    print("Credential Integrity Report")
    print("–" * len("Credential Integrity Report"))
    print(run_credential_integrity_checks())
    print("")

    os.system("pause")
