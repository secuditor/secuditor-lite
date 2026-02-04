# MIT License – Copyright (c) 2025 Menny Levinski

"""
Detects remote access capabilities and services exposure.
"""

import os
import subprocess
import winreg
import json
import socket

# --- Helper ---
def _run(cmd):
    try:
        return subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
    except Exception:
        return ""
    
# --- WinRM Settings ---
def check_winrm_service():
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

def check_winrm_startup():
    output = _run(["sc", "qc", "WinRM"])
    if "AUTO_START" in output:
        return "Automatic"
    if "DEMAND_START" in output:
        return "Manual"
    if "DISABLED" in output:
        return "Disabled"
    return "Unknown"

def check_listeners():
    output = _run(["winrm", "enumerate", "winrm/config/listener"])
    return {
        "http": "Transport = HTTP" in output,
        "https": "Transport = HTTPS" in output
    }

def check_ports():
    ports = []
    for port in (5985, 5986):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                ports.append(port)
    return ports

def check_auth():
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Service\Auth"
        ) as key:
            auth = {}
            for name in ["Basic", "Kerberos", "Negotiate", "Certificate"]:
                try:
                    auth[name] = bool(winreg.QueryValueEx(key, name)[0])
                except FileNotFoundError:
                    auth[name] = False
            return auth
    except Exception:
        return {}

def check_encryption():
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Service"
        ) as key:
            allow = winreg.QueryValueEx(key, "AllowUnencrypted")[0]
            return not bool(allow)
    except Exception:
        return True

def assess_risk(service, listeners, auth, encrypted):
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

def audit_winrm():
    service = check_winrm_service()
    startup = check_winrm_startup()
    listeners = check_listeners()
    ports = check_ports()
    auth = check_auth()
    encrypted = check_encryption()
    risk = assess_risk(service, listeners, auth, encrypted)
    verdict = winrm_verdict(service, listeners, ports, risk)

    return {
        "service": service,
        "startup": startup,
        "listeners": listeners,
        "ports": ports,
        "authentication": auth,
        "encryption": encrypted,
        "risk": risk,
        "verdict": verdict
    }

def winrm_verdict(service, listeners, ports, risk):
    status = service.get("status", "Unknown").lower()

    if status != "enabled":
        return "Disabled, no exposure, no risk"

    if not listeners.get("http") and not listeners.get("https"):
        return "Enabled, no listeners, low risk"

    if not ports:
        return "Enabled, no ports listening, low risk"

    if risk == "Low":
        return "Enabled, restricted exposure, medium risk"

    if risk == "Medium":
        return "Enabled, network exposure, medium risk"

    if risk in ("High", "Critical"):
        return "Enabled, remote access exposed, high risk"

    return "Enabled, exposure unknown, unknown risk"

# --- Remote Access Settings ---
def get_remote_access_settings():
    result = {
        "Remote Desktop": "Unknown",
        "Remote Assistance": "Unknown",
        "PowerShell Remoting": "Unknown",
        "COM Network Service": "Unknown",
        "RPC Print Service": "Unknown",
        "Rsync Service": "Unknown",
        "Telnet Service": "Unknown",
        "Bluetooth": "Unknown",
        "NetBIOS": "Unknown",
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
                                verdict = "Enabled, Low Risk"
                            else:
                                verdict = "Enabled, Potentially Dangerous (Without NLA or using weak encryption)"
                    except FileNotFoundError:
                        verdict = "Enabled, Potentially Dangerous (Configuration missing or insecure)"
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
        cmd = (
            'powershell -Command '
            '"Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol | '
            'Select-Object -ExpandProperty State"'
        )
        output = subprocess.check_output(cmd, shell=True, text=True, encoding="utf-8").strip()

        # --- Final verdict ---
        if output == "Enabled":
            verdict = "Enabled, Potentially Dangerous"  # SMB1 enabled → insecure
        elif output == "Disabled":
            verdict = "Disabled"  # Safe
        else:
            verdict = output or "Unknown"

        result["SMB1"] = verdict

    except subprocess.CalledProcessError:
        result["SMB1"] = "Disabled"
    except Exception:
        result["SMB1"] = "Unknown"

    # --- SMB2 ---
    try:
        result["SMB2"] = "Unknown"
        internal = {}

        # Get SMB2 configuration
        cmd = (
            'powershell -Command '
            '"Get-SmbServerConfiguration | '
            'Select-Object EnableSMB2Protocol, RequireSecuritySignature, EncryptData, EnableGuestAccess, EnableSMB1Protocol, AuditSmbAccess | '
            'ConvertTo-Json"'
        )
        output = subprocess.check_output(cmd, shell=True, text=True, encoding="utf-8").strip()
        data = json.loads(output)

        enable_smb2 = data.get("EnableSMB2Protocol", False)
        signing = data.get("RequireSecuritySignature", False)
        encryption = data.get("EncryptData", False)
        guest = data.get("EnableGuestAccess", False)
        smb1_enabled = data.get("EnableSMB1Protocol", False)
        audit = data.get("AuditSmbAccess", False)

        internal.update({
            "EnableSMB2Protocol": enable_smb2,
            "RequireSecuritySignature": signing,
            "EncryptData": encryption,
            "EnableGuestAccess": guest,
            "EnableSMB1Protocol": smb1_enabled,
            "AuditSmbAccess": audit,
            "InsecurePermissions": False
        })

        insecure_permissions = False

        if enable_smb2:
            # Check SMB shares for insecure access
            try:
                cmd_shares = (
                    'powershell -Command '
                    '"Get-SmbShare | '
                    'Select-Object Name, Path, FullAccess, ChangeAccess, ReadAccess | ConvertTo-Json"'
                )
                shares_output = subprocess.check_output(cmd_shares, shell=True, text=True, encoding="utf-8").strip()
                shares_data = json.loads(shares_output)

                if isinstance(shares_data, dict):
                    shares_data = [shares_data]

                for share in shares_data:
                    for access_type in ["FullAccess", "ChangeAccess", "ReadAccess"]:
                        users = share.get(access_type, [])
                        if isinstance(users, str):
                            users = [users]
                        for u in users:
                            if u.lower() in ["everyone", "guest", "anonymous"]:
                                insecure_permissions = True
            except Exception:
                insecure_permissions = False

            internal["InsecurePermissions"] = insecure_permissions

            # Determine final verdict
            if not insecure_permissions:
                if signing or encryption:
                    verdict = "Enabled, Low Risk"
                else:
                    verdict = "Enabled, Moderate Risk"
            else:
                verdict = "Enabled, Potentially Dangerous (shares allow Guest/Everyone/Anonymous access or weak SMB configuration)"
        else:
            verdict = "Disabled"

        result["SMB2"] = verdict

    except Exception:
        result["SMB2"] = "Unknown"

    # --- Bluetooth ---
    try:
        cmd = (
            'powershell -Command '
            '"Get-PnpDevice -Class Bluetooth -ErrorAction SilentlyContinue | '
            'Select-Object -ExpandProperty Status"'
        )
        output = subprocess.check_output(cmd, shell=True, text=True, encoding="utf-8").strip()

        if not output or "OK" not in output:
            result["Bluetooth"] = "Disabled"
        else:
            # --- Check Bluetooth ---
            try:
                cmd = (
                    'powershell -Command '
                    '"Get-Service bthserv -ErrorAction SilentlyContinue | '
                    'Select-Object -ExpandProperty Status"'
                )
                service_output = subprocess.check_output(cmd, shell=True, text=True, encoding="utf-8").strip()
                service_running = service_output == "Running"
            except Exception:
                service_running = False

            # --- Assess risk ---
            if service_running:
                verdict = "Enabled, Low Risk"
            else:
                verdict = "Enabled, Potentially Dangerous (service inactive or misconfigured, may allow unprotected pairing attempts)"

            result["Bluetooth"] = verdict

    except subprocess.CalledProcessError:
        result["Bluetooth"] = "Disabled"
    except Exception:
        result["Bluetooth"] = "Unknown"

    # --- COM Network Service ---
    try:
        # --- Check if DCOM is enabled ---
        cmd = r'powershell -Command "Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Ole -ErrorAction SilentlyContinue | Select-Object -ExpandProperty EnableDCOM"'
        reg_output = subprocess.check_output(cmd, shell=True, text=True, encoding="utf-8").strip()

        # --- Check Windows Firewall status (any profile) ---
        try:
            fw_status = subprocess.check_output(
                'powershell -Command "Get-NetFirewallProfile | Select-Object -ExpandProperty Enabled"',
                shell=True, text=True
            ).strip().lower()
            firewall_on = "true" in fw_status
        except Exception:
            firewall_on = False  # assume off if detection fails

        if reg_output == "Y":
            # 🔹 Check authentication level
            try:
                cmd = r'powershell -Command "Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Ole -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LegacyAuthenticationLevel"'
                auth_output = subprocess.check_output(cmd, shell=True, text=True, encoding="utf-8").strip()
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
                cmd = r'powershell -Command "Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Ole -ErrorAction SilentlyContinue | Select-Object -ExpandProperty RequireIntegrityActivationAuthenticationLevel"'
                harden_output = subprocess.check_output(cmd, shell=True, text=True, encoding="utf-8").strip()
                harden_state = "Enabled" if harden_output == "1" else "Disabled"
            except Exception:
                harden_state = "Unknown"

            # 🔹 Determine final verdict
            if auth_state in ["Packet Integrity (Safe)", "Packet Privacy (Best)"]:
                reg_state = "Enabled, Low Risk"
            elif harden_state == "Enabled":
                reg_state = "Enabled, Hardened by Patch"
            else:
                # Weak authentication / no hardening → potentially dangerous
                if firewall_on:
                    reg_state = "Enabled, Moderate Risk (Firewall On)"
                else:
                    reg_state = "Enabled, Potentially Dangerous (Firewall Off)"

        elif reg_output == "N":
            reg_state = "Remote Disabled"
        else:
            reg_state = "Unknown"

    except Exception:
        reg_state = "Unknown"

    result["COM Network Service"] = reg_state

    # --- NetBIOS ---
    try:
        output = subprocess.check_output("ipconfig /all", shell=True, text=True, encoding="utf-8")
        for line in output.splitlines():
            if "NetBIOS over Tcpip" in line:
                # Extract status after the colon
                result["NetBIOS"] = line.split(":")[-1].strip()
                break
    except Exception:
        result["NetBIOS"] = "Unknown"

    # --- Remote Assistance ---
    try:
        key_path = r"SYSTEM\CurrentControlSet\Control\Remote Assistance"
        with winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE) as hklm:
            with winreg.OpenKey(hklm, key_path) as key:
                ra_value, _ = winreg.QueryValueEx(key, "fAllowToGetHelp")
                result["Remote Assistance"] = "Enabled" if ra_value == 1 else "Disabled"
    except FileNotFoundError:
        result["Remote Assistance"] = "Disabled"
    except PermissionError:
        result["Remote Assistance"] = "Unknown"
    except Exception:
        result["Remote Assistance"] = "Unknown"

    # --- PowerShell Remoting (WinRM) ---
    try:
        # Check if WinRM service exists and status
        cmd_status = (
            'powershell -Command "if (Get-Service -Name WinRM -ErrorAction SilentlyContinue) {'
            '(Get-Service -Name WinRM).Status} else {\'NotInstalled\'}"'
        )
        winrm_status = subprocess.check_output(cmd_status, shell=True, text=True, encoding="utf-8").strip().lower()

        if not winrm_status or winrm_status == "notinstalled":
            result["PowerShell Remoting"] = "Disabled"
        elif winrm_status != "running":
            result["PowerShell Remoting"] = "Disabled"
        else:
            # Check if any WSMan listener exists (Server 2022 reliable method)
            cmd_listener = (
                'powershell -Command "if (Get-ChildItem WSMan:\\localhost\\Listener -ErrorAction SilentlyContinue) {\'Enabled\'} else {\'Disabled\'}"'
            )
            listener_status = subprocess.check_output(cmd_listener, shell=True, text=True, encoding="utf-8").strip().lower()

            if "enabled" in listener_status:
                result["PowerShell Remoting"] = "Enabled"
            else:
                # Fallback: AllowRemoteShellAccess registry
                cmd_reg = (
                    r'powershell -Command "$val = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Service -ErrorAction SilentlyContinue).AllowRemoteShellAccess; '
                    r'if ($val -eq $null) {\'Unknown\'} elseif ($val -eq 1 -or $val -eq \'true\') {\'Enabled\'} else {\'Disabled\'}"'
                )
                reg_status = subprocess.check_output(cmd_reg, shell=True, text=True, encoding="utf-8").strip().lower()
                if reg_status in ("enabled", "1", "true"):
                    result["PowerShell Remoting"] = "Enabled"
                elif reg_status == "disabled":
                    result["PowerShell Remoting"] = "Disabled"
                else:
                    result["PowerShell Remoting"] = "Unknown"

    except Exception:
        result["PowerShell Remoting"] = "Unknown"

    # --- RPC Print Service ---
    try:
        # Check if RPC Print Service key exists
        check_rpc = subprocess.run(
            'powershell -Command "Test-Path HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Print\\RpcEnabled"',
            shell=True, text=True, capture_output=True
        ).stdout.strip()

        if check_rpc.lower() == "true":
            # Read RpcEnabled value
            rpc_value = subprocess.check_output(
                'powershell -Command "Get-ItemProperty -Path HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Print '
                '| Select-Object -ExpandProperty RpcEnabled"',
                shell=True, text=True, errors="ignore"
            ).strip()

            if rpc_value == "1":
                # --- Service is enabled, assess risk ---
                # Check if remote clients are restricted
                restrict_clients = subprocess.run(
                    'powershell -Command "Get-ItemProperty -Path HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Print '
                    '| Select-Object -ExpandProperty RestrictRemoteClients"',
                    shell=True, text=True, capture_output=True
                ).stdout.strip()

                # Check if privacy/authentication is enabled
                privacy_enabled = subprocess.run(
                    'powershell -Command "Get-ItemProperty -Path HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Print '
                    '| Select-Object -ExpandProperty RpcAuthnLevelPrivacyEnabled"',
                    shell=True, text=True, capture_output=True
                ).stdout.strip()

                # Determine risk with explanations
                if restrict_clients == "1" and privacy_enabled == "1":
                    verdict = "Enabled, Low Risk (restricted to authenticated clients and privacy enabled)"
                elif restrict_clients == "1" or privacy_enabled == "1":
                    verdict = "Enabled, Moderate Risk (partially secured; either restricted clients or privacy enabled)"
                else:
                    verdict = "Enabled, Potentially Dangerous (open to unauthenticated network access, no privacy)"

            else:
                verdict = "Disabled"
        else:
            verdict = "Disabled"

        result["RPC Print Service"] = verdict

    except Exception:
        result["RPC Print Service"] = "Unknown"

    # --- Rsync Service ---
    try:
        output = subprocess.check_output(
            'powershell -Command "Get-Service rsync -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Status"',
            shell=True, text=True
        ).strip()
        if output == "Running":
            result["Rsync Service"] = "Enabled"
        elif output == "Stopped":
            result["Rsync Service"] = "Disabled"
        elif output == "":
            result["Rsync Service"] = "Disabled"
        else:
            result["Rsync Service"] = output or "Unknown"
    except subprocess.CalledProcessError:
        result["Rsync Service"] = "Disabled"
    except Exception:
        result["Rsync Service"] = "Unknown"

    # --- Telnet Service ---
    try:
        output = subprocess.check_output(
            'powershell -Command "Get-Service TlntSvr -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Status"',
            shell=True, text=True
        ).strip()
        if output == "Running":
            result["Telnet Service"] = "Enabled"
        elif output == "Stopped":
            result["Telnet Service"] = "Disabled"
        elif output == "":
            result["Telnet Service"] = "Disabled"
        else:
            result["Telnet Service"] = output or "Unknown"
    except subprocess.CalledProcessError:
        result["Telnet Service"] = "Disabled"
    except Exception:
        result["Telnet Service"] = "Unknown"

    # --- WinRM ---
    winrm_data = audit_winrm()
    result["WinRM"] = winrm_data["verdict"]

    return format_remote_access_settings(result)

def format_remote_access_settings(settings):
    report = [""]
    keys = list(settings.keys())
    
    for i, key in enumerate(keys):
        report.append(f"{key}:")
        report.append(f"  {settings[key]}")
        if i != len(keys) - 1:
            report.append("–" * 40)

    return "\n".join(report)

# --- Output ---
if __name__ == "__main__":
    print("Remote Access Report")
    print("–" * len("Remote Access Report"))
    print(get_remote_access_settings())
    print("")

    os.system("pause")
