# MIT License – Copyright (c) 2025 Menny Levinski

"""
Inspects the system for server side remote features.
"""

import os
import subprocess
import socket
import json
import re
import winreg

# --- Helper ---
def _run(cmd):
    try:
        return subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
    except Exception:
        return ""

# --- Remote Server Settings ---
def get_remote_server_settings():
    result = {
        "DHCP": "Unknown",
        "DNS": "Unknown",
        "FTP": "Unknown",
        "NTP": "Unknown",
        "IIS": "Unknown",
        "PKI": "Unknown",
        "SSH": "Unknown",
        "SNMP": "Unknown",
        "SMTP": "Unknown",
        "POP3": "Unknown",
        "IMAP": "Unknown",
        "DFSR": "Unknown",
        "LDAP": "Unknown",
        "MSMQ":  "Unknown",
        "MSSQL":  "Unknown",
        "TlntSvr": "Unknown",
    }

    # --- DHCP Server ---
    try:
        output = subprocess.check_output(
            'powershell -Command "Get-Service DHCPServer -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Status"',
            shell=True, text=True, encoding="utf-8"
        ).strip()
        if output.lower() == "running":
            result["DHCP"] = "Enabled"
        elif output.lower() == "stopped":
            result["DHCP"] = "Disabled"
        elif output == "":
            result["DHCP"] = "No Server / Disabled"
        else:
            result["DHCP"] = output or "Unknown"
    except subprocess.CalledProcessError:
        result["DHCP"] = "No Server / Disabled"
    except Exception:
        result["DHCP"] = "Unknown"

    # --- DNS Server ---
    try:
        output = subprocess.check_output(
            'powershell -Command "Get-Service DNS -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Status"',
            shell=True, text=True, encoding="utf-8"
        ).strip()
        if output.lower() == "running":
            result["DNS"] = "Enabled"
        elif output.lower() == "stopped":
            result["DNS"] = "Disabled"
        elif output == "":
            result["DNS"] = "No Server / Disabled"
        else:
            result["DNS"] = output or "Unknown"
    except subprocess.CalledProcessError:
        result["DNS"] = "No Server / Disabled"
    except Exception:
        result["DNS"] = "Unknown"

    # --- FTP ---
    try:
        ftp_found = False

        # --- 1. Check known FTP services (IIS + FileZilla) ---
        service_cmd = (
            'powershell -NoProfile -Command '
            '"Get-Service | Where-Object { '
            '$_.Name -match \'ftpsvc|filezilla\' '
            '} | Select-Object Name, Status | ConvertTo-Json"'
        )

        try:
            services = subprocess.check_output(
                service_cmd, shell=True, text=True, encoding="utf-8"
            ).strip()
            services = json.loads(services) if services else []
        except Exception:
            services = []

        if isinstance(services, dict):
            services = [services]

        for svc in services:
            if svc.get("Status") == "Running":
                ftp_found = True

            output = _run(["sc", "qc", "w32time"])

        # --- 2. Check listening FTP / FTPS ports ---
        if not ftp_found:
            netstat = subprocess.check_output(
                "netstat -ano", shell=True, text=True, encoding="utf-8"
            )

            for line in netstat.splitlines():
                if (
                    re.search(r":21\s+.*LISTENING", line) or
                    re.search(r":990\s+.*LISTENING", line)
                ):
                    ftp_found = True
                    break

        # --- 3. Check FileZilla Server process ---
        if not ftp_found:
            tasklist = subprocess.check_output(
                "tasklist", shell=True, text=True, encoding="utf-8"
            ).lower()

            if "filezilla server.exe" in tasklist:
                ftp_found = True

        # --- Final state ---
        if ftp_found:
            result["FTP"] = "Enabled"
        else:
            result["FTP"] = "No Server / Disabled"

    except Exception:
        result["FTP"] = "Unknown"

    # --- NTP ---
    try:
        output = _run(["sc", "qc", "w32time"])
        
        if "SERVICE_NAME" not in output:
            result["NTP"] = "No Server / Disabled"
        elif "DISABLED" in output:
            result["NTP"] = "Disabled"
        else:
            # Check if the machine is configured as a server
            try:
                with winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SYSTEM\CurrentControlSet\Services\W32Time\Config"
                ) as key:
                    announce_flags = winreg.QueryValueEx(key, "AnnounceFlags")[0]
                    if announce_flags in (5, 10) and is_domain_controller():
                        result["NTP"] = "Enabled"
                    else:
                        result["NTP"] = "Disabled"
            except Exception:
                result["NTP"] = "Disabled"

    except Exception:
        result["NTP"] = "Unknown"
    
    # --- IIS ---
    try:
        output = subprocess.check_output(
            ["sc", "query", "W3SVC"],
            stderr=subprocess.STDOUT,
            text=True,
            shell=True
        ).upper()

        if "FAILED 1060" in output:
            result["IIS"] = "No Server / Disabled"
        elif "STATE" in output:
            if "RUNNING" in output:
                # check port 80 binding
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    if sock.connect_ex(("127.0.0.1", 80)) != 0:
                        result["IIS"] = "Enabled (No Binding)"
                    else:
                        result["IIS"] = "Enabled"
                    sock.close()
                except Exception:
                    result["IIS"] = "Enabled"
            else:
                result["IIS"] = "Disabled"
        else:
            result["IIS"] = "No Server / Disabled"

    except subprocess.CalledProcessError as e:
        if "1060" in str(e.output):
            result["IIS"] = "No Server / Disabled"
        else:
            result["IIS"] = "Unknown"
    except Exception:
        result["IIS"] = "Unknown"

    # --- SSH ---
    try:
        output = subprocess.check_output(
            'powershell -Command "Get-Service sshd -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Status"',
            shell=True, text=True
        ).strip()
        if output == "Running":
            result["SSH"] = "Enabled"
        elif output == "Stopped":
            result["SSH"] = "Disabled"
        elif output == "":
            result["SSH"] = "No Server / Disabled"
        else:
            result["SSH"] = output or "Unknown"
    except subprocess.CalledProcessError:
        result["SSH"] = "No Server / Disabled"
    except Exception:
        result["SSH"] = "Unknown"

    # --- Email Services ---
    email_services = {
        "SMTP": {"service": "SMTPSVC", "ports": [25, 465, 587]},
        "POP3": {"service": "POP3Svc", "ports": [110, 995]},
        "IMAP": {"service": "IMAP4Svc", "ports": [143, 993]},
    }

    for proto, info in email_services.items():
        try:
            output = subprocess.check_output(
                f'powershell -Command "Get-Service {info["service"]} -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Status"',
                shell=True, text=True
            ).strip()
            if output.lower() == "running":
                result[proto] = "Enabled"
            elif output.lower() == "stopped":
                result[proto] = "Disabled"
            elif output == "":
                result[proto] = "No Server / Disabled"
            else:
                result[proto] = output or "Unknown"

            # --- Check listening ports ---
            try:
                net_output = subprocess.check_output('netstat -ano | findstr LISTENING', shell=True, text=True).splitlines()
                port_open = any(
                    f":{port} " in line or f":{port}\r" in line
                    for line in net_output
                    for port in info["ports"]
                )
                if port_open:
                    result[proto] = "Enabled (Port Open)"
            except Exception:
                pass
        except subprocess.CalledProcessError:
            result[proto] = "No Server / Disabled"
        except Exception:
            result[proto] = "Unknown"

    # --- LDAP ---
    try:
        cmd = (
            'powershell -Command '
            '"Get-Service NTDS -ErrorAction SilentlyContinue | '
            'Select-Object -ExpandProperty Status"'
        )
        output = subprocess.check_output(cmd, shell=True, text=True, encoding="utf-8").strip()

        if output.lower() == "running":
            result["LDAP"] = "Enabled"
        elif output.lower() == "stopped":
            result["LDAP"] = "Disabled"
        elif output == "":
            result["LDAP"] = "No Server / Disabled"
        else:
            result["LDAP"] = output or "Unknown"

    except subprocess.CalledProcessError:
        result["LDAP"] = "No Server / Disabled"
    except Exception:
        result["LDAP"] = "Unknown"

    # --- TlntSvr ---
    try:
        output = subprocess.check_output(
            'powershell -Command "Get-Service TlntSvr -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Status"',
            shell=True, text=True
        ).strip()
        if output == "Running":
            result["TlntSvr"] = "Enabled"
        elif output == "Stopped":
            result["TlntSvr"] = "Disabled"
        elif output == "":
            result["TlntSvr"] = "No Server / Disabled"
        else:
            result["TlntSvr"] = output or "Unknown"
    except subprocess.CalledProcessError:
        result["TlntSvr"] = "No Server / Disabled"
    except Exception:
        result["TlntSvr"] = "Unknown"

    # --- SNMP ---
    try:
        output = subprocess.check_output(
            'powershell -Command "Get-Service SNMP -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Status"',
            shell=True, text=True
        ).strip()
        if output == "Running":
            result["SNMP"] = "Enabled"
        elif output == "Stopped":
            result["SNMP"] = "Disabled"
        elif output == "":
            result["SNMP"] = "No Server / Disabled"
        else:
            result["SNMP"] = output or "Unknown"
    except subprocess.CalledProcessError:
        result["SNMP"] = "No Server / Disabled"
    except Exception:
        result["SNMP"] = "Unknown"

    # --- PKI (AD CS) ---
    try:
        output = subprocess.check_output(
            ["sc", "query", "CertSvc"],
            stderr=subprocess.STDOUT,
            text=True,
            shell=True
        ).upper()

        if "FAILED 1060" in output or "DOES NOT EXIST" in output:
            result["PKI"] = "No Server / Disabled"
        elif "STATE" in output:
            if "RUNNING" in output:
                result["PKI"] = "Enabled"
            else:
                result["PKI"] = "Disabled"
        else:
            result["PKI"] = "No Server / Disabled"

    except subprocess.CalledProcessError as e:
        if "1060" in str(e.output):
            result["PKI"] = "No Server / Disabled"
        else:
            result["PKI"] = "Unknown"
    except Exception:
        result["PKI"] = "Unknown"

    # --- DFSR service ---
    try:
        cmd = 'powershell -Command "Get-Service DFSR -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Status"'
        output = subprocess.check_output(cmd, shell=True, text=True, encoding="utf-8").strip()

        if output.lower() == "running":
            result["DFSR"] = "Enabled"
        elif output.lower() == "stopped":
            result["DFSR"] = "Disabled"
        elif output == "":
            result["DFSR"] = "No Server / Disabled"
        else:
            result["DFSR"] = output or "Unknown"

    except subprocess.CalledProcessError:
        result["DFSR"] = "No Server / Disabled"
    except Exception:
        result["DFSR"] = "Unknown"

    # --- MSSQL (SQL Server Engine only) ---
    try:
        output = subprocess.check_output(
            "sc query state= all",
            shell=True,
            text=True,
            encoding="utf-8",
            stderr=subprocess.DEVNULL
        ).lower()

        instances = []

        for line in output.splitlines():
            if "service_name:" in line:
                svc = line.split(":", 1)[1].strip()
                if svc == "mssqlserver" or svc.startswith("mssql$"):
                    instances.append(svc)

        if not instances:
            result["MSSQL"] = "No Server / Disabled"
        else:
            running = False
            for inst in instances:
                try:
                    state = subprocess.check_output(
                        f"sc query {inst}",
                        shell=True,
                        text=True,
                        encoding="utf-8",
                        stderr=subprocess.DEVNULL
                    ).lower()

                    if "running" in state:
                        running = True
                        break
                except subprocess.CalledProcessError:
                    continue

            result["MSSQL"] = "Enabled" if running else "Disabled"

    except subprocess.CalledProcessError:
        result["MSSQL"] = "Unknown"
    except Exception:
        result["MSSQL"] = "Unknown"

        # --- MSMQ (Message Queuing) ---
    try:
        output = subprocess.check_output(
            'powershell -Command "Get-Service MSMQ -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Status"',
            shell=True, text=True, encoding="utf-8"
        ).strip()

        if output.lower() == "running":
            result["MSMQ"] = "Enabled"
        elif output.lower() == "stopped":
            result["MSMQ"] = "Disabled"
        elif output == "":
            result["MSMQ"] = "No Server / Disabled"
        else:
            result["MSMQ"] = output or "Unknown"

    except subprocess.CalledProcessError:
        result["MSMQ"] = "No Server / Disabled"
    except Exception:
        result["MSMQ"] = "Unknown"

    return format_remote_server_settings(result)
 
def format_remote_server_settings(settings):
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
    print("Remote Server Report")
    print("–" * len("Remote Server Report"))
    print(get_remote_server_settings())
    print("")

    os.system("pause")
