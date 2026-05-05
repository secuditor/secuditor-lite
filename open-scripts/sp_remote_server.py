# MIT License – Copyright (c) 2025 Menahem Levinski

"""
Inspects the system for server side remote features.
"""

import os
import sys
import subprocess
import socket
import json
import re
import winreg
import threading
import itertools
import time

def running_in_idle():
    return "idlelib" in sys.modules

# --- Dots worker ---
class Spinner:
    """Simple console spinner/dots animation in a separate thread."""
    def __init__(self, message: str = "Working"):
        self.message = message
        self._stop_event = threading.Event()
        self.thread = threading.Thread(target=self._spin, daemon=True)

    def _spin(self):
        for dots in itertools.cycle(["", ".", "..", "...", "....", "....."]):
            if self._stop_event.is_set():
                break
            print(f"\r{self.message}{dots}   ", end="", flush=True)
            time.sleep(0.5)
            
        print("\r" + " " * (len(self.message) + 10) + "\r", end="", flush=True)

    def start(self):
        self.thread.start()

    def stop(self):
        self._stop_event.set()
        self.thread.join()

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
        "WEB": "Unknown",
        "IAS": "Unknown",
        "PKI": "Unknown",
        "SSH": "Unknown",
        "SNMP": "Unknown",
        "SMTP": "Unknown",
        "POP3": "Unknown",
        "IMAP": "Unknown",
        "DFSR": "Unknown",
        "LDAP": "Unknown",
        "MSMQ": "Unknown",
        "SQLDB": "Unknown",
        "RRAS": "Unknown",
        "VMMS": "Unknown",
        "TlntSvr": "Unknown",
    }
    
    # --- DHCP Server ---
    try:
        output = subprocess.check_output(
            'powershell -Command "Get-Service DHCPServer -ErrorAction Stop | Select-Object -ExpandProperty Status"',
            shell=True, text=True, encoding="utf-8"
        ).strip()

        if output.lower() == "running":
            result["DHCP"] = "Running"
        elif output.lower() == "stopped":
            result["DHCP"] = "Stopped"
        else:
            result["DHCP"] = f"{output or 'Unknown'}"

    except subprocess.CalledProcessError:
        result["DHCP"] = "Not Installed"
    except Exception:
        result["DHCP"] = "Unknown"
    
    # --- DNS Server ---
    try:
        output = subprocess.check_output(
            'powershell -Command "Get-Service DNS -ErrorAction Stop | Select-Object -ExpandProperty Status"',
            shell=True, text=True, encoding="utf-8"
        ).strip()

        if output.lower() == "running":
            result["DNS"] = "Running"
        elif output.lower() == "stopped":
            result["DNS"] = "Stopped"
        else:
            result["DNS"] = f"{output or 'Unknown'}"

    except subprocess.CalledProcessError:
        result["DNS"] = "Not Installed"
    except Exception:
        result["DNS"] = "Unknown"
        
    # --- FTP Server ---
    try:
        service_state = None
        ftp_detected = False

        # 1. Known FTP server services (APP detection)
        ftp_services = {
            "ftpsvc": "IIS FTP Service",
            "filezilla": "FileZilla Server"
        }

        try:
            service_cmd = (
                'powershell -NoProfile -Command '
                '"Get-Service | Where-Object { '
                '$_.Name -match \'ftpsvc|filezilla\' '
                '} | Select-Object Name, Status | ConvertTo-Json"'
            )

            services = subprocess.check_output(
                service_cmd, shell=True, text=True, encoding="utf-8"
            ).strip()

            if services:
                data = json.loads(services)

                if isinstance(data, dict):
                    data = [data]

                for svc in data:
                    name = svc.get("Name", "").lower()
                    status = svc.get("Status")

                    if "filezilla" in name:
                        ftp_detected = True

                    if "ftpsvc" in name:
                        ftp_detected = True

                    if status == "Running":
                        service_state = "Running"
                        ftp_detected = True
                    elif status == "Stopped" and service_state is None:
                        service_state = "Stopped"

        except Exception:
            pass

        # 2. Port-based detection (FTP/FTPS)
        if not ftp_detected:
            try:
                netstat = subprocess.check_output(
                    "netstat -ano",
                    shell=True,
                    text=True,
                    encoding="utf-8"
                )

                if re.search(r":21\s+.*LISTENING", netstat) or re.search(r":990\s+.*LISTENING", netstat):
                    ftp_detected = True
                    service_state = "Running"

            except Exception:
                pass

        # 3. Process-based detection
        if not ftp_detected:
            try:
                tasklist = subprocess.check_output(
                    "tasklist",
                    shell=True,
                    text=True,
                    encoding="utf-8"
                ).lower()

                if "filezilla server.exe" in tasklist:
                    ftp_detected = True
                    service_state = "Running"

            except Exception:
                pass

        # 4. Final normalization (STATE ONLY)
        if ftp_detected:
            result["FTP"] = "Running (Exposed Service)"

        elif service_state == "Stopped":
            result["FTP"] = "Stopped"

        else:
            result["FTP"] = "Not Installed"

    except Exception:
        result["FTP"] = "Unknown"
        
    # --- NTP Server ---
    try:
        service_name = "Windows Time"
        status = None

        # 1. Service query (core state)
        output = _run(["sc", "query", "w32time"]).upper()

        if "SERVICE_NAME" not in output:
            result["NTP"] = f"Not Installed"

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
            result["NTP"] = f"{service_name} is {status}"

    except Exception:
        result["NTP"] = "Unknown"
        
    # --- WEB Server ---
    try:
        web_server = None   # <-- IMPORTANT (you removed it)
        status = None

        # 1. IIS Service (W3SVC)
        try:
            output = subprocess.check_output(
                'powershell -Command "Get-Service W3SVC -ErrorAction Stop | Select-Object -ExpandProperty Status"',
                shell=True,
                text=True
            ).strip()

            web_server = "IIS"   # <-- FIX HERE
            status = output

        except subprocess.CalledProcessError:
            web_server = None
        except Exception:
            pass

        # 2. IIS Express (dev server)
        if web_server is None:
            try:
                output = subprocess.check_output(
                    'powershell -Command "Get-Process | Where-Object {$_.Name -like \'iisexpress*\'}"',
                    shell=True,
                    text=True
                )

                if output.strip():
                    web_server = "IIS Express"
                    status = "Running"
            except Exception:
                pass

        # 3. Apache (fallback check)
        if web_server is None:
            try:
                output = subprocess.check_output(
                    'powershell -Command "Get-Process | Where-Object {$_.Name -like \'httpd*\'}"',
                    shell=True,
                    text=True
                )

                if output.strip():
                    web_server = "Apache"
                    status = "Running"
            except Exception:
                pass

        # 4. nginx (rare on Windows)
        if web_server is None:
            try:
                output = subprocess.check_output(
                    'powershell -Command "Get-Process | Where-Object {$_.Name -like \'nginx*\'}"',
                    shell=True,
                    text=True
                )

                if output.strip():
                    web_server = "Nginx"   # normalize name
                    status = "Running"
            except Exception:
                pass

        # 5. Port exposure check (80/443)
        port_open = False
        for port in [80, 443]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                if sock.connect_ex(("127.0.0.1", port)) == 0:
                    port_open = True
                sock.close()
            except Exception:
                pass

        # 6. Final classification
        if web_server is None:
            result["WEB"] = "Not Installed"
        else:
            if status == "Running":
                base = f"{web_server} is Running"
            elif status == "Stopped":
                base = f"{web_server} is Stopped"
            else:
                base = f"{web_server} is Unknown"

            if not port_open:
                base += " (No Port Binding)"

            result["WEB"] = base

    except Exception:
        result["WEB"] = "Unknown"
            
    # --- SSH Service ---
    try:
        ssh_services = {
            "sshd": "OpenSSH",
            "MobaSSHD": "MobaSSH",
            "FreeSSHD": "FreeSSHd",
            "ssh-agent": "OpenSSH-Agent"
        }

        detected = None
        status = None

        for svc, name in ssh_services.items():
            try:
                output = subprocess.check_output(
                    f'powershell -Command "Get-Service {svc} -ErrorAction Stop | Select-Object -ExpandProperty Status"',
                    shell=True,
                    text=True
                ).strip()

                detected = name
                status = output

                # don’t break blindly — ensure real service match
                break

            except subprocess.CalledProcessError:
                continue
            except Exception:
                continue

        if detected is None:
            result["SSH"] = "Not Installed"

        elif status == "Running":
            result["SSH"] = f"{detected} is Running (Exposed Service)"

        elif status == "Stopped":
            result["SSH"] = f"{detected} is Stopped"

        else:
            result["SSH"] = f"{detected} is {status}"

    except Exception:
        result["SSH"] = "Unknown"
            
    # --- Email Services ---
    try:
        email_services = {
            "SMTP": {
                "services": {
                    "SMTPSVC": "IIS SMTP Service",
                    "MSExchangeTransport": "Microsoft Exchange Transport",
                    "EdgeTransport": "Exchange Edge Transport",
                    "hMailServer": "hMailServer",
                    "MailEnable": "MailEnable",
                    "MDaemon": "MDaemon"
                }
            },
            "POP3": {
                "services": {
                    "POP3Svc": "IIS POP3 Service",
                    "MSExchangePOP3": "Exchange POP3",
                    "hMailServer": "hMailServer",
                    "MailEnable": "MailEnable"
                }
            },
            "IMAP": {
                "services": {
                    "IMAP4Svc": "IIS IMAP Service",
                    "MSExchangeIMAP4": "Exchange IMAP",
                    "hMailServer": "hMailServer",
                    "MailEnable": "MailEnable"
                }
            }
        }

        for proto, config in email_services.items():
            detected_name = None
            state = None

            # 1. Detect real mail server product
            for svc, name in config["services"].items():
                try:
                    output = subprocess.check_output(
                        f'powershell -Command "Get-Service {svc} -ErrorAction Stop | Select-Object -ExpandProperty Status"',
                        shell=True,
                        text=True
                    ).strip()

                    if output == "Running":
                        detected_name = name
                        state = "Running"
                        break

                    elif output == "Stopped" and state is None:
                        detected_name = name
                        state = "Stopped"

                except subprocess.CalledProcessError:
                    continue

            # 2. No service found
            if detected_name is None:
                result[proto] = "Not Installed"
            else:
                result[proto] = f"{detected_name} is {state}"

    except Exception:
        result["SMTP"] = "Unknown"
        result["POP3"] = "Unknown"
        result["IMAP"] = "Unknown"
        
    # --- LDAP Role ---
    try:
        status = None
        is_dc = False

        # 1. AD DS service (LDAP backend)
        try:
            cmd = (
                'powershell -Command '
                '"Get-Service NTDS -ErrorAction Stop | '
                'Select-Object -ExpandProperty Status"'
            )

            output = subprocess.check_output(
                cmd, shell=True, text=True, encoding="utf-8"
            ).strip()

            if output.lower() == "running":
                status = "Running"
                is_dc = True
            elif output.lower() == "stopped":
                status = "Stopped"
                is_dc = True
            else:
                status = output or "Unknown"
                is_dc = True

        except subprocess.CalledProcessError:
            status = "Not Installed"
        except Exception:
            status = "Unknown"

        # 2. LDAP port check (real exposure)
        ldap_exposed = False

        for port in [389, 636]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)

                if sock.connect_ex(("127.0.0.1", port)) == 0:
                    ldap_exposed = True

                sock.close()
            except Exception:
                pass

        # 3. Final normalization (SIMPLE STATE ONLY)
        if status == "Running" and ldap_exposed:
            result["LDAP"] = "Running"

        elif status == "Running":
            result["LDAP"] = "Running"

        elif status == "Stopped":
            result["LDAP"] = "Stopped"

        elif status == "Not Installed":
            result["LDAP"] = "Not Installed"

        else:
            result["LDAP"] = "Unknown"

    except Exception:
        result["LDAP"] = "Unknown"
        
    # --- TlntSvr Server ---
    try:
        service_name = "TlntSvr"
        detected = "Telnet Server"
        state = None

        try:
            output = subprocess.check_output(
                'powershell -Command "Get-Service TlntSvr -ErrorAction Stop | Select-Object -ExpandProperty Status"',
                shell=True,
                text=True,
                encoding="utf-8"
            ).strip()

            if output == "Running":
                state = "Running"
            elif output == "Stopped":
                state = "Stopped"
            else:
                state = "Unknown"

        except subprocess.CalledProcessError:
            state = "Not Installed"

        except Exception:
            state = "Unknown"

        # --- Final structured output ---
        if state == "Running":
            result["TlntSvr"] = f"{detected} is Running (High Risk)"
        elif state == "Stopped":
            result["TlntSvr"] = f"{detected} is Stopped"
        elif state == "Not Installed":
            result["TlntSvr"] = "Not Installed"
        else:
            result["TlntSvr"] = f"{detected} is {state}"

    except Exception:
        result["TlntSvr"] = "Unknown"
        
    # --- SNMP Server ---
    try:
        output = subprocess.check_output(
            'powershell -Command "Get-Service SNMP -ErrorAction Stop | Select-Object -ExpandProperty Status"',
            shell=True, text=True
        ).strip()
        if output == "Running":
            result["SNMP"] = "Running"
        elif output == "Stopped":
            result["SNMP"] = "Stopped"
        else:
            result["SNMP"] = output or "Unknown"
    except subprocess.CalledProcessError:
        result["SNMP"] = "Not Installed"
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
            result["PKI"] = "Not Installed"

        elif "RUNNING" in output:
            result["PKI"] = "Running"

        elif "STOPPED" in output:
            result["PKI"] = "Stopped"

        else:
            result["PKI"] = "Unknown"

    except subprocess.CalledProcessError:
        result["PKI"] = "Not Installed"
    except Exception:
        result["PKI"] = "Unknown"
        
    # --- DFSR service ---
    try:
        cmd = 'powershell -Command "Get-Service DFSR -ErrorAction Stop | Select-Object -ExpandProperty Status"'
        output = subprocess.check_output(cmd, shell=True, text=True, encoding="utf-8").strip()

        if output.lower() == "running":
            result["DFSR"] = "Running"

        elif output.lower() == "stopped":
            result["DFSR"] = "Stopped"

        else:
            result["DFSR"] = output if output else "Unknown"

    except subprocess.CalledProcessError:
        result["DFSR"] = "Not Installed"
    except Exception:
        result["DFSR"] = "Unknown"
        
    # --- SQL Databases (MSSQL / MySQL / MariaDB / PostgreSQL / MongoDB) ---
    try:
        output = subprocess.check_output(
            "sc query state= all",
            shell=True,
            text=True,
            encoding="utf-8",
            stderr=subprocess.DEVNULL
        ).lower()

        # 1. DB engine definitions
        db_engines = {
            "MSSQL": {
                "match": ["mssqlserver", "mssql$"],
                "name": "Microsoft SQL Server"
            },
            "MySQL": {
                "match": ["mysql"],
                "name": "MySQL Server"
            },
            "MariaDB": {
                "match": ["mariadb"],
                "name": "MariaDB Server"
            },
            "PostgreSQL": {
                "match": ["postgres", "postgresql"],
                "name": "PostgreSQL Server"
            },
            "MongoDB": {
                "match": ["mongodb"],
                "name": "MongoDB Server"
            }
        }

        instances = []

        # 2. Extract services
        for line in output.splitlines():
            if "service_name" in line:
                svc = line.split(":", 1)[1].strip()

                for engine, meta in db_engines.items():
                    if any(key in svc for key in meta["match"]):
                        instances.append((engine, svc))

        # 3. No DB found
        if not instances:
            result["SQLDB"] = "Not Installed"

        else:
            detected = {}

            # 4. Check each instance state
            for engine, svc in instances:
                try:
                    state = subprocess.check_output(
                        f"sc query {svc}",
                        shell=True,
                        text=True,
                        encoding="utf-8",
                        stderr=subprocess.DEVNULL
                    ).lower()

                    if "running" in state:
                        detected[engine] = "Running"

                    elif "stopped" in state:
                        detected[engine] = "Stopped"

                    else:
                        detected[engine] = "Unknown"

                except subprocess.CalledProcessError:
                    detected[engine] = "Unknown"

            # 5. Format output (clean)
            result["SQLDB"] = ", ".join(
                f"{db_engines[k]['name']} ({v})"
                for k, v in detected.items()
            )

    except Exception:
        result["SQLDB"] = "Unknown"
        
    # --- MSMQ (Message Queuing) ---
    try:
        output = subprocess.check_output(
            'powershell -Command "Get-Service MSMQ -ErrorAction Stop | Select-Object -ExpandProperty Status"',
            shell=True,
            text=True,
            encoding="utf-8"
        ).strip()

        if output.lower() == "running":
            result["MSMQ"] = "Running"

        elif output.lower() == "stopped":
            result["MSMQ"] = "Stopped"

        else:
            result["MSMQ"] = output if output else "Unknown"

    except subprocess.CalledProcessError:
        result["MSMQ"] = "Not Installed"

    except Exception:
        result["MSMQ"] = "Unknown"

    # --- RRAS (Routing and Remote Access Service) ---
    try:
        output = subprocess.check_output(
            'powershell -Command "Get-Service RemoteAccess -ErrorAction Stop | Select-Object -ExpandProperty Status"',
            shell=True,
            text=True,
            encoding="utf-8"
        ).strip()

        if output.lower() == "running":
            result["RRAS"] = "Running"

        elif output.lower() == "stopped":
            result["RRAS"] = "Stopped"

        else:
            result["RRAS"] = output if output else "Unknown"

    except subprocess.CalledProcessError:
        result["RRAS"] = "Not Installed"

    except Exception:
        result["RRAS"] = "Unknown"
        
    # --- IAS (Internet Authentication Service) ---
    try:
        output = subprocess.check_output(
            'powershell -Command "Get-Service IAS -ErrorAction Stop | Select-Object -ExpandProperty Status"',
            shell=True,
            text=True,
            encoding="utf-8"
        ).strip()

        if output.lower() == "running":
            result["IAS"] = "Running"

        elif output.lower() == "stopped":
            result["IAS"] = "Stopped"

        else:
            result["IAS"] = output if output else "Unknown"

    except subprocess.CalledProcessError:
        result["IAS"] = "Not Installed"

    except Exception:
        result["IAS"] = "Unknown"
        
    # --- VMMS / Virtualization Services (Hyper-V, VMware, VirtualBox) ---
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
            if "service_name" in line:

                svc = line.split(":", 1)[1].strip()

                # Hyper-V
                if svc == "vmms":
                    instances.append(svc)

                # VMware
                elif svc in [
                    "vmwareauthorizationservice",
                    "vmwareworkstationserver",
                    "vmnetdhcp",
                    "vmnetnat"
                ]:
                    instances.append(svc)

                # VirtualBox
                elif svc in ["vboxdrv", "vboxsvc"]:
                    instances.append(svc)

        # No virtualization detected
        if not instances:
            result["VMMS"] = "Not Installed"

        else:
            running = False
            stopped = False

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

                    elif "stopped" in state:
                        stopped = True

                except subprocess.CalledProcessError:
                    continue

            # Final decision (consistent model)
            if running:
                result["VMMS"] = "Running"
            elif stopped:
                result["VMMS"] = "Stopped"
            else:
                result["VMMS"] = "Unknown"

    except Exception:
        result["VMMS"] = "Unknown"

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

    if running_in_idle():
        print("Working... (please wait)")
        report = get_remote_server_settings()
    else:
        spinner = Spinner("Working")
        spinner.start()
        try:
            report = get_remote_server_settings()
        finally:
            spinner.stop()

    print(report)
    print("")
    os.system("pause")
