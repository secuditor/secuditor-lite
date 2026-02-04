# MIT License – Copyright (c) 2025 Menny Levinski

"""
Presents the device's network adapters and configurations.
"""

import os
import re
import json
import subprocess

# --- Detect network adapter headers (Ethernet, Wi-Fi, etc.) ---
def get_network_settings():
    """
    Get local IPs, subnet masks, DNS servers, default gateways, DHCP servers,
    MAC addresses, external IP, and Wi-Fi adapter status.
    Returns a nicely formatted string with separators.
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

    try:
        # --- IPConfig parsing ---
        output = subprocess.check_output("ipconfig /all", shell=True).decode(errors="ignore")
        collecting_dns = collecting_ip = collecting_gateway = False

        for line in output.splitlines():
            line = line.strip()
            if "DNS Servers" in line:
                dns = line.split(":")[-1].strip()
                if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", dns):
                    network_info["DNS Servers"].append(dns)
                collecting_dns = True
            elif collecting_dns and re.match(r"^\d{1,3}(\.\d{1,3}){3}$", line):
                network_info["DNS Servers"].append(line)
            else:
                collecting_dns = False

            if "IPv4 Address" in line:
                ip = line.split(":")[-1].split("(")[0].strip()
                if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
                    network_info["Local Ips"].append(ip)
                collecting_ip = True
            elif collecting_ip and "Subnet Mask" in line:
                mask = line.split(":")[-1].strip()
                network_info["Subnet Masks"].append(mask)
            else:
                collecting_ip = False

            if "Default Gateway" in line:
                gw = line.split(":")[-1].strip()
                if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", gw):
                    network_info["Default Gateways"].append(gw)
                collecting_gateway = True
            elif collecting_gateway and re.match(r"^\d{1,3}(\.\d{1,3}){3}$", line):
                network_info["Default Gateways"].append(line)
            else:
                collecting_gateway = False

            if "DHCP Server" in line:
                dhcp = line.split(":")[-1].strip()
                if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", dhcp):
                    network_info["DHCP Servers"].append(dhcp)

            if "Physical Address" in line:
                mac = line.split(":")[-1].strip()
                if re.match(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$", mac):
                    network_info["MAC Addresses"].append(mac)

        # --- Wi-Fi adapters ---
        try:
            ps_cmd = (
                'powershell -Command "Get-NetAdapter -Physical | '
                'Where-Object {$_.InterfaceDescription -Match \'Wireless|Wi-Fi\'} | '
                'Select-Object Name, Status | ConvertTo-Json"'
            )
            adapters_json = subprocess.check_output(ps_cmd, shell=True, text=True, encoding="utf-8").strip()
            adapters = json.loads(adapters_json)
            if isinstance(adapters, dict):
                adapters = [adapters]

            ssid_output = subprocess.check_output('netsh wlan show interfaces', shell=True, text=True, encoding="utf-8").strip()
            ssid_interfaces = {}
            current_name = None
            for line in ssid_output.splitlines():
                line = line.strip()
                if line.startswith("Name") and ":" in line:
                    current_name = line.split(":", 1)[1].strip()
                    ssid_interfaces[current_name] = "Not Connected"
                elif line.startswith("SSID") and ":" in line and current_name:
                    ssid_value = line.split(":", 1)[1].strip()
                    if ssid_value != "":
                        ssid_interfaces[current_name] = ssid_value

            for adapter in adapters:
                name = adapter["Name"]
                status = adapter["Status"]
                adapter_str = f"{name} ({status})"
                if status.lower() == "up":
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

    # --- Format report with separators ---
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
            report.append(f"{key}:")  # Header
            value = network_info[key]

            if isinstance(value, list):
                for item in value:
                    report.append(f"  {item}")
            else:
                report.append(f"  {value}")

            # Add the line only if this is NOT the last key
            if i != len(keys_order) - 1:
                report.append("–" * 40)

    return "\n".join(report)

# --- Output ---
if __name__ == "__main__":
    print("Network Settings Report")
    print("–" * len("Network Settings Report"))
    print(get_network_settings())
    print("")

    os.system("pause")
