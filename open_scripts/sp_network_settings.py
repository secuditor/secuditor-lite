# MIT License – Copyright (c) 2025 Menny Levinski

"""
Presents the device's network adapters and configurations.
"""

import os
import re
import json
import subprocess
import ipaddress

# --- Detect network adapter headers (Ethernet, Wi-Fi, etc.) ---
def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def get_network_settings():
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

    adapter_macs_seen = set()  # global MAC deduplication

    try:
        output_lines = subprocess.check_output(
            "ipconfig /all", shell=True
        ).decode(errors="ignore").splitlines()

        collecting_dns = False
        collecting_gateway = False
        current_adapter_ips = []  # list of tuples (ip, mask_or_none)
        current_adapter_has_ipv4 = False

        for idx, raw_line in enumerate(output_lines):
            line = raw_line.strip()

            # --- Adapter header detection ---
            if raw_line and not raw_line.startswith(" ") and "adapter" in raw_line.lower():
                # Flush previous adapter IPs
                if current_adapter_ips:
                    if current_adapter_has_ipv4:
                        for ip, mask in current_adapter_ips:
                            if ipaddress.ip_address(ip.split("/")[0]).version == 4:
                                network_info["Local Ips"].append(ip)
                                network_info["Subnet Masks"].append(mask)
                    else:
                        for ip, mask in current_adapter_ips:
                            network_info["Local Ips"].append(ip)
                            if mask:
                                network_info["Subnet Masks"].append(mask)
                # Reset per new adapter
                current_adapter_ips = []
                current_adapter_has_ipv4 = False

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
                gw = line.split(":")[-1].strip()
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

            # --- MAC Address (global deduplication) ---
            if "Physical Address" in line:
                mac = line.split(":")[-1].strip()
                if re.match(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$", mac):
                    if mac not in adapter_macs_seen:
                        network_info["MAC Addresses"].append(mac)
                        adapter_macs_seen.add(mac)

        # Flush last adapter IPs
        if current_adapter_ips:
            if current_adapter_has_ipv4:
                for ip, mask in current_adapter_ips:
                    if ipaddress.ip_address(ip.split("/")[0]).version == 4:
                        network_info["Local Ips"].append(ip)
                        network_info["Subnet Masks"].append(mask)
            else:
                for ip, mask in current_adapter_ips:
                    network_info["Local Ips"].append(ip)
                    if mask:
                        network_info["Subnet Masks"].append(mask)
                        
        # ---- Wi-Fi logic unchanged ----
        try:
            ps_cmd = (
                'powershell -Command "Get-NetAdapter -Physical | '
                'Where-Object {$_.InterfaceDescription -Match \'Wireless|Wi-Fi\'} | '
                'Select-Object Name, Status | ConvertTo-Json"'
            )
            adapters_json = subprocess.check_output(
                ps_cmd, shell=True, text=True, encoding="utf-8"
            ).strip()

            adapters = json.loads(adapters_json)
            if isinstance(adapters, dict):
                adapters = [adapters]

            ssid_output = subprocess.check_output(
                'netsh wlan show interfaces',
                shell=True,
                text=True,
                encoding="utf-8"
            ).strip()

            ssid_interfaces = {}
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
                report.append("–" * 40)

    return "\n".join(report)

# --- Output ---
if __name__ == "__main__":
    print("Network Settings Report")
    print("–" * len("Network Settings Report"))
    print(get_network_settings())
    print("")

    os.system("pause")
