# MIT License – Copyright (c) 2025 Menny Levinski

"""
Detects the local network's default gateway and public IP.

Third-party: requests (urllib3), psutil.
"""

import subprocess
import platform
import warnings
import os
import re
import requests
import psutil
import socket
from urllib3.exceptions import InsecureRequestWarning

# --- Suppress HTTPS certificate warnings ---
warnings.simplefilter("ignore", InsecureRequestWarning)

# --- Get default gateway ---
def get_default_gateway():
    """Return dict with IPv4 and IPv6 default gateways."""

    gateways = {"IPv4": None, "IPv6": None}

    try:
        output = subprocess.check_output(
            "ipconfig", shell=True, text=True, encoding="utf-8", errors="ignore"
        )

        for line in output.splitlines():
            if "Default Gateway" in line:
                ip = line.split(":")[-1].strip()

                # IPv4
                if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
                    gateways["IPv4"] = ip

                # IPv6
                elif ":" in ip:
                    gateways["IPv6"] = ip.split("%")[0]  # remove scope id

    except Exception:
        pass

    if not gateways["IPv4"] and not gateways["IPv6"]:
        return None
    
    return gateways

def ping_device(ip):
    """Ping IPv4 or IPv6 device."""
    try:
        system = platform.system().lower()

        if ":" in ip:  # IPv6
            param = "-n" if system == "windows" else "-c"
            cmd = ["ping", "-6", param, "1", ip]
        else:  # IPv4
            param = "-n" if system == "windows" else "-c"
            cmd = ["ping", param, "1", ip]

        result = subprocess.run(cmd, capture_output=True, text=True)
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

def get_mac_from_arp(ip):
    """Get MAC address for IPv4 only."""

    if ":" in ip:
        return None  # IPv6 → no ARP

    try:
        output = subprocess.check_output("arp -a", shell=True, text=True)
        for line in output.splitlines():
            if ip in line:
                mac_match = re.search(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})", line)
                if mac_match:

                    return mac_match.group(0)
    except Exception:
        pass

    return None

def lookup_vendor(mac, device_ip=None):
    """
    Lookup vendor from MAC address.
    1. Try macvendors.com API.
    2. Identify virtual / locally administered MACs.
    3. Optional: use ping_device for TTL/response heuristics if IP is provided.
    """
    
    if not mac:
        return "Unknown"

    vendor = "Unknown"
    oui = mac.replace("-", ":").upper()[:8]

    # --- First: try online API ---
    try:
        response = requests.get(f"https://api.macvendors.com/{mac}", timeout=3)
        if response.status_code == 200:
            api_vendor = response.text.strip()
            if api_vendor and "unknown" not in api_vendor.lower():
                vendor = api_vendor
    except Exception:
        pass

    # --- Second: check for virtual / locally administered MAC ---
    try:
        first_byte = int(mac.split("-")[0], 16)
        if first_byte & 0b00000010:
            vendor = "Virtual/Software MAC"
    except Exception:
        pass

    # --- Third: optional TTL-based heuristic ---
    if device_ip:
        reply = ping_device(device_ip)
        ttl_match = re.search(r"TTL=(\d+)", reply, re.IGNORECASE)
        if ttl_match:
            ttl = int(ttl_match.group(1))
            if ttl <= 64:
                vendor = "Likely Linux/Unix device"
            elif ttl <= 128:
                vendor = "Likely Windows device"
            elif ttl <= 255:
                vendor = "Likely network appliance / router"

    return vendor

def check_http_access(ip):
    """Check HTTP/HTTPS for IPv4 or IPv6."""
    for scheme in ["http", "https"]:
        try:
            if ":" in ip:  # IPv6
                url = f"{scheme}://[{ip}]"
            else:
                url = f"{scheme}://{ip}"

            r = requests.get(url, timeout=3, verify=False)
            if r.status_code < 500:
                return f"{scheme.upper()} Responding ({r.status_code})"
        except Exception:
            continue
    return "No web interface detected"

def detect_nat():
    """
    Detect NAT by comparing local and external IPs.
    Fully independent: retrieves local and external IPs itself.

    Returns:
        str: NAT detection result.
    """
    try:
        # --- Get local IPs via ipconfig ---
        output = subprocess.check_output("ipconfig", shell=True).decode(errors="ignore")
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
            return "Unable to determine"

        local_ip = local_ips[0]
        if local_ip != external_ip:
            return f"Detected"
        else:
            return "NoDetect"

    except Exception:
        return "Error during detection"

def get_external_ip():
    """Discover external/public IP."""
    try:
        return requests.get("https://api.ipify.org", timeout=5).text.strip()
    except Exception:
        return "Unavailable"

def detect_gateway_device():
    """Main detection routine — returns a dict with gateway info."""
    result = {
        "Vendor": "Unknown",
        "MAC": "Unknown",
        "IP": "Unavailable",
        "PING": "Unknown",
        "GUI": "Unknown",
        "NAT": "Unknown",
        "VPN": "Unknown",
        "Public IP": "Unavailable"
    }

    gateways = get_default_gateway()
    if not gateways:
        result["IP"] = "Not Found"
        return result

    gw_ip = gateways.get("IPv4") or gateways.get("IPv6")
    result["IP"] = f"IPv4: {gateways.get('IPv4') or 'None'} | IPv6: {gateways.get('IPv6') or 'None'}"
    if not gateways:
        result["IP"] = "Not Found"
        return result

    # Gather gateway info
    result["IP"] = gw_ip
    result["Public IP"] = get_external_ip()
    result["PING"] = ping_device(gw_ip)

    mac = get_mac_from_arp(gw_ip)
    result["MAC"] = mac if mac else "Unknown"

    result["Vendor"] = lookup_vendor(mac)
    result["NAT"] = detect_nat()
    result["GUI"] = check_http_access(gw_ip)
    
    # --- VPN Client check ---
    try:
        vpn_adapters = []
        vpn_connected = False

        for name, addrs in psutil.net_if_addrs().items():
            # Detect common VPN interfaces
            if any(keyword in name.lower() for keyword in ["vpn", "ppp", "tap", "tun"]):
                vpn_adapters.append(name)
                # Check if adapter has a valid IP
                for addr in addrs:
                    if addr.family == socket.AF_INET and not addr.address.startswith("169.254"):
                        vpn_connected = True

        if not vpn_adapters:
            result["VPN"] = "Not Detected"
        elif vpn_connected:
            result["VPN"] = "Enabled (connected)"
        else:
            result["VPN"] = "Enabled (no connection)"
    except Exception:
        result["VPN"] = "Unknown"

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
                output.append("–" * 40)

        # Optional separator between sections
        output.append("–" * 40)
    
    return "\n".join(output)

# --- Output ---
if __name__ == "__main__":
    print("Gateway Detection Report")
    print("–" * len("Gateway Detection Report"))
    print(detect_gateway_device())
    print("")

    os.system("pause")
