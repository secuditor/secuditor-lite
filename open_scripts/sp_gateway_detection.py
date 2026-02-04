# MIT License – Copyright (c) 2025 Menny Levinski

"""
Detects the local network's default gateway and public IP.

Third-party: requests (urllib3), psutil
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
    """Return the default gateway IP address."""
    try:
        output = subprocess.check_output("ipconfig", shell=True, text=True)
        for line in output.splitlines():
            if "Default Gateway" in line:
                ip = line.split(":")[-1].strip()
                if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
                    return ip
    except Exception:
        pass
    return None

# --- Ping device ---
def ping_device(ip):
    """
    Ping the gateway and return a concise result:
    - 'Reply from ...' if reachable
    - 'Request timed out' if not
    """
    try:
        param = "-n" if platform.system().lower() == "windows" else "-c"
        result = subprocess.run(["ping", param, "1", ip], capture_output=True, text=True)
        output = result.stdout.strip()

        # Parse the output for the reply line
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("Reply from") or "Request timed out" in line:
                return line
        # fallback
        return "No response"
    except Exception as e:
        return f"Ping failed: {e}"

# --- Mac address ---
def get_mac_from_arp(ip):
    """Get MAC address of the gateway from ARP table."""
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

# --- Lookup vendor ---
def lookup_vendor(mac, device_ip=None):
    """
    Lookup vendor from MAC address.
    1. Try macvendors.com API.
    2. Identify virtual / locally administered MACs.
    3. Optional: use ping_device for TTL/response heuristics if IP is provided.
    """
    if not mac:
        return "Unknown"

    oui = mac.replace("-", ":").upper()[:8]

    # --- First: try online API ---
    try:
        response = requests.get(f"https://api.macvendors.com/{mac}", timeout=3)
        if response.status_code == 200:
            vendor = response.text.strip()
            if vendor and "unknown" not in vendor.lower():
                return vendor
    except Exception:
        pass  # silently fallback

    # --- Third: check for virtual / locally administered MAC ---
    first_byte = int(mac.split("-")[0], 16)
    if first_byte & 0b00000010:  # locally administered bit
        return "Virtual/Software MAC"

    # --- Fourth: optional TTL-based heuristic using ping ---
    if device_ip:
        reply = ping_device(device_ip)
        ttl_match = re.search(r"TTL=(\d+)", reply, re.IGNORECASE)
        if ttl_match:
            ttl = int(ttl_match.group(1))
            if ttl <= 64:
                return "Likely Linux/Unix device"
            elif ttl <= 128:
                return "Likely Windows device"
            elif ttl <= 255:
                return "Likely network appliance / router"

    return "Unknown"

# --- Check https access ---
def check_http_access(ip):
    """Check if gateway responds to HTTP/HTTPS (router web interface)."""
    for scheme in ["http", "https"]:
        try:
            url = f"{scheme}://{ip}"
            r = requests.get(url, timeout=3, verify=False)  # suppress cert warning
            if r.status_code < 500:
                return f"{scheme.upper()} Responding ({r.status_code})"
        except Exception:
            continue
    return "No web interface detected"

# --- Detect NAT ---
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

# --- Get public IP ---
def get_external_ip():
    """Discover external/public IP."""
    try:
        return requests.get("https://api.ipify.org", timeout=5).text.strip()
    except Exception:
        return "Unavailable"

# --- Gateway device settings ---
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

    gw_ip = get_default_gateway()
    if not gw_ip:
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
