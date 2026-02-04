# MIT License – Copyright (c) 2025 Menny Levinski

"""
Presents a detailed report of the system's settings and inventory.
"""

import os
import sys
import platform
import socket
import subprocess
import winreg
import psutil
import json

# --- Collect basic OS and Resources info using platform module ---
def get_system_settings():
    os_name = platform.system()
    os_release = platform.release()
    unified_os = f"{os_name}{os_release}"

    # --- Gather resources info ---
    resources = {
        "Machine": platform.machine(),
        "Processor": platform.processor(),
        "Architecture": "x64" if platform.architecture()[0] == "64bit" else "x86",
        "CPU Cores": psutil.cpu_count(logical=False),
        "Threads": psutil.cpu_count(logical=True),
        "RAM (GB)": round(psutil.virtual_memory().total / (1024**3), 2),
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
        except (PermissionError, FileNotFoundError):
            # Skip drives that are not ready
            continue

    return {
        "Hostname": socket.gethostname(),
        "OS": unified_os,
        "Version": platform.version(),
        "Resources": resources,
        "Disks": disks
    }

def format_system_settings(settings):
    output = [""]  # Upperline added
    keys = list(settings.keys())

    for i, key in enumerate(keys):
        value = settings[key]

        if isinstance(value, dict):
            # Add section header (special handling for Resources and Disks)
            if key == "Resources":
                # Standard Resources section
                output.append("–" * 40)
                output.append(f"{key}:")
                output.append("")
            elif key == "Disks":
                # Always add a separator before Disks (even if after Resources)
                output.append("–" * 40)
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
                        output.append("–" * 40)
                else:
                    output.append(f"{sub_key}: {sub_value}")

            # Section separator for non-Disk/Resource sections (except last)
            if key not in ("Disks", "Resources") and i != len(keys) - 1:
                output.append("–" * 40)

        else:
            output.append(f"{key}: {value}")
            # Add separator if not last and next isn’t Resources/Disks
            if i != len(keys) - 1 and keys[i + 1] not in ("Resources", "Disks"):
                output.append("–" * 40)

    return "\n".join(output)

def get_formatted_system_settings():
    """Call get_system_settings and return formatted string"""
    settings = get_system_settings()
    return format_system_settings(settings)

# --- Scan related hardware devices ---
if sys.platform.startswith("win"):
    _CREATE_NO_WINDOW = 0x08000000
    _STARTUPINFO = subprocess.STARTUPINFO()
    _STARTUPINFO.dwFlags |= subprocess.STARTF_USESHOWWINDOW
else:
    _CREATE_NO_WINDOW = 0
    _STARTUPINFO = None

def _run_ps(cmd):
    """Run PowerShell command, return JSON list, hide window, ignore non-zero exit code."""
    try:
        # Use subprocess.run instead of check_output to avoid exception on exit code != 0
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", cmd],
            text=True,
            capture_output=True,
            creationflags=_CREATE_NO_WINDOW,
            startupinfo=_STARTUPINFO
        )
        out = result.stdout.strip()

        if not out:
            return []

        data = json.loads(out)

        # Always return a list
        if isinstance(data, dict):
            return [data]
        return data

    except Exception as e:
        # Only print actual unexpected errors
        print(f"[PS ERROR] {e}")
        return []

# --- PnP scanning ---
PNP_CLASS_MAP = {
    "Printers": "Printer",
    "Cameras": "Image", 
    "Bluetooth Devices": "Bluetooth",
    "Biometric Devices": "Biometric",
}

def scan_pnp_category(pnp_class):
    cmd = (
        f'Get-PnpDevice -PresentOnly -Class "{pnp_class}" | '
        f'Select-Object FriendlyName | ConvertTo-Json -Depth 2'
    )
    return _run_ps(cmd)

# --- USB scanning ---
def scan_usb_devices():
    cmd = (
        'Get-PnpDevice -PresentOnly | '
        'Where-Object { $_.InstanceId -like "USB*" } | '
        'Select-Object FriendlyName | ConvertTo-Json -Depth 2'
    )
    return _run_ps(cmd)

# ---Network adapters ---
def scan_network_adapters():
    return [{"Name": name} for name in psutil.net_if_addrs().keys()]

# --- Hardware report ---
def get_hardware_report():
    categories = {
        "Printers": scan_pnp_category(PNP_CLASS_MAP["Printers"]),
        "Cameras": scan_pnp_category(PNP_CLASS_MAP["Cameras"]),
        "Bluetooth Devices": scan_pnp_category(PNP_CLASS_MAP["Bluetooth Devices"]),
        "USB Devices": scan_usb_devices(),
        "Biometric Devices": scan_pnp_category(PNP_CLASS_MAP["Biometric Devices"]),
        "Network Adapters": scan_network_adapters(),
    }

    lines = [""]

    for i, category in enumerate(categories):
        lines.append(f"{category}:")
        items = categories[category]

        if not items:
            lines.append("  (None)")
        else:
            for item in items:
                name = item.get("FriendlyName") or item.get("Name") or "(Unknown)"
                lines.append(f"  {name}")

        if i != len(categories) - 1:
            lines.append("–" * 40)

    return "\n".join(lines)

# --- Output ---
if __name__ == "__main__":
    print("System & Hardware Report")
    print("–" * len("System & Hardware Report"))
    print(get_formatted_system_settings())
    print(get_hardware_report())
    print("")
    
    os.system("pause")
