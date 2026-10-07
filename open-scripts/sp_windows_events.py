# MIT License – Copyright (c) 2026 Menahem Levinski

"""
Outputs recent Windows system events summary.
"""

import os
import subprocess

# --- Check the latest 24 hours Windows System events ---
def get_system_events(report_widget=None):
    """
    Return system event counts for the last 24 hours.
    Prints live output to report_widget if provided.
    """
    result = {"Last 24 Hours": []}

    system_events = {
        # --- System Startup / Shutdown ---
        12: "Operating system started",
        13: "Operating system shutdown",
        6005: "Event Log service started",
        6006: "Event Log service stopped",
        6008: "Unexpected shutdown",

        # --- Driver / Service Issues ---
        7000: "Service failed to start",
        7001: "Dependent service failed",
        7009: "Service start timeout",
        7011: "Service timeout",
        7022: "Service hung during startup",
        7023: "Service terminated with error",
        7024: "Service terminated (application error)",
        7026: "Boot/system driver failed",
        7031: "Service terminated unexpectedly",
        7034: "Service unexpectedly terminated",
        7036: "Service state changed",

        # --- System Stability ---
        41: "Kernel-Power unexpected restart",
        55: "File system corruption detected",
        98: "Volume mount issue",
        1001: "BugCheck (Blue Screen)",
        1014: "DNS name resolution failure",

        # --- Hardware / Disk ---
        7: "Disk bad block detected",
        11: "Disk controller error",
        15: "Disk not ready",
        51: "Disk paging error",
        129: "Storage reset",
        153: "Disk retry operation",

        # --- Power & Sleep ---
        1: "System resumed from sleep",
        42: "System entering sleep",

        # --- Time Service ---
        35: "Time service synchronization failed",
        36: "Time service synchronized",
        37: "Time provider error",

        # --- Network ---
        4201: "Network adapter connected",
        4202: "Network adapter disconnected",

        # --- User Profile / Registry ---
        1500: "User profile cannot be loaded",
        1501: "User profile restored from backup",
        1508: "Registry file could not be loaded",
        1511: "Temporary user profile loaded",

        # --- NTFS / File System ---
        50: "Delayed write failed",
        57: "File system data corruption detected",

        # --- Storage / Disk ---
        140: "Disk configuration changed",
        157: "Disk has been removed unexpectedly",
        161: "Dump file creation failed",

        # --- Boot / Startup ---
        18: "System boot performance issue",
        27: "Boot device initialization problem",

        # --- Driver Framework ---
        20001: "Driver Framework initialization failed",
        20003: "Device driver failure",

        # --- Windows Update ---
        19: "Windows Update installation successful",
        20: "Windows Update installation failed",
        21: "Windows Update restart required",

        # --- Resource Exhaustion ---
        2004: "Resource exhaustion detected (low memory)",
    }

    try:
        events = []

        for event_id, desc in system_events.items():

            cmd = (
                f'wevtutil qe System '
                f'"/q:*[System[(EventID={event_id}) and '
                f'TimeCreated[timediff(@SystemTime) <= 86400000]]]" '
                f'/f:text'
            )

            try:
                output = subprocess.check_output(
                    cmd,
                    shell=True,
                    text=True
                ).strip()

                # Count individual Event[...] blocks
                count = 0

                if output:
                    lines = output.splitlines()

                    for line in lines:
                        if line.startswith("Event["):
                            count += 1

                events.append({
                    "Event ID": event_id,
                    "Description": desc,
                    "Count": count
                })

            except subprocess.CalledProcessError:
                result["Last 24 Hours"] = "Access denied"

                if report_widget:
                    report_widget.config(state="normal")
                    report_widget.insert("end", "  Access denied\n")
                    report_widget.see("end")
                    report_widget.config(state="disabled")

                return result

        result["Last 24 Hours"] = events

        # --- Live GUI output ---
        if report_widget:
            report_widget.config(state="normal")

            report_widget.insert(
                "end",
                "  System Events — Last 24 Hours\n\n"
            )

            for event in events:
                report_widget.insert(
                    "end",
                    f"  {event['Description']} "
                    f"({event['Event ID']}): "
                    f"{event['Count']}\n"
                )

            report_widget.see("end")
            report_widget.config(state="disabled")

    except Exception:
        result["Last 24 Hours"] = "Access denied"

        if report_widget:
            report_widget.config(state="normal")
            report_widget.insert("end", "  Access denied\n")
            report_widget.see("end")
            report_widget.config(state="disabled")

    return format_system_events(result)

def format_system_events(data):
    """
    Formats the system event counts as a clean table.
    """
    lines = [""]
    lines.append("–" * 80)
    lines.append("Last 24 Hours:")
    lines.append("–" * 80)

    events = data.get("Last 24 Hours", [])

    if isinstance(events, str):
        lines.append(f"    {events}")

    elif events:
        lines.append(
            f"    {'Event Description':<45}"
            f"{'Event ID':>14}"
            f"{'Cases':>14}"
        )
        lines.append("    " + "–" * 76)

        for event in events:
            lines.append(
                f"    {event['Description']:<45}"
                f"{event['Event ID']:>14}"
                f"{event['Count']:>14}"
            )

    else:
        lines.append("    None Detected")

    return "\n".join(lines)

# --- Output ---
if __name__ == "__main__":
    print("\nWindows Events Report")
    print("–" * len("Windows Events Report"))
    print(get_system_events())
    print("")

    os.system("pause")
