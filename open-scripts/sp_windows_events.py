# MIT License – Copyright (c) 2025 Menahem Levinski

"""
Outputs recent Windows system event log entries.
"""

import os
import subprocess

# --- Check the latest 24 hours Windows system events ---
def get_system_events(report_widget=None):
    """
    Return system events in a dictionary compatible with the GUI.
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
        for event_id, desc in system_events.items():
            cmd = (
                f'wevtutil qe System '
                f'"/q:*[System[(EventID={event_id}) and '
                f'TimeCreated[timediff(@SystemTime) <= 86400000]]]" '
                f'/f:text'
            )
            try:
                output = subprocess.check_output(cmd, shell=True, text=True).strip()
                if output:
                    snippet_lines = output.splitlines()[:20]  # limit snippet to first 20 lines
                    event_dict = {
                        "Event ID": event_id,
                        "Description": desc,
                        "Log Snippet": "\n".join(snippet_lines)
                    }
                    result["Last 24 Hours"].append(event_dict)

                    # --- live GUI output ---
                    if report_widget:
                        report_widget.config(state="normal")
                        report_widget.insert("end", f"- Event ID: {event_id}\n")
                        report_widget.insert("end", f"  Description: {desc}\n")
                        report_widget.insert("end", f"  Log Snippet:\n")
                        for line in snippet_lines:
                            report_widget.insert("end", f"    {line}\n")
                        report_widget.insert("end", "\n")
                        report_widget.see("end")
                        report_widget.config(state="disabled")

            except subprocess.CalledProcessError:
                # Cannot read System log → no admin
                result["Last 24 Hours"] = "Access denied"
                if report_widget:
                    report_widget.config(state="normal")
                    report_widget.insert("end", "  Access denied\n")
                    report_widget.see("end")
                    report_widget.config(state="disabled")
                return result

        if not result["Last 24 Hours"]:
            result["Last 24 Hours"] = "None Detected"
            if report_widget:
                report_widget.config(state="normal")
                report_widget.insert("end", "  None Detected\n")
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
    Formats the system events dictionary into a clean, readable string
    with separators.
    """
    lines = [""]
    lines.append("–" * 40)
    lines.append("Last 24 Hours:")
    lines.append("–" * 40)

    events = data.get("Last 24 Hours", [])
    if isinstance(events, str):
        lines.append(f"    {events}")
    elif events:
        for i, e in enumerate(events):
            lines.append(f"    Event ID: {e['Event ID']}")
            lines.append(f"    Description: {e['Description']}")
            lines.append("    Log Snippet:")
            snippet = e.get("Log Snippet", "")
            for line in snippet.splitlines():
                lines.append(f"        {line}")
            # Only add separator if not the last event
            if i != len(events) - 1:
                lines.append("–" * 40)
    else:
        lines.append("    None Detected")

    return "\n".join(lines)

# --- Output ---
if __name__ == "__main__":
    print("Windows Events Report")
    print("–" * len("System Events Report"))
    print(get_system_events())
    print("")

    os.system("pause")
