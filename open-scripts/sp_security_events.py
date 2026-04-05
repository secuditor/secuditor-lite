# MIT License – Copyright (c) 2025 Menny Levinski

"""
Outputs recent Windows security event log entries (requires admin permissions).
"""

import os
import subprocess

# --- Check the latest 24 hours Windows Security events ---
def get_security_events(report_widget=None):
    """
    Return security events in a dictionary compatible with the GUI.
    Prints live output to report_widget if provided.
    """
    result = {"Last 24 Hours": []}

    suspicious_events = {
    # --- Logon/Logoff ---
    4624: "Successful logon",
    4625: "Failed logon",
    4634: "Logoff",
    4647: "User initiated logoff",
    4648: "Logon with explicit credentials",
    4672: "Special privileges assigned to new logon",

    # --- Account Management ---
    4720: "New user account created",
    4722: "User account enabled",
    4725: "User account disabled",
    4726: "User account deleted",
    4738: "User account changed",
    4740: "User account locked out",

    # --- Group Membership Changes ---
    4727: "Security-enabled global group created",
    4728: "User added to global group",
    4729: "User removed from global group",
    4730: "Global group deleted",
    4731: "Security-enabled local group created",
    4732: "User added to local group",
    4733: "User removed from local group",
    4734: "Local group deleted",
    4756: "Universal group created",
    4757: "User added to universal group",
    4758: "User removed from universal group",
    4759: "Universal group deleted",

    # --- Policy & Privilege Changes ---
    4670: "Permissions on an object changed",
    4719: "System audit policy changed",
    4739: "Domain policy changed",
    4782: "Password hash accessed",

    # --- Service & Scheduled Task Events ---
    4697: "Service installed",
    4698: "Scheduled task created",
    4699: "Scheduled task deleted",
    4700: "Scheduled task enabled",
    4701: "Scheduled task disabled",

    # --- Audit & Log Tampering ---
    1102: "Security log cleared",
    4614: "Security log retention settings changed",
    4713: "Kerberos policy changed",
    }

    try:
        for event_id, desc in suspicious_events.items():
            cmd = f'wevtutil qe Security "/q:*[System[(EventID={event_id})]]" /f:text /c:100'
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
                # Cannot read Security log → no admin
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

    return format_security_events(result)

def format_security_events(data):
    """
    Formats the security events dictionary into a clean, readable string
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
    print("Security Events Report")
    print("–" * len("Security Events Report"))
    print(get_security_events())
    print("")

    os.system("pause")
