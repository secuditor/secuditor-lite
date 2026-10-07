# MIT License – Copyright (c) 2026 Menahem Levinski

"""
Outputs recent Windows security event log entries (requires admin permissions).
"""

import os
import subprocess

# --- Check the latest 24 hours Windows Security events ---
def get_security_events(report_widget=None):
    """
    Return security event counts for the last 24 hours.
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
        events = []

        for event_id, desc in suspicious_events.items():

            cmd = (
                f'wevtutil qe Security '
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
                # Cannot read Security log → no admin
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
                "  Security Events — Last 24 Hours\n\n"
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

    return format_security_events(result)

def format_security_events(data):
    """
    Formats the security event counts as a clean table.
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
    print("\nSecurity Events Report")
    print("–" * len("Security Events Report"))
    print(get_security_events())
    print("")

    os.system("pause")
