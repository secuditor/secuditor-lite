# MIT License – Copyright (c) 2025 Menny Levinski

"""
Identifies domain affiliation and discovers related settings.
"""

import os
import re
import subprocess
import socket
import getpass
import winreg

# --- Domain/workgroup info ---
def _check_laps():
    """Check if LAPS is installed and enabled."""
    try:
        key_path = r"SOFTWARE\Policies\Microsoft Services\AdmPwd"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
            installed = True
            try:
                enabled, _ = winreg.QueryValueEx(key, "AdmPwdEnabled")
                enabled = bool(enabled)
            except FileNotFoundError:
                enabled = False
            return installed, enabled
    except FileNotFoundError:
        return False, False

def get_domain_settings():
    """
    Returns a dictionary with domain/workgroup info and all local users.
    Keys:
        Type: "Domain", "Workgroup", "Local"
        Name: domain/workgroup name or None
        Computer Name
        Current User
        Domain Role
        Privileged Users: list of strings "username (Enabled/Disabled)"
        Regular Users: list of strings "username (Enabled/Disabled)"
        LAPS Status: "Enabled"/"Disabled"/"Not Installed"
    """
    
    data = {
        "Type": "Local",
        "Name": None,
        "Hostname": socket.gethostname(),
        "Current User": getpass.getuser(),
        "Domain Role": None,
        "NTLM Policy": None,
        "Privileged Users": [],
        "Regular Users": []
    }

    # --- Domain / Workgroup detection ---
    try:
        output = subprocess.check_output("wmic computersystem get domain", shell=True, text=True)
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        if len(lines) > 1:
            domain_name = lines[1]
            computer_name = data["Hostname"]
            if domain_name.upper() == "WORKGROUP":
                data["Type"] = "Workgroup"
                data["Name"] = domain_name
            elif domain_name.upper() != computer_name.upper():
                data["Type"] = "Domain"
                data["Name"] = domain_name
    except Exception:
        pass

    # --- Domain Role ---
    try:
        role_map = {
            0: "Standalone Workstation",
            1: "Member Workstation",
            2: "Standalone Server",
            3: "Member Server",
            4: "Backup Domain Controller",
            5: "Primary Domain Controller"
        }
        role = subprocess.check_output(
            'powershell -Command "(Get-WmiObject Win32_ComputerSystem).DomainRole"',
            shell=True, text=True
        ).strip()
        try:
            role_int = int(role)
            data["Domain Role"] = role_map.get(role_int, f"Unknown ({role})")
        except:
            data["Domain Role"] = f"Unknown ({role})"
    except Exception:
        data["Domain Role"] = "Unknown"

    # --- All local users ---
    try:
        output = subprocess.check_output('net user', shell=True, text=True, errors="ignore")
        lines = output.splitlines()
        try:
            sep_index = next(i for i, line in enumerate(lines) if line.strip().startswith('---'))
        except StopIteration:
            sep_index = 0

        users = []
        for line in lines[sep_index+1:]:
            if line.strip() and not line.lower().startswith("the command completed successfully"):
                users.extend(line.split())

        # --- Check each user ---
        for user in users:
            status = "Unknown"
            is_admin = False
            try:
                info_output = subprocess.check_output(f'net user "{user}"', shell=True, text=True, errors="ignore")
                match = re.search(r"Account active\s+(\w+)", info_output, re.IGNORECASE)
                if match:
                    status = "Enabled" if match.group(1).strip().lower() == "yes" else "Disabled"

                # Check if user is in Administrators group
                groups = re.findall(r"Local Group Memberships\s+(.*)", info_output)
                if groups and "Administrators" in groups[0]:
                    is_admin = True

            except Exception:
                pass

            user_entry = f"{user} ({status})"
            if is_admin:
                data["Privileged Users"].append(user_entry)
            else:
                data["Regular Users"].append(user_entry)
    except Exception:
        pass

    # --- Check NTLM ---
    try:
        data["NTLM Policy"] = check_ntlm_policy()
    except Exception:
        pass

    return format_domain_settings(data)

def format_domain_settings(data):
    report = [""]

    # Basic info
    for key in ["Type", "Name", "Hostname", "Current User", "Domain Role"]:
        report.append(f"{key}:")
        report.append(f"  {data.get(key, 'Unknown')}")
        report.append("–" * 40)

    # Privileged Users
    report.append("Privileged Users:")
    privileged = data.get("Privileged Users", [])
    if privileged:
        for user in privileged:
            report.append(f"  {user}")
    else:
        report.append("  (None)")
    report.append("–" * 40)

    # Regular Users
    report.append("Regular Users:")
    regular = data.get("Regular Users", [])
    if regular:
        for user in regular:
            report.append(f"  {user}")
    else:
        report.append("  (None)")
    report.append("–" * 40)

    # LAPS Status
    laps_status = data.get("LAPS Status", "Not Installed")
    report.append("LAPS Status:")
    report.append(f"  {laps_status}")
    report.append("–" * 40)

    # NTLM Policy
    ntlm_policy = check_ntlm_policy()
    report.append("NTLM Policy:")
    report.append(f"  {ntlm_policy}")

    return "\n".join(report)

# --- NTLM policy checker ---
def read_reg(path, key):
    try:
        reg = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_READ)
        value, _ = winreg.QueryValueEx(reg, key)
        return value
    except FileNotFoundError:
        return None

def ntlm_verdict(lm, lmhash, audit):
    """
    Produce a text verdict instead of a numeric score.
    """

    # Worst case verdict
    if lm in [0, 1]:
        return "Critical, Weak NTLM policy (LM/NTLMv1 enabled)."

    # Good: Using strong NTLMv2 defaults but not hardened
    if lm in [None, 2, 3]:
        if lmhash == 0:
            return "Warning, NTLMv2 is enabled but LM hashes allowed."
        return "Moderate, NTLMv2 is used but not enforced."

    # Strongest settings
    if lm in [4, 5]:
        if audit == 2:
            return "Strong, NTLMv2 enforced and NTLM audit enabled."
        return "Strong, NTLMv2 enforced without NTLM auditing."

    return "Unknown NTLM configuration."

def check_ntlm_policy():

    lsa_path = r"SYSTEM\CurrentControlSet\Control\Lsa"
    msv1_0_path = r"SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"

    lm = read_reg(lsa_path, "LmCompatibilityLevel")
    lmhash = read_reg(lsa_path, "NoLMHash")
    audit = read_reg(msv1_0_path, "AuditReceivingNTLMTraffic")

    verdict_text = ntlm_verdict(lm, lmhash, audit)

    # Return the verdict as a plain string
    return verdict_text

# --- Output ---
if __name__ == "__main__":
    print("Domain Settings Report")
    print("–" * len("Domain Settings Report"))
    print(get_domain_settings())
    print("")

    os.system("pause")
    
