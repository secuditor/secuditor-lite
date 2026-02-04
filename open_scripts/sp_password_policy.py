# MIT License – Copyright (c) 2025 Menny Levinski

"""
Evaluates local and domain affiliated password policies.
"""

import os
import subprocess
import getpass
import re
import winreg

# --- Main password policy checker ---
def get_password_policy_nonadmin():
    """
    Retrieve local password policy details without requiring admin privileges.
    Returns a formatted report string.
    """    
    result = {
        "Password History": "Unknown",
        "Password MinLength": None,
        "Password Complexity": False,
        "Password Required": "Unknown",
        "Password Expires": "Unknown",
        "Lockout Threshold": "Unknown",
        "Lockout Duration": "Unknown",
        "Lockout Observed": "Unknown",
        "Verdict": "Unknown"
    }

    username = getpass.getuser()

    # --- Password History ---
    try:
        output = subprocess.check_output(
            'net accounts',
            shell=True,
            text=True,
            encoding="utf-8"
        ).strip()

        # Look for any line that contains a number and 'history' or likely candidate
        for line in output.splitlines():
            line_clean = line.strip()
            # Search for the first number in the line
            match = re.search(r'\b\d+\b', line_clean)
            if match:
                value = int(match.group(0))
                # Heuristic: if the line contains "history" or "previous", treat as password history
                if "history" in line_clean.lower() or "previous" in line_clean.lower() or "remembered" in line_clean.lower():
                    if value == 0:
                        result["Password History"] = "Not Enforced"
                    else:
                        result["Password History"] = f"Last {value} Enforced"
                    break
    except subprocess.CalledProcessError:
        result["Password History"] = "Unknown"
    except Exception:
        result["Password History"] = "Unknown"

    # --- LSA registry ---
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa") as key:
            min_length, _ = winreg.QueryValueEx(key, "MinimumPasswordLength")
            complexity, _ = winreg.QueryValueEx(key, "PasswordComplexity")
            result["Password MinLength"] = min_length
            result["Password Complexity"] = bool(complexity)
    except Exception:
        pass

    # --- System-wide policy via net accounts ---
    try:
        output = subprocess.check_output("net accounts", shell=True, text=True, encoding="utf-8")
        for line in output.splitlines():
            line_lower = line.strip().lower()
            if "minimum password age" in line_lower:
                value = line.split()[-1]
                try:
                    days = int(value)
                    result["Password Expires"] = "No" if days == 0 else "Yes"
                except ValueError:
                    result["Password Expires"] = "Unknown"
            elif "minimum password length" in line_lower:
                try:
                    result["Password MinLength"] = int(line.split()[-1])
                except:
                    pass
            elif "lockout threshold" in line_lower:
                result["Lockout Threshold"] = line.split()[-1]
            elif "lockout duration" in line_lower:
                result["Lockout Duration"] = line.split()[-1]
    except Exception:
        pass

    # --- Current user's info ---
    try:
        output = subprocess.check_output(f'net user "{username}"', shell=True, text=True, encoding="utf-8")
        for line in output.splitlines():
            line_lower = line.strip().lower()
            if "password required" in line_lower:
                result["Password Required"] = "Yes" if "yes" in line_lower else "No"
            elif "password expires" in line_lower:
                parts = line.split("Password expires")
                if len(parts) > 1:
                    value = parts[1].strip()
                    # Normalize to Yes/No
                    result["Password Expires"] = "No" if value.lower() == "never" else "Yes"
            elif "account active" in line_lower:
                result["Lockout Observed"] = line.split()[-1].capitalize()
    except Exception:
        pass

    # --- Simple verdict ---
    try:
        if result["Password Required"] == "No":
            result["Verdict"] = "Weak"
        elif result["Password Required"] == "Yes":
            if (
                result["Password Expires"] != "Never"
                and result["Password MinLength"]
                and result["Password Complexity"]
                and result["Password MinLength"] >= 8
            ):
                result["Verdict"] = "Strong"
            elif result["Password MinLength"] >= 8 and result["Lockout Observed"]:
                result["Verdict"] = "Moderate"
            else:
                result["Verdict"] = "Weak"
        else:
            result["Verdict"] = "Unknown"
    except Exception:
        result["Verdict"] = "Unknown"

    return format_password_policy(result)

def format_password_policy(policy):
    """
    Returns a formatted multi-line report for password policy with dashed lines.
    """
    report = [""]

    keys = list(policy.keys())
    for i, key in enumerate(keys):
        value = policy[key]

        report.append(f"{key}:")
        report.append(f"  {value}")

        # Add separator only if not the last item
        if i != len(keys) - 1:
            report.append("–" * 40)

    return "\n".join(report)

# --- Output ---
if __name__ == "__main__":
    print("Password Policy Report")
    print("–" * len("Password Policy Report"))
    print(get_password_policy_nonadmin())
    print("")

    os.system("pause")
