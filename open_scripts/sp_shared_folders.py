# MIT License – Copyright (c) 2025 Menny Levinski

"""
Mapping shared folders (requires admin permissions).

- Third-party:
  - pywin32 (win32security, win32con, pythoncom)
  - wmi
"""

import ctypes
import win32security
import win32con as con
import pythoncom
import wmi
import os

# --- Get shared folders ---
# --- Check if script runs as admin ---
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

# --- Resolve SID to account name ---
def resolve_sid(sid_str):
    try:
        sid = win32security.ConvertStringSidToSid(sid_str)
        name, domain, _ = win32security.LookupAccountSid(None, sid)
        return f"{domain}\\{name}" if domain else name
    except Exception:
        return sid_str

# --- Get permissions for a folder ---
def get_permissions(folder_path):
    perms = []
    everyone_detected = False
    try:
        sd = win32security.GetFileSecurity(folder_path, win32security.DACL_SECURITY_INFORMATION)
        dacl = sd.GetSecurityDescriptorDacl()
        if dacl:
            for i in range(dacl.GetAceCount()):
                ace = dacl.GetAce(i)
                sid = ace[2]
                access_mask = ace[1]
                sid_str = win32security.ConvertSidToStringSid(sid)
                account = resolve_sid(sid_str)

                # Check for Everyone
                if account.upper() in ("EVERYONE", "BUILTIN\\EVERYONE"):
                    everyone_detected = True

                if account.startswith("NT AUTHORITY\\"):
                    continue  # skip these accounts

                rights = []
                if access_mask & con.FILE_GENERIC_READ:
                    rights.append("Read")
                if access_mask & con.FILE_GENERIC_WRITE:
                    rights.append("Write")
                if access_mask & con.FILE_GENERIC_EXECUTE:
                    rights.append("Execute")
                if access_mask & con.FILE_ALL_ACCESS:
                    rights = ["Full Control"]

                perms.append(f"{account}: {', '.join(rights) if rights else 'Special Permissions'}")
        else:
            perms.append("(No DACL)")
    except Exception as e:
        perms.append(f"(Unable to read ACL: {e})")
    return perms, everyone_detected

# --- Get shared folders with Everyone check ---
def get_shared_folders():
    output = [""]
    shares_data = []

    try:
        pythoncom.CoInitialize()
        c = wmi.WMI()
        admin = is_admin()
        for s in c.Win32_Share():
            if s.Name.upper() in ("ADMIN$", "IPC$"):
                continue

            if admin and s.Path:
                permissions, everyone_flag = get_permissions(s.Path)
            else:
                permissions = ["(Access denied)"]
                everyone_flag = False

            shares_data.append({
                "Name": s.Name,
                "Path": s.Path or "",
                "Description": s.Description or "None",
                "Permissions": permissions,
                "Everyone": everyone_flag
            })

    except Exception as e:
        output.append(f"Error: {e}")
        return "\n".join(output)

    if not shares_data:
        output.append("No shared folders found.")
    else:
        for i, share in enumerate(shares_data):
            output.append(f"Share Name : {share['Name']}")
            output.append(f"Path       : {share['Path']}")
            output.append(f"Description: {share['Description']}")
            output.append("Permissions:")
            for perm in share["Permissions"]:
                output.append(f"  {perm}")
            if share["Everyone"]:
                output.append("⚠️ Warning: Folder accessible by Everyone!")
            
            # Only add the separator if not the last share
            if i != len(shares_data) - 1:
                output.append("–" * 40)

    return "\n".join(output)

# --- Output ---
if __name__ == "__main__":
    print("Shared Folders Mapping")
    print("–" * len("Shared Folders Mapping"))
    print(get_shared_folders())
    print("")

    os.system("pause")
