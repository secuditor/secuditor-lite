# MIT License – Copyright (c) 2025 Menny Levinski

"""
Outputs a list of applications installed on the device.
"""

import os
import sys
import winreg

# --- Get the count of installed applications by querying registry ---
def get_installed_apps():
    uninstall_keys = [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    ]

    apps = set()

    for root in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
        for subkey in uninstall_keys:
            try:
                with winreg.OpenKey(root, subkey) as hkey:
                    for i in range(winreg.QueryInfoKey(hkey)[0]):
                        try:
                            skey_name = winreg.EnumKey(hkey, i)
                            with winreg.OpenKey(hkey, skey_name) as skey:
                                name, _ = winreg.QueryValueEx(skey, "DisplayName")
                                if name:
                                    apps.add(name.strip())
                        except OSError:
                            continue
            except FileNotFoundError:
                continue

    # Sort case-insensitive A-Z
    return sorted(apps, key=lambda x: x.lower())

# --- Output ---
if __name__ == "__main__":
    apps = get_installed_apps()
    print("Installed Applications Report")
    print("–" * len("Installed Applications Report"))
    print("")

    if apps:
        for app in apps:
            print(app)  # <-- print each app on a separate line

    else:
        print("(No applications found)")
        
    print("")
    os.system("pause")
