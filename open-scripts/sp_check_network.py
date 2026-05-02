# MIT License – Copyright (c) 2025 Menahem Levinski

import requests
import ipaddress
import socket
import psutil
import re
import tkinter as tk

# NETWORK LOGIC (standalone)
def check_internet_connection(timeout=3):
    result = {
        "Connected": False,
        "Test Host": "https://www.google.com",
        "External IP": "Unavailable",
        "Error": None
    }

    try:
        response = requests.head(result["Test Host"], timeout=timeout)
        if response.status_code < 400:
            result["Connected"] = True
    except Exception as e:
        result["Error"] = f"No internet connectivity: {e}"
        return result

    if result["Connected"]:
        try:
            response = requests.get("https://api.ipify.org", timeout=timeout)
            if response.status_code == 200:
                result["External IP"] = response.text.strip()
        except Exception as e:
            result["External IP"] = "Unavailable"
            result["Error"] = f"External IP check failed: {e}"

    return result

def get_ip_info(ip):
    try:
        if ipaddress.ip_address(ip).is_private:
            return "Private IP", "Local Network"

        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        data = response.json()

        isp_full = data.get("org", "Unknown ISP")
        region_full = ", ".join(filter(None, [
            data.get("region"),
            data.get("country")
        ])) or "Unknown Region"

        return shorten_isp(isp_full), truncate_text(region_full, 40)

    except Exception:
        return "Unknown ISP", "Unknown Region"

def get_vpn_connection():
    try:
        vpn_adapters = []
        vpn_connected = False

        for name, addrs in psutil.net_if_addrs().items():
            lname = name.lower()

            if any(k in lname for k in ("vpn", "ppp", "tap", "tun", "wireguard")):
                vpn_adapters.append(name)

                for addr in addrs:
                    if addr.family == socket.AF_INET and not addr.address.startswith("169.254"):
                        vpn_connected = True

        if not vpn_adapters:
            return "Not Installed"
        elif vpn_connected:
            return "Enabled (connected)"
        else:
            return "Enabled (no connection)"

    except Exception:
        return "Unknown"

def shorten_isp(isp: str) -> str:
    if not isp or isp == "Unknown ISP":
        return "Unknown ISP"

    parts = isp.split()

    if parts[0].upper().startswith("AS") and parts[0][2:].isdigit():
        parts = parts[1:]

    name = " ".join(parts)

    name = re.sub(
        r'\b(Inc|LLC|Ltd|Co|Corporation|Limited)\b\.?',
        '',
        name,
        flags=re.IGNORECASE
    )

    name = " ".join(name.split())

    return name[:40] + "..." if len(name) > 40 else name


def truncate_text(text: str, max_len: int) -> str:
    return text if len(text) <= max_len else text[:max_len] + "..."

# GUI CLASS (UNCHANGED OUTPUT)
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Network Tool")

        # --- window size ---
        win_w = 300
        win_h = 150

        # --- center on screen ---
        self.update_idletasks()

        screen_w = self.winfo_screenwidth()
        screen_h = self.winfo_screenheight()

        pos_x = (screen_w - win_w) // 2
        pos_y = (screen_h - win_h) // 2

        self.geometry(f"{win_w}x{win_h}+{pos_x}+{pos_y}")

        tk.Button(self, text="Check Network", command=self.show_network_status).pack(pady=40)

    # --- Bind standalone functions ---
    def check_internet_connection(self):
        return check_internet_connection()

    def get_ip_info(self, ip):
        return get_ip_info(ip)

    def get_vpn_connection(self):
        return get_vpn_connection()

    # --- YOUR ORIGINAL FUNCTION (unchanged) ---
    def show_network_status(self):
        net_status = self.check_internet_connection()

        show_net = tk.Toplevel()
        show_net.title("Network Status")
        show_net.resizable(False, False)

        show_net.transient(self)
        show_net.grab_set()
        show_net.focus_force()

        if net_status["Connected"]:
            ip = net_status["External IP"]
            isp, region = self.get_ip_info(ip)
            vpn_status = self.get_vpn_connection()

            if vpn_status == "Enabled (connected)":
                msg_text = (
                    f"🌐 Internet Connection: VPN\n\n"
                    f"Public IP: {ip}\n"
                    f"ISP: {isp}\n"
                    f"Region: {region}"
                )
                win_w, win_h = 420, 200
            else:
                msg_text = (
                    f"🌐 Internet Connection: Direct\n\n"
                    f"Public IP: {ip}\n"
                    f"ISP: {isp}\n"
                    f"Region: {region}"
                )
                win_w, win_h = 420, 200
        else:
            msg_text = "⚠️ No internet connection detected.\nSome checks may not work."
            win_w, win_h = 400, 180

        # --- Center popup on screen ---
        show_net.update_idletasks()

        screen_w = show_net.winfo_screenwidth()
        screen_h = show_net.winfo_screenheight()

        pos_x = (screen_w - win_w) // 2
        pos_y = (screen_h - win_h) // 2

        show_net.geometry(f"{win_w}x{win_h}+{pos_x}+{pos_y}")

        tk.Label(
            show_net,
            text=msg_text,
            font=("Segoe UI", 10),
            justify="center",
            wraplength=380
        ).pack(pady=(24, 16), padx=12)

        tk.Button(show_net, text="OK", width=10, command=show_net.destroy).pack(pady=(0, 12))

# --- Output ---
if __name__ == "__main__":
    app = App()
    app.mainloop()
