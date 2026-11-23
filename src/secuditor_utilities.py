# Secuditor Toolbar Utilities – Copyright (c) 2026 Menahem Levinski

import io
import os
import re
import sys
import time
import uuid
import socket
import logging
import platform
import queue
import ipaddress
import subprocess
import threading
import tkinter as tk
import concurrent.futures

from typing import List, Dict, Iterable, Optional
from tkinter import ttk, filedialog, messagebox

import psutil
import requests
import secuditor_loader

# --- Speed Test ---
TEST_FILE_URL = "https://test.secuditor.com/speedtest.png"
THREADS = 4
REPEATS = 8

# ======= LAN scanning configs =======
# Default common ports to check quickly
COMMON_PORTS_TCP = [20, 21, 22, 23, 79, 80, 389, 443, 445, 636, 989, 990, 1080, 1433, 1434, 1521, 2222, 2375, 2376, 2049, 5601, 3306, 3389, 5432, 5060, 5061, 5900, 5985, 5986, 6379, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9001, 9042, 10000, 10443, 27017, 30015]

COMMON_PORTS_UDP = [53, 67, 68, 69, 111, 123, 137, 138, 161, 162, 500, 514, 520, 1900, 3478, 4500, 5353, 5683, 11211, 27015]

# OS detection
IS_WINDOWS = platform.system().lower().startswith("win")

_oui_vendor_cache = None

# Windows-specific flags to hide console windows for subprocess children
if IS_WINDOWS:
    WINDOWS_CREATE_NO_WINDOW = 0x08000000
    try:
        STARTUPINFO = subprocess.STARTUPINFO()
        STARTUPINFO.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        STARTUPINFO.wShowWindow = subprocess.SW_HIDE
    except Exception:
        STARTUPINFO = None
else:
    WINDOWS_CREATE_NO_WINDOW = 0
    STARTUPINFO = None

# --- Data path ---
def resource_path(relative_path):
    """ Get absolute path to resource (works in .py and in PyInstaller EXE) """
    if hasattr(sys, '_MEIPASS'):  # PyInstaller sets this attr
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), relative_path)

# --- Set Tk window icon with fallback ---
def set_window_icon(window):
    try:
        # Preferred: use the bundled .ico
        ico_path = resource_path("icon.ico")
        if isinstance(window, tk.Tk):
            window.iconbitmap(default=ico_path)
        window.iconbitmap(ico_path)
    except Exception:
        # Fallback: use the PNG when running unbundled
        try:
            from tkinter import PhotoImage
            photo = PhotoImage(file=resource_path("secuditor_icon.png"))
            window._icon_photo = photo  # keep reference so Tk doesn't GC the image
            window.iconphoto(False, photo)
        except Exception:
            pass  # Silent fail if no icon found

# --- Native Windows modal helper (replaces Tk grab_set to prevent minimize/restore deadlocks) ---
def attach_native_modal(parent, dialog):
    """
    Make `dialog` modal over `parent` using native Win32 owner disabling
    (transient + EnableWindow on GA_ROOT) instead of Tk's grab_set(),
    preventing Windows minimize/restore (Win+D / taskbar) deadlocks.
    Falls back to grab_set() on non-Windows platforms.
    """
    try:
        dialog.transient(parent)
    except tk.TclError:
        pass

    try:
        dialog.update_idletasks()
        dialog.deiconify()
        dialog.lift()
        dialog.focus_force()
    except tk.TclError:
        return

    if not IS_WINDOWS:
        try:
            dialog.grab_set()
        except tk.TclError:
            pass
        return

    try:
        import ctypes
        from ctypes import wintypes

        user32 = ctypes.WinDLL(_system_exe("user32.dll"), use_last_error=True)

        get_ancestor = user32.GetAncestor
        get_ancestor.argtypes = [wintypes.HWND, wintypes.UINT]
        get_ancestor.restype = wintypes.HWND

        enable_window = user32.EnableWindow
        enable_window.argtypes = [wintypes.HWND, wintypes.BOOL]
        enable_window.restype = wintypes.BOOL

        set_foreground = user32.SetForegroundWindow
        set_foreground.argtypes = [wintypes.HWND]
        set_foreground.restype = wintypes.BOOL

        parent.update_idletasks()
        GA_ROOT = 2
        parent_hwnd = get_ancestor(int(parent.winfo_id()), GA_ROOT) or int(parent.winfo_id())
    except Exception:
        try:
            dialog.grab_set()
        except tk.TclError:
            pass
        return

    # Ref-count per parent so nested modals cannot re-enable the parent prematurely
    parent._native_modal_count = getattr(parent, "_native_modal_count", 0) + 1
    released = [False]

    def _release_parent(restore_focus=True):
        if released[0]:
            return
        released[0] = True
        remaining = max(getattr(parent, "_native_modal_count", 1) - 1, 0)
        parent._native_modal_count = remaining
        if remaining == 0:
            try:
                enable_window(parent_hwnd, True)
            except Exception:
                pass
            if restore_focus:
                try:
                    if parent.winfo_exists() and parent.state() != "iconic":
                        parent.lift()
                        set_foreground(parent_hwnd)
                        parent.focus_force()
                except Exception:
                    pass

    # Wrap dialog.destroy so parent is re-enabled BEFORE the dialog HWND disappears
    # (prevents Windows from dropping foreground focus to a background window).
    orig_destroy = dialog.destroy

    def _safe_destroy():
        _release_parent(restore_focus=True)
        orig_destroy()

    dialog.destroy = _safe_destroy

    # Route default X-button close through _safe_destroy unless dialog already set a custom handler
    try:
        if not dialog.protocol("WM_DELETE_WINDOW"):
            dialog.protocol("WM_DELETE_WINDOW", dialog.destroy)
    except tk.TclError:
        pass

    # Failsafe if dialog is destroyed via any other path
    def _on_destroy(event):
        if event.widget is dialog:
            _release_parent(restore_focus=True)

    dialog.bind("<Destroy>", _on_destroy, add="+")

    # Disable parent only AFTER dialog is visible and cleanup hooks are armed
    try:
        enable_window(parent_hwnd, False)
    except Exception:
        _release_parent(restore_focus=False)

def _system_exe(name: str) -> str:
    """Resolve a Windows built-in executable or DLL from System32 to prevent CWD/PATH hijacking."""
    if not IS_WINDOWS or not name or os.path.isabs(name):
        return name
    sys32 = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")
    if name.lower() in ("powershell", "powershell.exe"):
        ps_path = os.path.join(sys32, "WindowsPowerShell", "v1.0", "powershell.exe")
        if os.path.isfile(ps_path):
            return ps_path
    base = os.path.basename(name)
    names_to_try = [name] if "." in base else [f"{name}.exe", f"{name}.cmd"]
    for directory in (sys32, os.path.join(sys32, "wbem")):
        for candidate_name in names_to_try:
            candidate = os.path.join(directory, candidate_name)
            if os.path.isfile(candidate):
                return candidate
    return name

def _safe_subproc_env(extra_env: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    env = dict(os.environ)
    if IS_WINDOWS:
        env.setdefault("NoDefaultCurrentDirectoryInExePath", "1")
    if extra_env:
        env.update(extra_env)
    return env

def _subproc_kwargs_hide_window() -> dict:
    if IS_WINDOWS:
        kwargs = {"creationflags": WINDOWS_CREATE_NO_WINDOW}
        if STARTUPINFO is not None:
            kwargs["startupinfo"] = STARTUPINFO
        return kwargs
    return {}

def _run_check_output(cmd, shell=False, **kwargs) -> str:
    if isinstance(cmd, (list, tuple)) and cmd and not shell:
        cmd = [_system_exe(str(cmd[0])), *cmd[1:]]
    base_kwargs = {"text": True, "encoding": "utf-8", "errors": "ignore", "shell": shell}
    if "env" not in kwargs:
        base_kwargs["env"] = _safe_subproc_env()
    base_kwargs.update(_subproc_kwargs_hide_window())
    base_kwargs.update(kwargs)
    return subprocess.check_output(cmd, **base_kwargs)

def load_oui_database(force_reload: bool = False):
    """Load OUI vendor mappings from the local SQLite cache."""
    global _oui_vendor_cache

    if force_reload or _oui_vendor_cache is None:
        _oui_vendor_cache = secuditor_loader.load_oui_cache()

        if _oui_vendor_cache:
            logging.info(
                f"[+] OUI database loaded successfully "
                f"({len(_oui_vendor_cache):,} vendor mappings)."
            )
        else:
            logging.warning(
                "[!] OUI database is empty or unavailable."
            )

    return _oui_vendor_cache

def get_default_interface_and_ip():
    """Detect the default network interface name and its local IPv4 address."""
    interface = None
    local_ip = None

    try:
        interfaces = psutil.net_if_addrs()

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
        except Exception:
            pass
        finally:
            s.close()

        if local_ip:
            for name, addrs in interfaces.items():
                for addr in addrs:
                    if addr.family == socket.AF_INET and addr.address == local_ip:
                        interface = name
                        break
                if interface:
                    break
    except Exception:
        pass

    return interface, local_ip

VPN_INTERFACE_KEYWORDS = (
    "vpn",
    "ppp",
    "tap",
    "tun",
    "wireguard",
    "anyconnect",
    "forti",
    "globalprotect",
    "tailscale",
    "zerotier",
    "openvpn",
    "nordlynx",
    "protonvpn",
    "mullvad",
)


def _is_vpn_interface_name(
    name: Optional[str],
    keywords: Iterable[str] = VPN_INTERFACE_KEYWORDS,
) -> bool:
    """Return True if an interface name matches known VPN/tunnel adapter keywords."""
    if not name:
        return False
    lname = name.lower()
    return any(k in lname for k in keywords)


def get_ipv4_default_gateways() -> List[Dict[str, Optional[str]]]:
    """Return active IPv4 default gateway entries as {gateway, interface_ip, metric}."""
    entries: List[Dict[str, Optional[str]]] = []
    seen_gateways = set()

    def _add_entry(gw: str, iface_ip: Optional[str] = None, metric: Optional[int] = None):
        gw = gw.strip()
        try:
            ip_obj = ipaddress.IPv4Address(gw)
        except ValueError:
            return
        if ip_obj.is_unspecified or ip_obj.is_loopback:
            return
        gw_str = str(ip_obj)
        if gw_str in seen_gateways:
            return
        seen_gateways.add(gw_str)
        entries.append({"gateway": gw_str, "interface_ip": iface_ip, "metric": metric})

    if IS_WINDOWS:
        try:
            route_out = _run_check_output(["route", "print", "-4", "0.0.0.0"], shell=False)
            route_rows = []
            for line in route_out.splitlines():
                m = re.match(
                    r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s*$",
                    line,
                )
                if m:
                    gw, iface_ip, metric = m.group(1), m.group(2), int(m.group(3))
                    route_rows.append((metric, gw, iface_ip))
            for metric, gw, iface_ip in sorted(route_rows, key=lambda r: r[0]):
                _add_entry(gw, iface_ip=iface_ip, metric=metric)
        except Exception:
            pass

        if not entries:
            try:
                ipcfg_out = _run_check_output(["ipconfig"], shell=False)
                collecting = False
                for raw_line in ipcfg_out.splitlines():
                    line = raw_line.strip()
                    if "Default Gateway" in line and ":" in line:
                        collecting = True
                        _add_entry(line.split(":", 1)[-1])
                    elif collecting:
                        if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", line):
                            _add_entry(line)
                        else:
                            collecting = False
            except Exception:
                pass
    else:
        try:
            route_out = _run_check_output(["ip", "-4", "route", "show", "default"], shell=False)
            for line in route_out.splitlines():
                m = re.search(r"\bvia\s+(\d+\.\d+\.\d+\.\d+)", line)
                if m:
                    _add_entry(m.group(1))
        except Exception:
            pass

    return entries


def guess_subnet(ip: Optional[str], mask_bits: int = 24, default=None):
    if not ip:
        return default
    try:
        return ipaddress.ip_network(f"{ip}/{mask_bits}", strict=False)
    except Exception:
        return default

def _bring_window_to_front(win) -> bool:
    if win is None:
        return False
    try:
        if win.winfo_exists():
            win.deiconify()
            win.lift()
            win.focus_force()
            return True
    except tk.TclError:
        pass
    return False

def _create_centered_tool_window(parent, title: str, width: int = 1024, height: int = 500, parent_geom: Optional[str] = None):
    if parent is None:
        win = tk.Tk()
    else:
        win = tk.Toplevel(parent)
    win.withdraw()
    set_window_icon(win)
    win.title(title)
    win.resizable(False, False)

    win.update_idletasks()
    sw = win.winfo_screenwidth()
    sh = win.winfo_screenheight()

    if parent is not None:
        parent.update_idletasks()
        pw = parent.winfo_width()
        ph = parent.winfo_height()
        if pw > 0:
            width = min(pw, sw)
        x = parent.winfo_x()
        if hasattr(parent, "report_output") and parent.report_output.winfo_exists():
            y = parent.report_output.winfo_rooty() - 4
        else:
            y = parent.winfo_y() + (ph - height) // 2
    else:
        m = re.fullmatch(r"(\d{1,5})x(\d{1,5})([+-]\d{1,5})([+-]\d{1,5})", str(parent_geom or "").strip())
        if m:
            pw, ph, px, py = (int(m.group(i)) for i in range(1, 5))
            if pw > 0:
                width = min(pw, sw)
            if ph > 0:
                height = min(ph, sh)
            x = px
            y = py
        else:
            width = min(width, sw)
            x = (sw - width) // 2
            y = (sh - height) // 2

    x = max(0, min(x, max(0, sw - width)))
    y = max(0, min(y, max(0, sh - height)))

    win.geometry(f"{width}x{height}+{x}+{y}")
    return win

def _parse_log_cli_args():
    log_level = logging.DEBUG if "--debug" in sys.argv else logging.INFO
    log_file = None
    if "--log" in sys.argv:
        idx = sys.argv.index("--log")
        log_file = sys.argv[idx + 1] if idx + 1 < len(sys.argv) else "scan.log"
    return log_level, log_file

def _create_scrolled_log_text(parent) -> tk.Text:
    log_frame = ttk.Frame(parent)
    log_frame.pack(fill="both", expand=True, padx=10, pady=10)

    txt = tk.Text(log_frame, width=90, height=22, state="disabled")
    scrollbar = ttk.Scrollbar(log_frame, orient="vertical", command=txt.yview)
    txt.pack(side="left", fill="both", expand=True)
    scrollbar.pack_forget()

    def update_scrollbar(*args):
        scrollbar.set(*args)
        first, last = float(args[0]), float(args[1])
        if first <= 0.0 and last >= 1.0:
            scrollbar.pack_forget()
        elif not scrollbar.winfo_ismapped():
            scrollbar.pack(side="right", fill="y")

    txt.configure(yscrollcommand=update_scrollbar)

    context_menu = tk.Menu(txt, tearoff=0)

    def copy_text():
        try:
            selected_text = txt.get("sel.first", "sel.last")
            txt.clipboard_clear()
            txt.clipboard_append(selected_text)
        except tk.TclError:
            pass

    def select_all_text():
        txt.configure(state="normal")
        txt.tag_add("sel", "1.0", "end")
        txt.configure(state="disabled")
        txt.focus_set()

    context_menu.add_command(label="Copy", command=copy_text)
    context_menu.add_command(label="Select All", command=select_all_text)

    def show_context_menu(event):
        try:
            context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            context_menu.grab_release()

    txt.bind("<Button-3>", show_context_menu)
    return txt

class _ThreadSafeLogBuffer:
    """Thread-safe drop-in StringIO buffer for concurrent StreamHandler writes and UI exports."""
    def __init__(self):
        self._lock = threading.Lock()
        self._buf = io.StringIO()

    def write(self, s: str) -> int:
        with self._lock:
            return self._buf.write(s)

    def flush(self):
        with self._lock:
            self._buf.flush()

    def getvalue(self) -> str:
        with self._lock:
            return self._buf.getvalue()

    def clear(self):
        with self._lock:
            self._buf.seek(0)
            self._buf.truncate(0)

    def seek(self, pos: int, whence: int = 0) -> int:
        with self._lock:
            return self._buf.seek(pos, whence)

    def truncate(self, size: Optional[int] = None) -> int:
        with self._lock:
            return self._buf.truncate(size)

class _QueueTextLogHandler(logging.Handler):
    """Thread-safe logging handler that pushes formatted lines to a Queue (no Tk calls off-thread)."""
    def __init__(self, ui_queue: "queue.Queue"):
        super().__init__()
        self.ui_queue = ui_queue
        self.setFormatter(logging.Formatter("%(message)s"))

    def emit(self, record):
        try:
            msg = self.format(record)
            self.ui_queue.put(("log", msg))
        except Exception:
            pass

class _TextWidgetLogHandler(logging.Handler):
    def __init__(self, txt: tk.Text):
        super().__init__()
        self.txt = txt
        self.setFormatter(logging.Formatter("%(message)s"))

    def emit(self, record):
        msg = self.format(record)

        def append():
            try:
                if self.txt.winfo_exists():
                    self.txt.config(state="normal")
                    self.txt.insert("end", msg + "\n")
                    self.txt.see("end")
                    self.txt.config(state="disabled")
            except (tk.TclError, RuntimeError):
                pass

        try:
            if self.txt.winfo_exists():
                self.txt.after(0, append)
        except (tk.TclError, RuntimeError):
            pass

def _attach_text_log_handler(logger, txt: tk.Text, old_handler):
    if old_handler:
        logger.removeHandler(old_handler)
    handler = _TextWidgetLogHandler(txt)
    logger.addHandler(handler)
    return handler

def _close_logger_handlers(logger):
    if logger is None:
        return
    for handler in logger.handlers[:]:
        try:
            logger.removeHandler(handler)
            handler.close()
        except Exception:
            pass

def _export_log_buffer(parent_win, title: str, log_buffer, handle_errors: bool = False):
    filename = filedialog.asksaveasfilename(
        parent=parent_win,
        title=title,
        defaultextension=".txt",
        filetypes=[("Text Files", "*.txt")]
    )
    if not filename:
        return

    try:
        with open(filename, "w", encoding="utf-8") as f:
            f.write(log_buffer.getvalue())
        messagebox.showinfo(
            "Export",
            f"Logs exported successfully.\n\n{filename}",
            parent=parent_win
        )
    except Exception as e:
        if handle_errors:
            messagebox.showerror("Export Error", str(e), parent=parent_win)
        else:
            raise

# ====== Logger Setup =======
def setup_logger(
    logger_name,
    level=logging.INFO,
    logfile: Optional[str] = None,
    log_buffer=None
):
    """Create and configure an isolated logger."""

    logger = logging.getLogger(logger_name)
    logger.setLevel(level)
    logger.propagate = False

    # Remove old handlers belonging to this logger only
    _close_logger_handlers(logger)

    if logfile:
        fh = logging.FileHandler(logfile, encoding="utf-8")
        fh.setFormatter(
            logging.Formatter(
                "%(asctime)s [%(levelname)s] %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S"
            )
        )
        logger.addHandler(fh)

    if log_buffer is not None:
        sh = logging.StreamHandler(log_buffer)
        sh.setFormatter(
            logging.Formatter(
                "%(asctime)s [%(levelname)s] %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S"
            )
        )
        logger.addHandler(sh)

    return logger

# ====== Traffic Flow =======
class TrafficFlow:
    def __init__(self, parent=None):
        self.parent = parent

        self.traflow_win = None

        self.log_buffer = io.StringIO()

        self.logger = None
        self.text_handler = None

        self.stop_event = None
        self.flow_thread = None
        self.seen = set()

        self.NOISE_PORTS = {
            5353,
            1900,
            123,
            137,
            138,
            139
        }

    # Helpers
    def _get_process_name(self, pid):
        if pid is None:
            return "N/A"
        try:
            return psutil.Process(pid).name()
        except Exception:
            return "N/A"

    def _detect_direction(
        self,
        laddr_ip: str,
        raddr_ip: str,
        local_port: int = None,
        listening_ports=None,
        local_subnet=None
    ) -> str:
        try:
            l_ip = ipaddress.ip_address(laddr_ip)
            r_ip = ipaddress.ip_address(raddr_ip)

            # A connection using a local listening port is
            # likely an accepted inbound connection.
            if listening_ports and local_port in listening_ports:
                return "IN"

            # Distinguish local-network traffic from Internet traffic.
            if local_subnet and r_ip in local_subnet:
                return "LAN"

            # A local endpoint communicating with a remote endpoint.
            return "OUT"

        except (ValueError, TypeError):
            return "UNKNOWN"

    # Traffic Flow
    def _is_noise_traffic(self, conn):
        is_udp = conn.type == socket.SOCK_DGRAM

        allowed_statuses = (
            "ESTABLISHED",
            "CLOSE_WAIT",
            "SYN_SENT",
            "LISTEN",
        )

        # UDP sockets commonly have no TCP-style connection status.
        if is_udp:
            if conn.status not in ("NONE", ""):
                return True
        elif conn.status not in allowed_statuses:
            return True

        if conn.raddr:
            remote_ip = conn.raddr.ip

            if remote_ip.startswith("fe80:"):
                return True

            if remote_ip in ("::", "::1"):
                return True

            if remote_ip.startswith("127."):
                return True

            if remote_ip.startswith("169.254."):
                return True

        if conn.laddr and conn.laddr.port in self.NOISE_PORTS:
            return True

        if conn.raddr and conn.raddr.port in self.NOISE_PORTS:
            return True

        # Ignore UDP sockets without a remote endpoint.
        if is_udp and not conn.raddr:
            return True

        return False

    def _inspect_connections(
        self,
        interval: float = 1.0,
        ports=None,
        timeout: int = 0,
        skip_time_wait: bool = True,
        stop_event: Optional[threading.Event] = None,
        logger: Optional[logging.Logger] = None,
    ):

        active_stop = stop_event if stop_event is not None else self.stop_event
        active_logger = logger if logger is not None else self.logger
        ports_set = set(ports) if ports else None
        seen = set()

        _, local_ip = get_default_interface_and_ip()
        local_ip = local_ip or "0.0.0.0"
        local_subnet = guess_subnet(local_ip, 24)

        active_logger.info("")
        active_logger.info(
            f"=== Traffic Flow started "
            f"(ports: {ports if ports else 'all'}) ==="
        )

        start_time = time.time()

        while active_stop is None or not active_stop.is_set():

            now = time.time()

            try:

                connections = psutil.net_connections(kind="inet")

                listening_ports = {
                    conn.laddr.port
                    for conn in connections
                    if conn.laddr and conn.status == "LISTEN"
                }

                for conn in connections:

                    if active_stop is not None and active_stop.is_set():
                        break

                    # Must have local address
                    if not conn.laddr:
                        continue

                    proto = (
                        "UDP"
                        if conn.type == socket.SOCK_DGRAM
                        else "TCP"
                    )

                    l_ip = conn.laddr.ip
                    l_port = conn.laddr.port

                    r_ip = (
                        conn.raddr.ip
                        if conn.raddr
                        else None
                    )

                    r_port = (
                        conn.raddr.port
                        if conn.raddr
                        else None
                    )

                    # TIME_WAIT filter
                    if (
                        skip_time_wait
                        and proto == "TCP"
                        and conn.status == "TIME_WAIT"
                    ):
                        continue

                    # Port filter
                    if ports_set:

                        if (
                            l_port not in ports_set
                            and (
                                r_port not in ports_set
                                if r_port
                                else True
                            )
                        ):
                            continue

                    # Noise filter
                    if self._is_noise_traffic(conn):
                        continue

                    # LISTEN cleanup
                    if conn.status == "LISTEN":

                        if l_ip in (
                            "127.0.0.1",
                            "::1",
                            "0.0.0.0",
                            "::"
                        ):
                            continue

                        if l_port in self.NOISE_PORTS:
                            continue

                    # Deduplicate
                    key = (
                        conn.pid,
                        l_ip,
                        l_port,
                        r_ip,
                        r_port,
                        conn.status
                    )

                    if key in seen:
                        continue

                    seen.add(key)

                    # Process
                    proc_name = self._get_process_name(
                        conn.pid
                    )

                    # Direction
                    if conn.status == "LISTEN":

                        direction = "LISTEN"
                        src = f"{l_ip}:{l_port}"
                        dst = "*:*"

                    elif r_ip:

                        direction = self._detect_direction(
                            l_ip,
                            r_ip,
                            local_port=l_port,
                            listening_ports=listening_ports,
                            local_subnet=local_subnet
                        )

                        src = f"{l_ip}:{l_port}"
                        dst = f"{r_ip}:{r_port}"

                        # Reverse endpoints for incoming connections
                        if direction == "IN":
                            src, dst = dst, src

                    else:

                        direction = "LOCAL"
                        src = f"{l_ip}:{l_port}"
                        dst = "*:*"

                    # Log
                    active_logger.info(
                        f"[FLOW] {proto} {direction} "
                        f"{proc_name} {src} → {dst} "
                        f"({conn.status})"
                    )

                # Memory cleanup
                if len(seen) > 5000:
                    seen.clear()

            except Exception as e:

                active_logger.error(
                    f"[Inspector Error] {e}"
                )

            # Timeout
            if (
                timeout > 0
                and (now - start_time) >= timeout
            ):
                active_logger.info(
                    "Traffic flow timeout reached."
                )
                if active_stop is not None:
                    active_stop.set()
                break

            if active_stop is not None:
                active_stop.wait(interval)
            else:
                time.sleep(interval)

        active_logger.info(
            "=== Traffic flow stopped ==="
        )

    # Run
    def run(self, parent_geom=None):

        if _bring_window_to_front(self.traflow_win):
            return self.traflow_win
        self.traflow_win = _create_centered_tool_window(self.parent, "Traffic Flow", parent_geom=parent_geom)
        traflow_win = self.traflow_win

        # Signal any previous window's worker to stop without blocking the new session
        if self.stop_event is not None:
            self.stop_event.set()

        # Per-window isolated session state (queue, logger, buffer, thread, run_id)
        session_id = uuid.uuid4().hex[:8]
        log_level, log_file = _parse_log_cli_args()
        win_log_buffer = _ThreadSafeLogBuffer()
        self.log_buffer = win_log_buffer

        win_logger = setup_logger(
            f"secuditor.trafficflow.{session_id}",
            level=log_level,
            logfile=log_file,
            log_buffer=win_log_buffer,
        )
        self.logger = win_logger

        ui_queue: "queue.Queue" = queue.Queue()
        win_text_handler = _QueueTextLogHandler(ui_queue)
        win_logger.addHandler(win_text_handler)
        self.text_handler = win_text_handler

        win_stop_event = threading.Event()
        self.stop_event = win_stop_event
        self.seen = set()

        win_state = {
            "thread": None,
            "run_stop_event": None,
            "run_id": 0,
            "closed": False,
            "poll_job": None,
        }

        # Status
        status_var = tk.StringVar(value="Ready")

        ttk.Label(
            traflow_win,
            textvariable=status_var
        ).pack(pady=(10, 5))

        # Log window
        txt = _create_scrolled_log_text(traflow_win)

        win_logger.info(
            "Secuditor Traffic Flow Log"
        )

        # Port filter
        port_frame = ttk.Frame(traflow_win)
        port_frame.pack(
            pady=(0, 5)
        )

        ttk.Label(
            port_frame,
            text="Ports:"
        ).pack(
            side="left",
            padx=(0, 5)
        )

        port_var = tk.StringVar()

        port_entry = ttk.Entry(
            port_frame,
            textvariable=port_var,
            width=30
        )

        port_entry.pack(
            side="left"
        )

        ttk.Label(
            port_frame,
            text="(e.g. 443, 80, 22 | default: All Ports)"
        ).pack(
            side="left",
            padx=(5, 0)
        )

        # Start / Stop / Export
        def parse_ports():

            value = port_var.get().strip()

            if not value:
                return None

            ports = set()

            for item in value.split(","):

                item = item.strip()

                if not item:
                    continue

                try:

                    port = int(item)

                except ValueError:

                    messagebox.showerror(
                        "Invalid Port",
                        f"Invalid port value:\n\n{item}",
                        parent=traflow_win
                    )

                    return False

                if not 1 <= port <= 65535:

                    messagebox.showerror(
                        "Invalid Port",
                        f"Port must be between 1 and 65535:\n\n{port}",
                        parent=traflow_win
                    )

                    return False

                ports.add(port)

            if not ports:

                return None

            return sorted(ports)

        def flow_worker(ports, run_stop_event, run_id):

            start_time = time.time()

            try:

                interface, local = (
                    get_default_interface_and_ip()
                )

                win_logger.info("")

                win_logger.info(
                    f"Interface: {interface or 'N/A'}"
                )

                win_logger.info(
                    f"Local IP: {local or 'N/A'}"
                )

                if local:

                    try:

                        subnet = guess_subnet(
                            local,
                            24
                        )

                        win_logger.info(
                            f"Detected subnet: {subnet}"
                        )

                    except Exception:

                        subnet = None

                else:

                    subnet = None

                if ports:

                    win_logger.info(
                        f"Port filter: "
                        f"{', '.join(map(str, ports))}"
                    )

                else:

                    win_logger.info(
                        "Port filter: All"
                    )

                win_logger.info("")

                if run_stop_event.is_set():
                    return

                self._inspect_connections(
                    interval=0.2,
                    ports=ports,
                    timeout=0,
                    skip_time_wait=True,
                    stop_event=run_stop_event,
                    logger=win_logger,
                )

            finally:

                elapsed = (
                    time.time()
                    - start_time
                )

                win_logger.info("")

                win_logger.info(
                    f"Traffic Flow finished in "
                    f"{elapsed:.1f} seconds"
                )

                ui_queue.put(("done", (run_id, run_stop_event.is_set())))

        def start_flow():

            if (
                win_state["thread"]
                and win_state["thread"].is_alive()
            ):
                return

            ports = parse_ports()

            if ports is False:
                return

            txt.config(state="normal")
            txt.delete("1.0", "end")
            txt.config(state="disabled")

            win_log_buffer.clear()

            run_stop_event = threading.Event()
            win_state["run_stop_event"] = run_stop_event
            win_state["run_id"] += 1
            current_run_id = win_state["run_id"]
            self.stop_event = run_stop_event
            self.seen.clear()

            btn_start["state"] = "disabled"
            btn_stop["state"] = "normal"
            port_entry["state"] = "disabled"

            status_var.set(
                "Traffic flow running..."
            )

            t = threading.Thread(
                target=flow_worker,
                args=(ports, run_stop_event, current_run_id),
                daemon=True
            )
            win_state["thread"] = t
            self.flow_thread = t

            t.start()

        def stop_flow():

            if (
                win_state["thread"]
                and win_state["thread"].is_alive()
            ):

                if win_state["run_stop_event"] is not None:
                    win_state["run_stop_event"].set()

                try:
                    if traflow_win.winfo_exists():
                        status_var.set("Stopping...")
                        btn_stop["state"] = "disabled"
                except tk.TclError:
                    pass

                win_logger.warning(
                    "Stop requested..."
                )

        def export_logs():
            _export_log_buffer(
                traflow_win,
                "Export Traffic Flow Log",
                win_log_buffer,
                handle_errors=True
            )

        # Buttons
        buttons = ttk.Frame(
            traflow_win
        )

        buttons.pack(
            pady=10
        )

        btn_start = ttk.Button(
            buttons,
            text="Start",
            command=start_flow
        )

        btn_start.grid(
            row=0,
            column=0,
            padx=5
        )

        btn_stop = ttk.Button(
            buttons,
            text="Stop",
            command=stop_flow,
            state="disabled"
        )

        btn_stop.grid(
            row=0,
            column=1,
            padx=5
        )

        btn_export = ttk.Button(
            buttons,
            text="Export Logs",
            command=export_logs
        )

        btn_export.grid(
            row=0,
            column=2,
            padx=5
        )

        # Main-thread UI queue poller (drains logs FIFO before applying done state)
        def drain_ui_queue():
            if win_state["closed"]:
                return
            try:
                if not traflow_win.winfo_exists():
                    win_state["closed"] = True
                    return

                log_batch = []
                done_payload = None
                while True:
                    try:
                        kind, payload = ui_queue.get_nowait()
                    except queue.Empty:
                        break
                    if kind == "log":
                        log_batch.append(payload)
                    elif kind == "done":
                        done_payload = payload

                if log_batch:
                    txt.config(state="normal")
                    txt.insert("end", "\n".join(log_batch) + "\n")
                    txt.see("end")
                    txt.config(state="disabled")

                if done_payload is not None:
                    finished_run_id, was_stopped = done_payload
                    if finished_run_id == win_state["run_id"]:
                        status_var.set("Stopped" if was_stopped else "Finished")
                        btn_start["state"] = "normal"
                        btn_stop["state"] = "disabled"
                        port_entry["state"] = "normal"

                win_state["poll_job"] = traflow_win.after(40, drain_ui_queue)
            except (tk.TclError, RuntimeError):
                win_state["closed"] = True

        # Close
        def on_close():
            if win_state["closed"]:
                return
            win_state["closed"] = True

            if win_state["poll_job"] is not None:
                try:
                    traflow_win.after_cancel(win_state["poll_job"])
                except (tk.TclError, RuntimeError):
                    pass
                win_state["poll_job"] = None

            win_stop_event.set()
            if win_state["run_stop_event"] is not None:
                win_state["run_stop_event"].set()

            _close_logger_handlers(win_logger)
            if self.text_handler is win_text_handler:
                self.text_handler = None

            if self.traflow_win is traflow_win:
                self.traflow_win = None

            try:
                if traflow_win.winfo_exists():
                    traflow_win.destroy()
            except (tk.TclError, RuntimeError):
                pass

        traflow_win.protocol(
            "WM_DELETE_WINDOW",
            on_close
        )
        traflow_win.bind("<Destroy>", lambda e: on_close() if e.widget is traflow_win else None)

        win_state["poll_job"] = traflow_win.after(40, drain_ui_queue)

        # Show window
        traflow_win.deiconify()
        traflow_win.lift()
        traflow_win.focus_force()

        return traflow_win

# ===== CLASS LAN Scanning =====
class LanScanner:
    MAX_SUBNET_HOSTS = 512

    UDP_PROBES: Dict[int, bytes] = {
        53: b"\xaa\xaa\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03",
        69: b"\x00\x01test\x00octet\x00",
        123: b"\x1b" + 47 * b"\0",
        137: b"\x80\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00!\x00\x01",
        161: b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x00\x00\x00\x00\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00",
        162: b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x00\x00\x00\x00\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00",
        520: b"\x01\x01\x00\x00" + 20 * b"\x00",
        1434: b"\x02",
        1900: b'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n',
        5353: b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x09_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0c\x00\x01",
        5683: b"\x40\x01\x12\x34",
        11211: b"\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n",
        27015: b"\xff\xff\xff\xffTSource Engine Query\x00",
    }

    _TABLE_HEADERS = ["IP Address", "Vendor", "MAC", "Alive", "Open Ports"]
    _TABLE_COL_WIDTHS = [15, 26, 20, 10, 40]

    def __init__(self, parent=None):
        self.parent = parent

        self.lan_win = None

        self.log_buffer = io.StringIO()

        self.logger = logging.getLogger("secuditor.lanscan")
        self.text_handler = None
        self.stop_event = threading.Event()
        self.scan_thread = None
        self.scan_results = []

    def _scan_stopped(self, stop_event: Optional[threading.Event] = None) -> bool:
        ev = stop_event if stop_event is not None else getattr(self, "stop_event", None)
        return bool(ev and ev.is_set())

    def _lookup_vendor(self, mac: Optional[str]) -> str:
        """Lookup vendor from MAC address."""

        if not mac:
            return "Unknown"

        mac_key = mac.strip().upper()

        # Normalize MAC separators to match oui.csv
        oui = mac_key[:8].replace(":", "-")

        oui_database = load_oui_database()

        return oui_database.get(oui, "Unknown")

    def _ping(self, ip: str, timeout_ms: int = 300) -> bool:
        system = platform.system().lower()

        if system == "windows":
            cmd = [_system_exe("ping"), "-n", "1", "-w", str(timeout_ms), ip]
        else:
            # Linux / macOS
            timeout_sec = max(1, timeout_ms // 1000)
            cmd = ["ping", "-c", "1", "-W", str(timeout_sec), ip]

        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                encoding="utf-8",
                errors="ignore",
                env=_safe_subproc_env(),
                **_subproc_kwargs_hide_window()
            )
        except Exception:
            return False

        if result.returncode != 0 or not result.stdout:
            return False

        # Windows ping.exe exits 0 on ICMP error replies (e.g. "Destination host unreachable",
        # "TTL expired in transit"); require an actual echo reply line for `ip` with `TTL=<n>`.
        ip_pattern = re.compile(rf"(?<!\d){re.escape(ip)}(?!\d)")
        ttl_pattern = re.compile(r"\bttl\s*=\s*\d+", re.IGNORECASE)
        return any(
            ip_pattern.search(line) and ttl_pattern.search(line)
            for line in result.stdout.splitlines()
        )

    def _parse_arp_table(self) -> Dict[str, str]:
        ip_to_mac = {}
        try:
            out = _run_check_output(["arp", "-a"], shell=False)
            if IS_WINDOWS:
                for line in out.splitlines():
                    m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{14,17})", line)
                    if m:
                        ip, mac = m.group(1), m.group(2).replace("-", ":").lower()
                        ip_to_mac[ip] = mac
            else:
                for line in out.splitlines():
                    m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]{17})", line)
                    if m:
                        ip, mac = m.group(1), m.group(2).lower()
                        ip_to_mac[ip] = mac
        except Exception:
            pass
        return ip_to_mac

    def _scan_ports(
        self,
        ip: str,
        ports: Iterable[int],
        timeout: float = 0.5,
        max_workers: int = 100,
        on_port_found=None,
        stop_event: Optional[threading.Event] = None
    ) -> List[int]:

        open_ports = []
        ports_list = list(ports)

        if not ports_list or self._scan_stopped(stop_event):
            return []

        def _try_port(port: int) -> Optional[int]:
            if self._scan_stopped(stop_event):
                return None

            if port in COMMON_PORTS_UDP or port in self.UDP_PROBES:
                try:
                    probe = self.UDP_PROBES.get(port, b"\x00")
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                        s.settimeout(timeout)
                        s.sendto(probe, (ip, port))
                        data, _ = s.recvfrom(1024)
                        if data:
                            return port
                except Exception:
                    pass

            if self._scan_stopped(stop_event):
                return None

            if port not in COMMON_PORTS_UDP or port in COMMON_PORTS_TCP:
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(timeout)
                        if s.connect_ex((ip, port)) == 0:
                            return port
                except Exception:
                    pass

            return None

        worker_count = min(max_workers, len(ports_list))
        ex = concurrent.futures.ThreadPoolExecutor(max_workers=worker_count)
        futures = {ex.submit(_try_port, port): port for port in ports_list}
        try:
            for fut in concurrent.futures.as_completed(futures):
                if self._scan_stopped(stop_event):
                    for pending in futures:
                        pending.cancel()
                    break

                try:
                    res = fut.result()
                except Exception:
                    continue

                if res is not None:
                    open_ports.append(res)

                    # Report immediately
                    if on_port_found:
                        try:
                            on_port_found(res)
                        except Exception:
                            pass
        finally:
            stopped = self._scan_stopped(stop_event)
            ex.shutdown(wait=not stopped, cancel_futures=stopped)

        return sorted(open_ports)

    def _clamp_subnet(
        self,
        subnet: Optional[ipaddress.IPv4Network],
        local_ip: Optional[str] = None,
        action: str = "scan",
    ) -> Optional[ipaddress.IPv4Network]:
        """Clamp oversized subnets to /24 around local_ip, or return None if unbounded."""
        if subnet is None or subnet.num_addresses <= self.MAX_SUBNET_HOSTS:
            return subnet
        if local_ip:
            self.logger.warning(
                f"Subnet {subnet} is too large ({subnet.num_addresses} addresses). "
                f"Restricting {action} to /24 around {local_ip} to prevent system freeze."
            )
            return guess_subnet(local_ip, 24)
        self.logger.error(
            f"Subnet {subnet} is too large ({subnet.num_addresses} addresses; max is {self.MAX_SUBNET_HOSTS}). "
            f"Aborting {action} to prevent system freeze."
        )
        return None

    def _scan_ips_incremental(
        self,
        ips: List[str],
        subnet: Optional[ipaddress.IPv4Network] = None,
        local_ip: Optional[str] = None,
        do_port_scan: bool = False,
        ports: Optional[Iterable[int]] = None,
        on_device=None,
        include_arp_only: bool = True,
        check_arp_fallback: bool = False,
        tcp_timeout: float = 0.3,
        port_timeout: float = 0.6,
        stop_event: Optional[threading.Event] = None,
    ) -> List[dict]:
        """
        Incrementally probe each IP in parallel and invoke `on_device(device)`
        as soon as each host finishes discovery and port scanning.
        Returns the full sorted list of discovered devices.
        """
        if not ips or self._scan_stopped(stop_event):
            return []

        if ports is None:
            ports = COMMON_PORTS_TCP + COMMON_PORTS_UDP
        else:
            ports = list(ports)

        # Warm OUI cache before spawning worker threads
        load_oui_database()

        ip_mac = self._parse_arp_table()
        arp_lock = threading.Lock()
        last_arp_refresh = [time.monotonic()]
        ping_sem = threading.Semaphore(64)
        port_scan_sem = threading.Semaphore(6)

        emitted_ips = set()
        emitted_lock = threading.Lock()
        callback_lock = threading.Lock()
        devices: List[dict] = []

        def _emit(device: dict):
            with emitted_lock:
                if self._scan_stopped(stop_event):
                    return
                if device["ip"] in emitted_ips:
                    return
                emitted_ips.add(device["ip"])
                devices.append(device)
            if on_device:
                with callback_lock:
                    if not self._scan_stopped(stop_event):
                        on_device(device)

        def _get_mac(ip: str) -> Optional[str]:
            with arp_lock:
                mac = ip_mac.get(ip)
                if mac:
                    return mac
                now_mono = time.monotonic()
                if now_mono - last_arp_refresh[0] >= 0.25:
                    ip_mac.update(self._parse_arp_table())
                    last_arp_refresh[0] = now_mono
                    return ip_mac.get(ip)
            return None

        def _probe_host(ip: str):
            if self._scan_stopped(stop_event):
                return
            if local_ip and ip == local_ip:
                return

            tcp_alive = False
            for port in (22, 53, 80, 139, 443, 445):
                if self._scan_stopped(stop_event):
                    return
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(tcp_timeout)
                        if s.connect_ex((ip, port)) == 0:
                            tcp_alive = True
                            break
                except Exception:
                    pass

            ping_alive = False
            if not tcp_alive and not self._scan_stopped(stop_event):
                with ping_sem:
                    if not self._scan_stopped(stop_event):
                        ping_alive = self._ping(ip, timeout_ms=300)

            in_arp = False
            if not tcp_alive and not ping_alive and check_arp_fallback:
                with arp_lock:
                    in_arp = ip in ip_mac

            if self._scan_stopped(stop_event):
                return

            if not tcp_alive and not ping_alive and not in_arp:
                return

            alive = tcp_alive or ping_alive

            open_ports = []
            if do_port_scan:
                with port_scan_sem:
                    if not self._scan_stopped(stop_event):
                        open_ports = self._scan_ports(ip, ports, port_timeout, 32, stop_event=stop_event)
            if self._scan_stopped(stop_event):
                return

            mac = _get_mac(ip)
            vendor = self._lookup_vendor(mac)

            _emit({
                "ip": ip,
                "vendor": vendor,
                "mac": mac,
                "alive": alive,
                "open_ports": open_ports,
            })

        worker_count = min(100, len(ips))
        ex = concurrent.futures.ThreadPoolExecutor(max_workers=worker_count)
        futures = [ex.submit(_probe_host, ip) for ip in ips]
        try:
            for fut in concurrent.futures.as_completed(futures):
                if self._scan_stopped(stop_event):
                    for pending in futures:
                        pending.cancel()
                    break
                try:
                    fut.result()
                except Exception:
                    pass
        finally:
            stopped = self._scan_stopped(stop_event)
            ex.shutdown(wait=not stopped, cancel_futures=stopped)

        if self._scan_stopped(stop_event):
            with emitted_lock:
                snapshot = list(devices)
            return sorted(snapshot, key=lambda x: socket.inet_aton(x["ip"]))

        # ---- Include ARP-only hosts (TCP/ICMP-blocked / firewalled) ----
        if include_arp_only and subnet is not None:
            fresh_arp = self._parse_arp_table()
            with emitted_lock:
                already = set(emitted_ips)
            arp_only = []
            for ip, mac in fresh_arp.items():
                try:
                    ip_obj = ipaddress.ip_address(ip)
                    if ip_obj not in subnet:
                        continue
                    if ip == str(subnet.broadcast_address):
                        continue
                    if local_ip and ip == local_ip:
                        continue
                    if ip in already:
                        continue
                    if not mac or mac.lower().replace("-", ":").startswith("ff:ff"):
                        continue
                    arp_only.append((ip, mac))
                except ValueError:
                    continue

            if arp_only:
                def _finish_arp_only(ip_mac_pair):
                    if self._scan_stopped(stop_event):
                        return
                    ip, mac = ip_mac_pair
                    vendor = self._lookup_vendor(mac)
                    _emit({
                        "ip": ip,
                        "vendor": vendor,
                        "mac": mac,
                        "alive": False,
                        "open_ports": [],
                    })

                arp_ex = concurrent.futures.ThreadPoolExecutor(max_workers=min(50, len(arp_only)))
                arp_futures = [arp_ex.submit(_finish_arp_only, item) for item in arp_only]
                try:
                    for fut in concurrent.futures.as_completed(arp_futures):
                        if self._scan_stopped(stop_event):
                            for pending in arp_futures:
                                pending.cancel()
                            break
                        try:
                            fut.result()
                        except Exception:
                            pass
                finally:
                    stopped = self._scan_stopped(stop_event)
                    arp_ex.shutdown(wait=not stopped, cancel_futures=stopped)

        with emitted_lock:
            snapshot = list(devices)
        return sorted(snapshot, key=lambda x: socket.inet_aton(x["ip"]))

    def discover_network(
        self,
        subnet,
        local_ip=None,
        do_port_scan=False,
        ports=None,
        on_device=None,
        stop_event=None,
        extra_ips=None,
    ):
        """
        Discover hosts on a subnet incrementally. Works for Ethernet and Wi-Fi.
        - Uses TCP ports + ICMP ping + ARP table to detect hosts.
        - Emits each discovered host immediately via `on_device(device)` if provided.
        - Scans any explicit `extra_ips` (such as Default Gateways) even when `subnet` is None.
        """
        extra_list: List[str] = []
        seen_extra = set()
        for raw_ip in (extra_ips or ()):
            try:
                ip_str = str(ipaddress.IPv4Address(str(raw_ip).strip()))
            except ValueError:
                continue
            if local_ip and ip_str == local_ip:
                continue
            if ip_str not in seen_extra:
                seen_extra.add(ip_str)
                extra_list.append(ip_str)

        if subnet is None and local_ip and not extra_list:
            subnet = guess_subnet(local_ip, 24)

        if subnet is not None:
            subnet = self._clamp_subnet(subnet, local_ip=local_ip, action="LAN scan")

        if not subnet and not extra_list:
            self.logger.warning("No subnet provided, skipping scan.")
            return []

        ips = [str(ip) for ip in subnet.hosts()] if subnet else []
        ip_set = set(ips)
        for ip_str in extra_list:
            if ip_str not in ip_set:
                ips.append(ip_str)
                ip_set.add(ip_str)

        return self._scan_ips_incremental(
            ips=ips,
            subnet=subnet,
            local_ip=local_ip,
            do_port_scan=do_port_scan,
            ports=ports,
            on_device=on_device,
            include_arp_only=True,
            check_arp_fallback=bool(extra_list),
            stop_event=stop_event,
        )

    def _primary_mac(self) -> Optional[str]:
        """Return primary system MAC address (best-effort, cross-platform)."""
        try:
            mac = uuid.getnode()
            return ":".join(f"{(mac >> i) & 0xff:02x}" for i in range(40, -1, -8))
        except Exception:
            return None

    # ======= Print Setup =======
    @staticmethod
    def _trim_col(s: str, w: int) -> str:
        return (s[: w - 3] + "...") if len(s) > w else s

    def _print_table_header(self, logger: Optional[logging.Logger] = None) -> str:
        active_logger = logger if logger is not None else self.logger
        header_line = "  ".join(
            h.center(w) for h, w in zip(self._TABLE_HEADERS, self._TABLE_COL_WIDTHS)
        )
        sep_line = "–" * len(header_line)
        active_logger.info(sep_line)
        active_logger.info(header_line)
        active_logger.info(sep_line)
        return sep_line

    def _format_device_row(self, d: dict) -> str:
        ip = d["ip"]
        vendor = self._trim_col(d.get("vendor") or "Unknown", self._TABLE_COL_WIDTHS[1])
        mac = self._trim_col(d.get("mac") or "N/A", self._TABLE_COL_WIDTHS[2])
        alive = str(d["alive"])
        ports_str = (
            ", ".join(map(str, d["open_ports"]))
            if d.get("open_ports")
            else "N/A"
        )
        ports_str = self._trim_col(ports_str, self._TABLE_COL_WIDTHS[4])
        return (
            f"{ip.ljust(self._TABLE_COL_WIDTHS[0])}  {vendor.center(self._TABLE_COL_WIDTHS[1])}  "
            f"{mac.center(self._TABLE_COL_WIDTHS[2])}  {alive.center(self._TABLE_COL_WIDTHS[3])}  "
            f"{ports_str.center(self._TABLE_COL_WIDTHS[4])}"
        )

    def test_print(
        self,
        subnet: Optional[ipaddress.IPv4Network] = None,
        local_ip: Optional[str] = None,
        do_port_scan: bool = True,
        ports: Optional[Iterable[int]] = None,
        silent: bool = False,
        on_device=None,
        stop_event: Optional[threading.Event] = None,
        extra_ips: Optional[Iterable[str]] = None,
        logger: Optional[logging.Logger] = None,
    ) -> list:

        active_logger = logger if logger is not None else self.logger
        extra_list = list(extra_ips) if extra_ips else None

        if subnet is None and local_ip and not extra_list:
            subnet = guess_subnet(local_ip, 24)

        if silent:
            return self.discover_network(
                subnet=subnet,
                local_ip=local_ip,
                do_port_scan=do_port_scan,
                ports=ports,
                on_device=on_device,
                stop_event=stop_event,
                extra_ips=extra_list,
            )

        active_logger.info("")
        active_logger.info(f"Scanning local network...")
        active_logger.info("")
        sep_line = self._print_table_header(logger=active_logger)

        seen_ips = set()
        print_lock = threading.Lock()

        def _stream_device(d: dict):
            ip = d["ip"]
            with print_lock:
                if self._scan_stopped(stop_event):
                    return
                if ip in seen_ips:
                    return
                seen_ips.add(ip)
                active_logger.info(self._format_device_row(d))
            if on_device:
                on_device(d)

        devices = []
        try:
            devices = self.discover_network(
                subnet=subnet,
                local_ip=local_ip,
                do_port_scan=do_port_scan,
                ports=ports,
                on_device=_stream_device,
                stop_event=stop_event,
                extra_ips=extra_list,
            )
        finally:
            active_logger.info(sep_line)
            if self._scan_stopped(stop_event):
                active_logger.info("Scan stopped.")
            active_logger.info(f"Found {len(seen_ips)} devices")

        return devices

    # --- Define private IP check ---
    def is_private_ip(self, ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False

    @staticmethod
    def _get_interface_ipv4_subnet(
        interface: Optional[str],
        local_ip: Optional[str],
        addrs: dict,
    ) -> Optional[ipaddress.IPv4Network]:
        if not interface or not local_ip:
            return None
        for addr in addrs.get(interface, []):
            if addr.family == socket.AF_INET and addr.address == local_ip and addr.netmask:
                try:
                    return ipaddress.ip_network(f"{local_ip}/{addr.netmask}", strict=False)
                except ValueError:
                    return None
        return None

    @staticmethod
    def _find_physical_lan_fallback(gw_entries: list, addrs: dict, stats: dict):
        """Find an active non-VPN IPv4 interface/subnet, prioritizing interfaces with a default gateway."""
        candidates = []
        for if_name, if_addrs in addrs.items():
            if _is_vpn_interface_name(if_name):
                continue
            if stats and if_name in stats and not stats[if_name].isup:
                continue
            for addr in if_addrs:
                if addr.family != socket.AF_INET or not addr.netmask:
                    continue
                try:
                    ip_obj = ipaddress.IPv4Address(addr.address)
                    net = ipaddress.ip_network(f"{addr.address}/{addr.netmask}", strict=False)
                except ValueError:
                    continue
                if ip_obj.is_loopback or addr.address.startswith("169.254.") or net.prefixlen >= 32:
                    continue
                candidates.append((if_name, addr.address, net))

        for entry in gw_entries:
            if_ip = entry.get("interface_ip")
            if if_ip:
                for cand in candidates:
                    if cand[1] == if_ip:
                        return cand

        for entry in gw_entries:
            try:
                gw_obj = ipaddress.IPv4Address(entry["gateway"])
            except (KeyError, TypeError, ValueError):
                continue
            for cand in candidates:
                if gw_obj in cand[2]:
                    return cand

        virtual_hints = ("vmnet", "virtualbox", "vbox", "docker")
        for cand in candidates:
            lname = cand[0].lower()
            if not any(h in lname for h in virtual_hints):
                return cand

        return candidates[0] if candidates else None

    def _resolve_scan_target(self) -> dict:
        """Resolve local interface, subnet, VPN state, and fallback Default Gateway targets."""
        interface, local = get_default_interface_and_ip()
        mac = self._primary_mac()
        vpn_status = NetStatus().get_vpn_connection()
        gw_entries = get_ipv4_default_gateways()
        gw_ips = [e["gateway"] for e in gw_entries]

        try:
            addrs = psutil.net_if_addrs()
        except Exception:
            addrs = {}
        try:
            stats = psutil.net_if_stats()
        except Exception:
            stats = {}

        is_vpn_iface = _is_vpn_interface_name(interface)
        vpn_active = (vpn_status == "Enabled (connected)") or is_vpn_iface
        raw_subnet = self._get_interface_ipv4_subnet(interface, local, addrs)

        apipa = isinstance(local, str) and local.startswith("169.254.") and not vpn_active
        needs_fallback = (not apipa) and (
            is_vpn_iface or raw_subnet is None or raw_subnet.prefixlen >= 32
        )

        fell_back_iface = False
        if needs_fallback:
            fallback = self._find_physical_lan_fallback(gw_entries, addrs, stats)
            if fallback:
                interface, local, raw_subnet = fallback
                fell_back_iface = True
            elif is_vpn_iface or (raw_subnet is not None and raw_subnet.prefixlen >= 32):
                raw_subnet = None

        subnet = None
        if not apipa and raw_subnet is not None and raw_subnet.prefixlen < 32:
            subnet = self._clamp_subnet(raw_subnet, local_ip=local, action="LAN scan")

        extra_ips = gw_ips if (vpn_active or subnet is None) and gw_ips else []

        return {
            "interface": interface,
            "local_ip": local,
            "mac": mac,
            "subnet": subnet,
            "extra_ips": extra_ips,
            "gw_ips": gw_ips,
            "vpn_active": vpn_active,
            "vpn_status": vpn_status,
            "fell_back_iface": fell_back_iface,
            "apipa": apipa,
        }

    def run(self, parent_geom=None):

        # If the window is already open, bring it to the front
        if _bring_window_to_front(self.lan_win):
            return self.lan_win

        # Create hidden window
        self.lan_win = _create_centered_tool_window(self.parent, "LAN Discovery", parent_geom=parent_geom)
        lanscan_win = self.lan_win

        # Signal any previous window's scan to stop without blocking the new session
        if self.stop_event is not None:
            self.stop_event.set()

        # Per-window isolated session state (queue, logger, buffer, thread, run_id)
        session_id = uuid.uuid4().hex[:8]
        log_level, log_file = _parse_log_cli_args()

        win_log_buffer = _ThreadSafeLogBuffer()
        self.log_buffer = win_log_buffer

        win_logger = setup_logger(
            f"secuditor.lanscan.{session_id}",
            level=log_level,
            logfile=log_file,
            log_buffer=win_log_buffer,
        )
        self.logger = win_logger

        ui_queue: "queue.Queue" = queue.Queue()
        win_text_handler = _QueueTextLogHandler(ui_queue)
        win_logger.addHandler(win_text_handler)
        self.text_handler = win_text_handler

        win_stop_event = threading.Event()
        self.stop_event = win_stop_event
        self.scan_results = []

        win_state = {
            "thread": None,
            "run_stop_event": None,
            "run_id": 0,
            "closed": False,
            "poll_job": None,
        }

        # Status
        status_var = tk.StringVar(value="Ready")

        ttk.Label(
            lanscan_win,
            textvariable=status_var
        ).pack(pady=(10, 5))

        # Spinner
        progress = ttk.Progressbar(
            lanscan_win,
            mode="indeterminate",
            length=300
        )
        progress.pack(pady=5)

        # --- Read-only Log window ---
        txt = _create_scrolled_log_text(lanscan_win)

        win_logger.info("Secuditor Network Discovery Log")

        # Worker
        def scan_worker(run_stop_event, run_id):

            start_time = time.time()

            try:

                target = self._resolve_scan_target()
                interface = target["interface"]
                local = target["local_ip"]
                mac = target["mac"]
                subnet = target["subnet"]
                extra_ips = target["extra_ips"]
                gw_ips = target["gw_ips"]

                win_logger.info("")
                win_logger.info(f"Interface: {interface or 'N/A'}")
                win_logger.info(f"Local MAC: {mac or 'N/A'}")
                win_logger.info(f"Local Adapter IP: {local or 'N/A'}")
                if gw_ips:
                    win_logger.info(f"Default Gateway(s): {', '.join(gw_ips)}")

                if target["vpn_active"]:
                    if target["fell_back_iface"] and subnet is not None:
                        win_logger.warning(
                            "VPN connection detected — switched from tunnel interface to physical LAN adapter and Default Gateway."
                        )
                    elif subnet is not None:
                        win_logger.warning(
                            "VPN connection detected — LAN discovery may be restricted by VPN routing. Scanning available local network and Default Gateway."
                        )
                    elif extra_ips:
                        win_logger.warning(
                            "VPN connection detected — unable to determine physical LAN subnet. Scanning Default Gateway only."
                        )
                    else:
                        win_logger.warning(
                            "VPN connection detected — no scannable local LAN subnet or Default Gateway found."
                        )

                if target["apipa"]:
                    win_logger.warning("APIPA detected (169.254.x.x). No DHCP lease — LAN scan disabled.")
                elif subnet is not None:
                    win_logger.info(f"Detected Subnet: {subnet}")
                elif not target["vpn_active"]:
                    if extra_ips:
                        win_logger.warning(
                            "Unable to determine local subnet mask — scanning Default Gateway only."
                        )
                    elif isinstance(local, str) and "." in local:
                        win_logger.warning("Unable to determine network mask — LAN scan disabled.")
                    else:
                        win_logger.warning("Subnet detection skipped (IPv6 or no IP)")

                if (not subnet and not extra_ips) or run_stop_event.is_set():
                    return

                results = self.test_print(
                    subnet=subnet,
                    local_ip=local,
                    do_port_scan=True,
                    stop_event=run_stop_event,
                    extra_ips=extra_ips,
                    logger=win_logger,
                )

                if self.lan_win is lanscan_win:
                    self.scan_results = results

            finally:

                elapsed = time.time() - start_time

                win_logger.info("")
                win_logger.info(f"LAN scan finished in {elapsed:.1f}s")

                ui_queue.put(("done", (run_id, run_stop_event.is_set())))

        # Buttons
        def start_scan():

            if win_state["thread"] and win_state["thread"].is_alive():
                return

            txt.config(state="normal")
            txt.delete("1.0", "end")
            txt.config(state="disabled")

            win_log_buffer.clear()

            run_stop_event = threading.Event()
            win_state["run_stop_event"] = run_stop_event
            win_state["run_id"] += 1
            current_run_id = win_state["run_id"]
            self.stop_event = run_stop_event

            btn_start["state"] = "disabled"
            btn_stop["state"] = "normal"

            status_var.set("Scanning...")

            progress.start(15)

            t = threading.Thread(
                target=scan_worker,
                args=(run_stop_event, current_run_id),
                daemon=True
            )
            win_state["thread"] = t
            self.scan_thread = t

            t.start()

        def stop_scan():

            if win_state["run_stop_event"] is not None:
                win_state["run_stop_event"].set()

            try:
                if lanscan_win.winfo_exists():
                    status_var.set("Stopping...")
                    btn_stop["state"] = "disabled"

            except tk.TclError:
                pass

            win_logger.warning("Stop requested...")

        def export_logs():
            _export_log_buffer(
                lanscan_win,
                "Export Network Discovery Log",
                win_log_buffer,
                handle_errors=True
            )

        # Buttons Frame
        buttons = ttk.Frame(lanscan_win)
        buttons.pack(pady=10)

        btn_start = ttk.Button(
            buttons,
            text="Start Scan",
            command=start_scan
        )
        btn_start.grid(row=0, column=0, padx=5)

        btn_stop = ttk.Button(
            buttons,
            text="Stop",
            command=stop_scan,
            state="disabled"
        )
        btn_stop.grid(row=0, column=1, padx=5)

        btn_export = ttk.Button(
            buttons,
            text="Export Logs",
            command=export_logs
        )
        btn_export.grid(row=0, column=2, padx=5)

        # Main-thread UI queue poller (drains logs FIFO before applying done state)
        def drain_ui_queue():
            if win_state["closed"]:
                return
            try:
                if not lanscan_win.winfo_exists():
                    win_state["closed"] = True
                    return

                log_batch = []
                done_payload = None
                while True:
                    try:
                        kind, payload = ui_queue.get_nowait()
                    except queue.Empty:
                        break
                    if kind == "log":
                        log_batch.append(payload)
                    elif kind == "done":
                        done_payload = payload

                if log_batch:
                    txt.config(state="normal")
                    txt.insert("end", "\n".join(log_batch) + "\n")
                    txt.see("end")
                    txt.config(state="disabled")

                if done_payload is not None:
                    finished_run_id, was_stopped = done_payload
                    if finished_run_id == win_state["run_id"]:
                        progress.stop()
                        status_var.set("Stopped" if was_stopped else "Finished")
                        btn_start["state"] = "normal"
                        btn_stop["state"] = "disabled"

                win_state["poll_job"] = lanscan_win.after(40, drain_ui_queue)
            except (tk.TclError, RuntimeError):
                win_state["closed"] = True

        def on_close():
            if win_state["closed"]:
                return
            win_state["closed"] = True

            if win_state["poll_job"] is not None:
                try:
                    lanscan_win.after_cancel(win_state["poll_job"])
                except (tk.TclError, RuntimeError):
                    pass
                win_state["poll_job"] = None

            win_stop_event.set()
            if win_state["run_stop_event"] is not None:
                win_state["run_stop_event"].set()

            _close_logger_handlers(win_logger)
            if self.text_handler is win_text_handler:
                self.text_handler = None

            if self.lan_win is lanscan_win:
                self.lan_win = None

            try:
                if lanscan_win.winfo_exists():
                    lanscan_win.destroy()
            except (tk.TclError, RuntimeError):
                pass

        lanscan_win.protocol("WM_DELETE_WINDOW", on_close)
        lanscan_win.bind("<Destroy>", lambda e: on_close() if e.widget is lanscan_win else None)

        win_state["poll_job"] = lanscan_win.after(40, drain_ui_queue)

        # Show the window ONLY after the entire UI has been created.
        lanscan_win.deiconify()
        lanscan_win.lift()
        lanscan_win.focus_force()

        return lanscan_win

# ===== CLASS NAT Status =====
class NetStatus:
    def __init__(self):
        self.internet_status = None

    # --- Check Internet Connection ---
    def check_internet_connection(self, timeout=3):
        """
        Check if the system has an active internet connection.
        """
        result = {
            "Connected": False,
            "Test Host": "https://www.google.com",
            "External IP": "Unavailable",
            "Error": None
        }

        try:
            # --- Fast check using HEAD request ---
            response = requests.head(result["Test Host"], timeout=timeout)
            if response.status_code < 400:
                result["Connected"] = True
        except Exception as e:
            result["Error"] = f"No internet connectivity: {e}"
            result["Connected"] = False

        # --- Attempt to get external IP if connected ---
        if result["Connected"]:
            try:
                response = requests.get("https://api.ipify.org", timeout=timeout)
                if response.status_code == 200:
                    result["External IP"] = response.text.strip()
            except Exception as e:
                result["External IP"] = "Unavailable"
                result["Error"] = f"External IP check failed: {e}"

        return result

    def check_and_store_internet(self):
        status = self.check_internet_connection()
        self.internet_status = status["Connected"]
        print(f"Internet connected: {self.internet_status}")

    # --- Get DNS Server ---
    def get_dns_servers(self):
        try:
            output = _run_check_output(["ipconfig", "/all"], shell=False)

            dns_servers = []
            seen = set()
            in_dns_section = False

            def _add_dns(candidate: str):
                addr_clean = candidate.strip()
                if not addr_clean:
                    return
                try:
                    ip_obj = ipaddress.IPv4Address(addr_clean)
                except ValueError:
                    return
                ipv4_str = str(ip_obj)
                if ipv4_str not in seen:
                    seen.add(ipv4_str)
                    dns_servers.append(ipv4_str)

            for line in output.splitlines():
                stripped = line.strip()
                if "DNS Servers" in line and ":" in line:
                    in_dns_section = True
                    _add_dns(line.split(":", 1)[1])
                elif in_dns_section:
                    if not stripped or ". :" in line or ".." in line or (
                        ":" in stripped and not stripped.split("%", 1)[0].replace(":", "").isalnum()
                    ):
                        # Next field label reached unless line is a valid continuation IP
                        if not stripped or ". :" in line or ".." in line:
                            in_dns_section = False
                            continue
                        try:
                            ipaddress.ip_address(stripped.split("%", 1)[0])
                            _add_dns(stripped)
                        except ValueError:
                            in_dns_section = False
                    else:
                        try:
                            ipaddress.ip_address(stripped.split("%", 1)[0])
                            _add_dns(stripped)
                        except ValueError:
                            in_dns_section = False

            return ", ".join(dns_servers) if dns_servers else "Unavailable"

        except Exception:
            return "Unavailable"

    # --- Get ISP and region from IP ---
    def get_ip_info(self, ip):
        """
        Returns ISP and region for the given IP.
        - Detects private IPs
        - Uses ipinfo.io for public IPs
        - Shortens and cleans ISP names
        - Truncates region/district to 40 characters
        """
        try:
            # Handle private/local IPs
            if ipaddress.ip_address(ip).is_private:
                return "Private IP", "Local Network"

            # Public IP: query ipinfo.io
            response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
            data = response.json()
            isp_full = data.get("org", "Unknown ISP")
            region_full = ", ".join(filter(None, [data.get("region"), data.get("country")])) or "Unknown Region"

            # Shorten & clean ISP
            isp_short = self.shorten_isp(isp_full)

            # Truncate region if longer than 40 chars
            region_short = self.truncate_text(region_full, 40)

            return isp_short, region_short

        except Exception:
            return "Unknown ISP", "Unknown Region"

    @staticmethod
    def shorten_isp(isp: str) -> str:
        """
        Shorten ISP names by:
        - Removing ASN prefix (ASxxxx)
        - Removing common suffixes like Inc, LLC, Ltd, Co
        - Truncating to 20 characters
        """
        if not isp or isp == "Unknown ISP":
            return "Unknown ISP"

        # Remove ASN prefix like 'AS15169 '
        parts = isp.split()
        if parts[0].upper().startswith("AS") and parts[0][2:].isdigit():
            parts = parts[1:]  # remove ASN

        # Join parts and remove common suffixes
        name = " ".join(parts)
        # Regex to remove Inc, LLC, Ltd, Co, Corporation, Limited (case-insensitive)
        name = re.sub(r'\b(Inc|LLC|Ltd|Co|Corporation|Limited)\b\.?', '', name, flags=re.IGNORECASE)
        # Remove extra spaces
        name = " ".join(name.split())

        # Truncate if too long
        if len(name) > 40:
            name = name[:40] + "..."

        return name

    @staticmethod
    def truncate_text(text: str, max_len: int) -> str:
        """
        Truncate text to max_len characters, adding '...' if truncated.
        """
        if len(text) <= max_len:
            return text
        return text[:max_len] + "..."

    # --- VPN Client check ---
    def get_vpn_connection(
        self,
        keywords=VPN_INTERFACE_KEYWORDS,
        not_found_label="Not Installed",
    ) -> str:
        try:
            vpn_adapters = []
            vpn_connected = False

            for name, addrs in psutil.net_if_addrs().items():
                # Detect common VPN interface names
                if _is_vpn_interface_name(name, keywords):
                    vpn_adapters.append(name)

                    for addr in addrs:
                        if addr.family == socket.AF_INET and not addr.address.startswith("169.254"):
                            vpn_connected = True

            if not vpn_adapters:
                return not_found_label
            elif vpn_connected:
                return "Enabled (connected)"
            else:
                return "Enabled (no connection)"

        except Exception:
            return "Unknown"

    # --- Show network status popup ---
    def show_network_status(self, parent):
        print("NAT Status function started")
        show_net = tk.Toplevel(parent)
        show_net.withdraw()

        set_window_icon(show_net)

        show_net.title("NAT Status")
        show_net.resizable(False, False)

        def _center_window(win_w, win_h):
            parent.update_idletasks()
            main_x = parent.winfo_x()
            main_y = parent.winfo_y()
            main_w = parent.winfo_width()
            main_h = parent.winfo_height()
            pos_x = main_x + (main_w - win_w) // 2
            pos_y = main_y + (main_h - win_h) // 2
            show_net.geometry(f"{win_w}x{win_h}+{pos_x}+{pos_y}")

        _center_window(420, 150)

        loading_label = tk.Label(
            show_net,
            text="🌐 Checking network status...",
            font=("Segoe UI", 10)
        )
        loading_label.pack(pady=35)

        def _render_result(net_status, dns, isp, region, conn_type):
            try:
                if not show_net.winfo_exists():
                    return
            except tk.TclError:
                return

            for child in show_net.winfo_children():
                child.destroy()

            if net_status["Connected"]:
                ip = net_status["External IP"]
                _center_window(420, 270)
                print("NAT Status function completed")

                tk.Label(
                    show_net,
                    text=f"🌐 Internet Connection: {conn_type}",
                    font=("Segoe UI", 10)
                ).pack(pady=(18, 8))

                ttk.Separator(
                    show_net,
                    orient="horizontal"
                ).pack(fill="x", padx=25)

                tk.Label(
                    show_net,
                    text=f"Public IP: {ip}",
                    font=("Segoe UI", 10)
                ).pack(pady=6)

                ttk.Separator(
                    show_net,
                    orient="horizontal"
                ).pack(fill="x", padx=25)

                tk.Label(
                    show_net,
                    text=f"DNS Servers: {dns}",
                    font=("Segoe UI", 10),
                    wraplength=360
                ).pack(pady=6)

                ttk.Separator(
                    show_net,
                    orient="horizontal"
                ).pack(fill="x", padx=25)

                tk.Label(
                    show_net,
                    text=f"ISP: {isp}",
                    font=("Segoe UI", 10)
                ).pack(pady=6)

                ttk.Separator(
                    show_net,
                    orient="horizontal"
                ).pack(fill="x", padx=25)

                tk.Label(
                    show_net,
                    text=f"Region: {region}",
                    font=("Segoe UI", 10)
                ).pack(pady=6)

            else:
                _center_window(420, 180)
                print("NAT Status function failed. No internet connection")

                tk.Label(
                    show_net,
                    text="⚠️ No internet connection detected.\n"
                         "Some checks may not work.",
                    font=("Segoe UI", 10),
                    justify="center",
                    wraplength=380
                ).pack(pady=(24, 16), padx=12)

            # --- OK button ---
            tk.Button(
                show_net,
                text="OK",
                width=10,
                command=show_net.destroy
            ).pack(pady=(8, 12))

        result_queue: "queue.Queue" = queue.Queue()
        net_state = {"closed": False, "poll_job": None}

        def on_close():
            if net_state["closed"]:
                return
            net_state["closed"] = True
            if net_state["poll_job"] is not None:
                try:
                    show_net.after_cancel(net_state["poll_job"])
                except (tk.TclError, RuntimeError):
                    pass
                net_state["poll_job"] = None
            try:
                if show_net.winfo_exists():
                    show_net.destroy()
            except (tk.TclError, RuntimeError):
                pass

        show_net.protocol("WM_DELETE_WINDOW", on_close)
        show_net.bind("<Destroy>", lambda e: on_close() if e.widget is show_net else None, add="+")
        attach_native_modal(parent, show_net)

        def _poll_result():
            if net_state["closed"]:
                return
            try:
                if not show_net.winfo_exists():
                    net_state["closed"] = True
                    return
                try:
                    payload = result_queue.get_nowait()
                except queue.Empty:
                    net_state["poll_job"] = show_net.after(40, _poll_result)
                    return
                net_state["poll_job"] = None
                _render_result(*payload)
            except (tk.TclError, RuntimeError):
                net_state["closed"] = True

        def _worker():
            net_status = self.check_internet_connection()
            dns = self.get_dns_servers()
            isp = "Unknown ISP"
            region = "Unknown Region"
            conn_type = "Direct"

            if net_status["Connected"]:
                ip = net_status["External IP"]
                isp, region = self.get_ip_info(ip)
                vpn_status = self.get_vpn_connection()
                conn_type = "VPN" if vpn_status == "Enabled (connected)" else "Direct"

            result_queue.put((net_status, dns, isp, region, conn_type))

        net_state["poll_job"] = show_net.after(40, _poll_result)
        threading.Thread(target=_worker, daemon=True).start()

# ===== CLASS Speedtest =====
class SpeedTest:
    def __init__(self, parent):
        self.parent = parent

    # --- Main UI entry ---
    def show_download_speed(self, repeats=REPEATS):
        """Popup window that shows download speed with animated clock."""

        print("Speed Test function started")
        show_speed = tk.Toplevel(self.parent)
        show_speed.withdraw()

        set_window_icon(show_speed)

        show_speed.title("Speed Test")
        show_speed.resizable(False, False)
        
        # --- center window ---
        win_w, win_h = 400, 180

        self.parent.update_idletasks()
        main_x = self.parent.winfo_x()
        main_y = self.parent.winfo_y()
        main_w = self.parent.winfo_width()
        main_h = self.parent.winfo_height()

        pos_x = main_x + (main_w - win_w) // 2
        pos_y = main_y + (main_h - win_h) // 2

        show_speed.geometry(f"{win_w}x{win_h}+{pos_x}+{pos_y}")

        # --- Measuring status ---
        label = tk.Label(
            show_speed,
            text="🌐 Measuring Download Speed...",
            font=("Segoe UI", 10)
        )
        label.pack(pady=(25, 8))

        # --- Separator ---
        ttk.Separator(
            show_speed,
            orient="horizontal"
        ).pack(fill="x", padx=25, pady=(0, 8))

        # --- Test URL ---
        url_label = tk.Label(
            show_speed,
            text="https://test.secuditor.com",
            font=("Segoe UI", 10)
        )
        url_label.pack(pady=(0, 5))

        # --- Duration ---
        timer_label = tk.Label(
            show_speed,
            text="Duration: 00:00",
            font=("Segoe UI", 10)
        )
        timer_label.pack(pady=(0, 5))

        # --- timer ---
        start_time = time.time()
        show_speed._timer_job = None

        def update_timer():
            if not show_speed.winfo_exists():
                return

            elapsed = int(time.time() - start_time)
            minutes, seconds = divmod(elapsed, 60)

            timer_label.config(
                text=f"Duration: {minutes:02d}:{seconds:02d}"
            )

            show_speed._timer_job = show_speed.after(300, update_timer)

        update_timer()

        cancel_event = threading.Event()
        resp_lock = threading.Lock()
        active_responses = []

        def _close_active_responses():
            with resp_lock:
                responses = list(active_responses)
                active_responses.clear()
            for r in responses:
                try:
                    r.close()
                except Exception:
                    pass

        show_speed._poll_job = None
        speed_closed = [False]
        result_queue: "queue.Queue" = queue.Queue()

        def on_close():
            if speed_closed[0]:
                return
            speed_closed[0] = True
            cancel_event.set()
            _close_active_responses()
            if show_speed._timer_job:
                try:
                    show_speed.after_cancel(show_speed._timer_job)
                except (tk.TclError, RuntimeError):
                    pass
                show_speed._timer_job = None
            if show_speed._poll_job:
                try:
                    show_speed.after_cancel(show_speed._poll_job)
                except (tk.TclError, RuntimeError):
                    pass
                show_speed._poll_job = None
            try:
                if show_speed.winfo_exists():
                    show_speed.destroy()
            except (tk.TclError, RuntimeError):
                pass

        show_speed.protocol("WM_DELETE_WINDOW", on_close)
        show_speed.bind("<Destroy>", lambda e: on_close() if e.widget is show_speed else None, add="+")

        # --- download worker ---
        def _download_thread(url, lock, counter, round_stop):
            r = None
            try:
                r = requests.get(url, stream=True, timeout=15)
                r.raise_for_status()
                with resp_lock:
                    if round_stop.is_set() or cancel_event.is_set():
                        r.close()
                        return
                    active_responses.append(r)

                for chunk in r.iter_content(65536):
                    if round_stop.is_set() or cancel_event.is_set():
                        break
                    if chunk:
                        with lock:
                            counter[0] += len(chunk)
            except Exception:
                pass
            finally:
                if r is not None:
                    with resp_lock:
                        if r in active_responses:
                            active_responses.remove(r)
                    try:
                        r.close()
                    except Exception:
                        pass

        # --- measurement engine ---
        def _measure_download_speed(
            url=TEST_FILE_URL,
            threads=THREADS,
            repeats=repeats,
            max_time=3
        ):
            speeds = []

            for _ in range(repeats):
                if cancel_event.is_set():
                    break

                counter = [0]
                lock = threading.Lock()
                round_stop = threading.Event()
                thread_list = []

                start = time.time()

                for _ in range(threads):
                    t = threading.Thread(
                        target=_download_thread,
                        args=(url, lock, counter, round_stop),
                        daemon=True,
                    )
                    t.start()
                    thread_list.append(t)

                for t in thread_list:
                    elapsed = time.time() - start
                    remaining = max_time - elapsed
                    if remaining > 0 and not cancel_event.is_set():
                        t.join(remaining)

                elapsed_total = time.time() - start

                round_stop.set()
                _close_active_responses()

                for t in thread_list:
                    t.join(timeout=0.2)

                if elapsed_total > 0 and counter[0] > 0 and not cancel_event.is_set():
                    speeds.append(
                        (counter[0] * 8) / (elapsed_total * 1_000_000)
                    )

            return round(sum(speeds) / len(speeds), 2) if speeds else None

        # --- update UI safely ---
        def update_result(avg_mbps):
            if show_speed._timer_job:
                try:
                    show_speed.after_cancel(show_speed._timer_job)
                except tk.TclError:
                    pass
                show_speed._timer_job = None

            try:
                if not show_speed.winfo_exists():
                    return
            except tk.TclError:
                return

            timer_label.pack_forget()

            if avg_mbps is None:

                label.config(
                    text="⚠️ No internet connection detected."
                )

                url_label.config(
                    text="Cannot measure Download Speed."
                )

                print("Speed test function failed. No internet connection")

            else:

                label.config(
                    text=f"🌐 Average Download Speed: {avg_mbps} Mbps"
                )

                url_label.config(
                    text="https://test.secuditor.com"
                )

                print("Speed test function completed")

            tk.Button(
                show_speed,
                text="OK",
                width=10,
                command=on_close
            ).pack(pady=(10, 20))

        # --- main-thread poller & background thread ---
        def _poll_speed_result():
            if speed_closed[0] or cancel_event.is_set():
                return
            try:
                if not show_speed.winfo_exists():
                    speed_closed[0] = True
                    return
                try:
                    avg = result_queue.get_nowait()
                except queue.Empty:
                    show_speed._poll_job = show_speed.after(40, _poll_speed_result)
                    return
                show_speed._poll_job = None
                update_result(avg)
            except (tk.TclError, RuntimeError):
                speed_closed[0] = True

        def run_speed_test():
            avg = _measure_download_speed()
            if cancel_event.is_set():
                return
            result_queue.put(avg)

        show_speed._poll_job = show_speed.after(40, _poll_speed_result)
        threading.Thread(target=run_speed_test, daemon=True).start()

        # Show only after the window is completely built
        attach_native_modal(self.parent, show_speed)
