# Secuditor Lite 2.4.0 – Technical Overview

This document describes the internal architecture, execution flow, caching/threading model, scoring engine, external network dependencies, and security controls of **Secuditor Lite** (`src/`).

---

## 1. Repository & Module Architecture

All runtime code lives in `src/`:

| File | Primary Responsibility |
| :--- | :--- |
| `src/secuditor_lite_main.py` | Tkinter GUI (`OpSecGUI`), layout & search (`Ctrl+F`), welcome live telemetry timers, background worker orchestration, `_HybridSSLAdapter`, score calculation (`calculate_score_with_breakdown`), and TXT/log export. |
| `src/secuditor_modules.py` | Core Windows diagnostic and audit classes: `SystemSettings`, `HardwareReport`, `InstalledApps`, `NetworkSettings`, `SharedFolders`, `GatewayDiscovery`, `SecuritySettings`, `RemoteAccessSettings`, `DomainSettings`, `PasswordPolicy`, `CredentialIntegrity`, `WindowsEvents`, `WindowsUpdates`, `check_ntlm_policy()`, and OS build lookups. |
| `src/secuditor_scanners.py` | Threat and interception scanners (`SSLInspection`, `SuspiciousProxy`, `SensitivePaths`, `SuspiciousProcesses`), driven by `src/data/sec.json`. |
| `src/secuditor_utilities.py` | Standalone toolbar diagnostic modules (`TrafficFlow`, `LanScanner`, `NetStatus`, `SpeedTest`), safe subprocess wrappers (`_system_exe`, `_safe_subproc_env`, `_run_check_output`), OUI loader bridge, and resource/icon helpers. |
| `src/secuditor_loader.py` | OUI MAC-vendor cache manager (`OuiCache.db` in SQLite), remote metadata check, and SHA-256 verification for `oui.csv`. |
| `src/data/sec.json` | JSON rule/config store containing `suspicious_cmd_patterns`, `suspicious_parents`, `suspicious_remote_ports`, `suspicious_executable_locations`, `system_path_prefixes`, `applications_path_prefixes`, `legit_network_applications`, `known_system_processes`, `special_system_pid`, `lolbins`, `sensitive_path_templates`, `default_copy_search`, `sensitive_patterns`, `known_benign_files`, `legit_issuers`, and `public_cas`. |
| `src/icons/` | 35×35 toolbar PNGs (`run`, `traf`, `lan`, `network`, `speed`, `menu`, `home`, `about`, `txt`), 16×16 category tree icons, and `secuditor_logo.png`. |

---

## 2. Execution Flow & Threading Model

### Application Startup (`OpSecGUI.__init__`)
1. Hardens DLL search order on Windows via `ctypes.windll.kernel32.SetDllDirectoryW("")` without breaking PyInstaller `_MEIPASS`.
2. Loads local `OuiCache.db` immediately and launches a daemon thread (`OUI-Update`) to check for OUI CSV updates (`secuditor_loader.update_oui_cache()`).
3. Checks reachability to `https://secuditor.com`, initializes real-time logging under `%LOCALAPPDATA%\Secuditor Lite\Logs`, and triggers a non-blocking internet status check (`check_and_store_internet`).
4. Fetches `https://updates.secuditor.com/version.json` to compare against `CURRENT_VERSION = "2.4.0"`.
5. Seeds `psutil.cpu_percent(interval=None)` and triggers `_start_welcome_probe()`.

### Welcome Screen Live Telemetry
When the welcome view is active (`host_pulse` tag present):
- **2-second UI timer (`_tick_host_pulse`):** Calls `_format_host_pulse()` on the main thread using `psutil` to refresh `CPU Usage`, `Memory Usage`, and `Disk Usage`, applying `_apply_host_pulse_highlights()` (`Active` → `darkgreen`, `Inactive` → `red`, `>= 90.0%` → `darkred`, `Untrusted / MITM` → `#A855F7`). OS edition (`System Version`) is resolved once via `SystemSettings()._get_windows_edition()` and cached in `self._welcome_os_version`.
- **15-second / 60-second background probe (`_on_welcome_probe_timer` → `Welcome-SecurityProbe` daemon thread):**
  - Pauses automatically whenever `run_all_clicked` or `single_check` is active, and prevents overlap via `_welcome_probe_busy`.
  - Runs `SecuritySettings().get_quick_endpoint_status()` every **15 seconds** (in-process WMI COM `winmgmts:\\.\root\SecurityCenter2` with PowerShell/registry fallback + `winreg` Windows Firewall profile state).
  - Runs `SSLInspection().check_ssl_inspection("www.google.com", 443, use_cache=False)` every **60 seconds** (`_WELCOME_SSL_INTERVAL_SEC = 60.0`), updating the inline ASCII flow diagram without populating `_ssl_inspection_cache`.
- During a full **Security Audit** run, `lock_main_widgets()` keeps the welcome banner + 2s resource bars visible read-only while the background AV/FW/SSL probe loop stays paused.

### Single Check vs. Full Audit (`MODULE_TIMEOUT = 180s`)
- **Single Check (`run_single_check`):** Dispatches the selected module in a daemon worker thread, increments `_current_single_run_id` / `stop_event` on cancellation or navigation away so stale callbacks are discarded, and caches output in `self.single_node_cache`.
- **Full Security Audit (`run_all_clicked`):**
  1. Sets `secuditor_modules.set_scan_mode(run_all=True, single=False)` and clears both GUI caches and all module-level caches (`_clear_all_audit_caches()`).
  2. Executes the 18 registered modules in `self.checks` sequentially on a worker thread, enforcing a **180-second** join timeout per module (`MODULE_TIMEOUT`) and tracking timed-out/failed keys in `failed_checks`.
  3. Runs `calculate_score_with_breakdown(assembled)` on a separate calculation thread (`CALCULATION_TIMEOUT`), excluding any failed/timed-out module via `_failed_checks` (`N/A` instead of stale/partial failure penalties).
  4. Resets `run_all_clicked`, clears module audit caches cleanly in `finally:`, expands the tree, and opens the hostname **Summary Report** with clickable jump links.

---

## 3. Caching & State Isolation

- `secuditor_modules.py` maintains module-level caches (`_security_settings_cache`, `_remote_access_cache`, `_domain_settings_cache`, `_password_policy_cache`, `_windows_version_cache`, `_credential_guard_cache`, `_lsass_protection_cache`, `_ntlm_policy_cache`, `_audit_winrm_cache`, `_gateway_ip_cache`, `_gateway_mac_cache`, `_mac_vendor_cache`, `_management_ports_cache`, `_nat_cache`).
- `secuditor_scanners.py` maintains `_ssl_inspection_cache`, `_proxy_cache`, and `SuspiciousProcesses._cache`.
- **Bypass & Cleanup:**
  - Setting `run_all_clicked=True` or `single_check=True` forces fresh execution rather than reading module caches; after audit assembly finishes, `run_all_clicked` resets to `False` so `calculate_score_with_breakdown()` reuses data just collected during that run, and `_clear_all_audit_caches()` clears all caches once scoring finishes and at the start of the next audit.
  - Welcome-screen SSL checks pass `use_cache=False`, and `get_quick_endpoint_status()` reads live state without touching `_security_settings_cache`.

---

## 4. Security Score Engine (`calculate_score_with_breakdown`)

- Starts from a baseline of **`100`** and clamps the final score to **`0–100`** across **23 scored elements** (timed-out or failed source checks default to `N/A` / `0` points):
  - **Heavy-impact (`Hvy`) checks:** `Endpoint Protection` (`+10` / `-25`), `Password Policy` (`+10` / `0` / `-40`), `SMBv1 Protocol` (`0` / `-25`), `SMBv2 Protocol` (`0` / `-15`), `NTLM Configuration` (`+10` / `0` / `-20`).
  - **Medium-impact (`Med`) checks:** `Host-based Firewall` (`+10` / `0` / `-10`), `Network Gateway` (`+5` / `-15`), `Auto Screen Lock` (`+10` / `+5` / `-10`), `Elevation Prompt` (UAC, `+5` / `-15`), `Disk Encryption` (BitLocker, `+5` / `-5`), `LAPS Protection` (`+5` / `-15`), `Credential Guard` (`+5` / `-10`), `Domain Settings` (`0`), `PowerShell Remoting` (`0` / `-15`), `FTP Service` (`0` / `-10`), `DCOM Service` (`0` / `-10`), `WinRM Service` (`0` / `-10`), `Remote Desktop` (`0` / `-10`), `Proxy Configuration` (`+5` legit / `-15` suspicious / `-5` unknown), `SSL/TLS Interception` (`+10` legit / `+5` clean / `-15` suspicious / `-5` unknown), `Suspicious Activity` (`+5` / `-15`).
  - **Low-impact (`Low`) checks:** `Memory Integrity` (HVCI, `+5` / `-5`), `Boot Security Layer` (Secure Boot, `+5` / `-5`), `System Restore` (`+5` / `-5`), `Bluetooth Component` (`+5` / `0` / `-5`), `RPC Print Spooler` (`0` / `-10`).

---

## 5. Key Diagnostic Mechanisms

### SSL/TLS Interception (`SSLInspection.check_ssl_inspection`)
- **Stage 1 (OS Store):** Performs a verified TLS handshake (`CERT_REQUIRED`, `check_hostname=True`) against `www.google.com:443` using the Windows root trust store (`ssl.create_default_context()`). On `SSLCertVerificationError`, falls back to an unverified `CERT_NONE` socket solely to read the presented leaf certificate (`cryptography.x509`) for reporting.
- **Stage 2 (WebPKI / `certifi`):** If OS-trusted, performs a second handshake verified against `certifi.where()`. An OS-trusted cert that fails public WebPKI validation indicates local root injection (enterprise/AV SSL inspection).
- **Classification:** Validates SANs/CN with RFC 6125 label-safe wildcard matching, RDN token-boundary matching (`O`, `CN`, `OU`) against `public_cas` and `legit_issuers`, signature hash (`md5`/`sha1`), key strength (`RSA`/`ECC`/`Ed25519`/`Ed448`), and lifetime (`<= 825` days) to classify into `Not Detected`, `Likely Legitimate`, `Suspicious`, or `Unknown`, rendered alongside a wrapped ASCII flow diagram.

### Proxy & Suspicious Process Scanners (`secuditor_scanners.py`)
- **`SuspiciousProxy`:** Inspects WinINet (`Internet Settings`), WinHTTP (`netsh winhttp show proxy`), `Proxy*` environment variables, `netsh interface portproxy`, and maps local proxy ports back to owning PIDs/processes to flag SOCKS/Tor ports (`9050`, `9150`) and local MITM/tunnel binaries (`chisel`, `ngrok`, `mitmdump`, `fiddler`, `burpsuite`, etc.).
- **`SuspiciousProcesses`:** Scores active processes (`RISK_THRESHOLD = 40`) using system-path vs impersonation verification, `Get-AuthenticodeSignature` validation, parent-child rules, token-boundary regex command-line matching, `VirtualQueryEx` private executable memory indicators (`PAGE_EXECUTE_*`), unverified DLL/module anomaly checks, 1 MB byte entropy (`>= 7.5`), small unverified binaries (`< 50 KB`), scheduled tasks / Run-key persistence, network direction/multi-port/multi-peer/clipboard correlation, and LOLBin checks.

### Windows OS & Compatibility Details (`secuditor_modules.py`)
- **Windows 10 / 11 / Server detection:** Reads `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion` (`Build`, `UBR`, `EditionID`, `DisplayVersion`), uses `build >= 22000` for Windows 11 identification (covering upgraded systems whose registry `ProductName` remains `"Windows 10"`), supports **Windows 11 24H2 / 25H2 / 26H1 (`28000`) / 26H2 (`26300`)** and **Windows Server 2025**, and selects latest builds within the host's release branch ordered by `RELEASE_DATES` rather than raw integer build comparisons.
- **Win11 Hardening & Privacy Support:** Reads `TypeOfAdminApprovalMode` for **Administrator Protection**, checks `RestrictSendingNTLMTraffic`, `RestrictReceivingNTLMTraffic`, and `BlockNtlmv1SSO` in NTLM evaluation, uses `RPSessionInterval`/`DisableSR` for System Restore, and isolates `netsh wlan show interfaces` from `Get-NetAdapter` so Location Privacy blocks (`Error 5`) do not erase Wi-Fi adapter inventory.
- **Subprocess Safety:** Helper commands resolve system binaries from `%SystemRoot%\System32` (`_system_exe`), set `NoDefaultCurrentDirectoryInExePath=1` (`_safe_subproc_env`), and run with `shell=False` + `CREATE_NO_WINDOW` / `SW_HIDE`.

---

## 6. External Network Calls & Local Storage

### External Endpoints Contacted
- `https://secuditor.com` — startup reachability check (`HEAD`/`GET`) and download links (validated by `_is_safe_download_url` allowlist: `secuditor.com`, `www.secuditor.com`, `updates.secuditor.com`, and `github.com/secuditor/...`).
- `https://updates.secuditor.com/version.json` — application version check.
- `https://updates.secuditor.com/oui-version.json` & `https://updates.secuditor.com/oui.csv` — OUI CSV metadata and SHA-256-verified database download.
- `https://test.secuditor.com/speedtest.png` — 4-thread HTTP Range download throughput test (`SpeedTest`).
- `https://api.ipify.org` — public IP discovery (`NetStatus`, `GatewayDiscovery`).
- `https://ipinfo.io/{ip}/json` — ISP and region lookup for public IPs (`NetStatus`).
- `https://www.google.com` / `www.google.com:443` — HTTP connectivity test (`NetStatus`) and TLS handshake inspection (`SSLInspection`).
- `https://learn.microsoft.com/en-us/windows/release-health/...` — latest OS build baselines (`WindowsUpdates`).

*(HTTPS verification in `secuditor_lite_main.py` uses `_HybridSSLAdapter`, combining the Windows OS certificate store with `certifi`.)*

### Local File Storage
- **Logs:** `%LOCALAPPDATA%\Secuditor Lite\Logs\secuditor_<timestamp>.log` (auto-created per session; manual exports via **Export Report** / **Export Logs** / **Export Node** go to user-selected `.txt` files).
- **OUI Database Cache:** `%LOCALAPPDATA%\Secuditor Lite\Cache\OuiCache.db` (SQLite tables `oui_vendor` and `oui_metadata`).

---

## 7. Runtime Dependencies

- **Standard Library:** `tkinter`, `ttk`, `scrolledtext`, `sqlite3`, `ssl`, `socket`, `winreg`, `ctypes`, `subprocess`, `ipaddress`, `hashlib`, `concurrent.futures`, `threading`, `json`, `csv`, `re`.
- **Third-Party Packages:** `requests`, `urllib3`, `certifi`, `psutil`, `cryptography`, `pywin32` (`pythoncom`, `win32com.client`, `win32net`, `win32security`, `win32gui`, `win32process`, `win32clipboard`, `ntsecuritycon`), `WMI`.
