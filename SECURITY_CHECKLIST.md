# Secuditor Lite 2.4.1 – Security Checks & Diagnostics

This file lists the structured and comprehensive security audit elements that **Secuditor Lite** checks on Windows systems, helping identify misconfigurations, vulnerabilities, and potential risks across **endpoint, network, and operational security layers**.

For complete and accurate results, the tool should be run with **administrator privileges**.

---

### 🏠 Welcome / Home Screen Live Telemetry
- Live Endpoint Security summary (Active/Inactive Antivirus & Host-based Firewall status)
- Operating system label with live CPU Usage, Memory Usage, and Disk Usage bars (highlighting >= 90.0% usage)
- Live Password Policy sign-in flow diagram (Strong, Moderate, Hello/PIN, Weak, or Unverified Policy — non-admin)

---

### 🖥️ System Overview
- Hostname, Windows OS/edition, and firmware detection (UEFI / Legacy BIOS)
- System architecture (x86/x64/ARM) and processor identification
- CPU core count, thread count, and total memory (RAM) capacity, type, and speed
- GPU manufacturer and model identification
- Disk structure overview including partitions, and storage usage
- Installed applications inventory

---

### 🔌 Hardware Analysis
- Detection of connected hardware components and devices
- USB devices enumeration including storage, input, and peripheral
- Biometric hardware detection (fingerprint readers, cameras)
- Network interfaces enumeration including physical and virtual adapters

---

### 🌐 Network Configuration
- Local IP address enumeration (IPv4 and IPv6)
- Default gateway, Subnet mask, DHCP and DNS server detection
- Network interface status (Wi-Fi, Ethernet, virtual adapters)

---

### 📂 Shared Folders & Permissions
- Detection of shared folders and network shares
- Analysis of access permissions (read / write / full control)
- Identification of overly permissive or exposed shares
- Mapping of shared resources across the system

---

### 🛰️ Gateway Discovery
- Default gateway IPv4/IPv6 discovery, ICMP ping check, network CIDR, and interface MTU
- Gateway MAC resolution, OUI vendor lookup, and HTTP/WebGUI fingerprint classification
- Exposed gateway management port scan (FTP, SSH, Telnet, HTTP, HTTPS, SMB, WinBox, alt-HTTP, etc.)
- Gateway proxy indicator, NAT check (api.ipify.org), VPN interface detection, and public IP identification

---

### 🔍 LAN Scanning and Traffic Flow
- IPv4-based incremental local network device discovery
- MAC address vendor identification using a local OUI database
- Detection of common open ports and exposed network services
- Network traffic flow analysis by process, port, protocol, and direction
- Identification of active connections and potentially unusual network activity

---

### 🛡️ Endpoint Security Settings
- Antivirus & third-party Endpoint Protection status
- Host-based Firewall status (On / Off) and activity
- Auto Screen Lock timeout & lock-on-resume configuration
- User Account Control (UAC) prompt policy
- Core Isolation / Memory Integrity (HVCI)
- Microsoft Defender Attack Surface Reduction (ASR) rules summary
- PowerShell execution policy review
- Windows Anonymous Access restrictions
- Data Execution Prevention (DEP) support policy
- BitLocker Drive Encryption status across fixed volumes
- Office macro security policy (VBAWarnings)
- Removable storage (USBSTOR) and USB AutoRun (NoDriveTypeAutoRun) checks
- UEFI Secure Boot configuration check
- Windows System Restore status and policy

---

### 🌍 Remote Access & Exposure
- Remote Desktop (RDP) status, Network Level Authentication (NLA)
- PowerShell Remoting (WinRM) service, listener, and remote shell
- RPC Print Spooler (RpcEnabled & service exposure)
- DCOM configuration, authentication level, and hardening flag check
- NetBIOS over TCP/IP, UPnPHost, FTP, Rsync, and Bluetooth exposure + driver signature status
- SMBv1 optional feature / driver state and SMBv2/v3 signing, encryption, and null-session hardening check
- Remote Registry service configuration check and WinRM configuration and risk level analysis

---

### 👥 User & Domain Settings
- Audit of local user accounts, groups, and assigned roles
- Detection of privileged and administrative accounts
- Identification of Workgroup, Active Directory, Azure AD, and Hybrid domain environments
- LAPS (Local Administrator Password Solution) status and activity
- NTLM authentication policy and enforcement configuration analysis

---

### 🔒 Password Policy Analysis
- Password length, complexity, and character requirement validation
- Password expiration, history, and reuse policy analysis
- Account lockout thresholds, reset timers, and lockout duration review
- Identification of weak or legacy authentication configurations
- Overall assessment of domain-level password policy strength

---

### 🪪 Credential Integrity
- Credential Guard status and virtualization-based security enforcement check
- Non-admin Cached Credentials audit (`CachedLogonsCount`, Kerberos ticket cache via `klist`, and Windows Credential Vault via `vaultcmd`)

---

### 🧩 OS Version & Update Status
- Detecting Windows version, edition, build and revision (UBR) identification
- Listing installed updates inventory (cumulative and security updates)
- Presenting build comparison against Microsoft's release-health baselines

---

### 🔀 Proxy Configuration
- Audits WinINet (ProxyEnable, ProxyServer, AutoConfigURL, AutoDetect / WPAD), WinHTTP proxy, environment proxy variables
- Flags unexpected or suspicious SOCKS/Tor listeners, local MITM/tunnel tools (mitmproxy, Fiddler, Burp, ngrok, chisel, etc.)

---

### 🔐 SSL Interception Module
- Two-stage TLS certificate verification against the Windows OS trust store and Mozilla/WebPKI (certifi) roots
- SSL/TLS interception and potential man-in-the-middle (MITM) inspection, negotiated TLS version, and key strength
- Detects trusted enterprise SSL/TLS inspection vs untrusted MITM interception, CN/SAN mismatches, weak signature algorithms

---

### 💾 Sensitive Data Exposure
- Detection of sensitive system and directory service files (e.g., *.dit, *.ldf, *.mdf, *.ndf, *.edb)
- Identification of potentially exposed database files (e.g., *.sqlite, *.sqlite3, *.db, *.ibd, *.myd, *.myi)
- Evaluates file permissions (Everyone access), lock state, and exposed paths while filtering known benign OS metadata files

---

### ⚙️ Process & Connection
- Detection of suspicious processes and binaries based on behavior and execution patterns
- Digital signature validation of active processes, including non-system processes and official Windows system processes.
- Correlation of processes with network activity to identify suspicious communications
- Detection of unusual external connections, including connections involving commonly abused ports
- DLL/module anomalies, high file entropy, small suspicious binaries, persistence (Scheduled Tasks / Registry Run keys)
- LOLBin network/cmdline activity, wildcard listeners, and outbound connections on flagged remote ports

---

### 🌐 Web Browser Security Scanner
- Read-only multi-browser audit supporting Brave, Chrome, Edge, Firefox, Opera, Opera GX, and Vivaldi
- Inspects browser security settings, installed extensions, extension update sources, and site/privacy permissions
- Never reads saved passwords, cookies, browsing history, or bookmarks

---

### 📜 Event Log Analysis
- Basic analysis for Windows System and Security Event Logs, including selected Event IDs
- Audit of login activity, including successful and failed sign-in attempts
- Summarization of security-related events to help identify potential incidents

---

### 📊 Summary Report & MITRE ATT&CK Mapping
- Structured 26-element security posture table with Pass / Fail / N/A results and Fail-only MITRE ATT&CK technique mapping
- Clickable section jump links, live in-report search (`Ctrl+F`), and full TXT report export
