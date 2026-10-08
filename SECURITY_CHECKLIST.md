# Secuditor Lite 2.3.0 – Security Checks & Diagnostics

This file lists the structured and comprehensive security audit elements that **Secuditor Lite** checks on Windows systems, helping identify misconfigurations, vulnerabilities, and potential risks across **endpoint, network, and operational security layers**.

For complete and accurate results, the tool should be run with **administrator privileges**.

---

### 🖥️ System Overview
- Hostname and operating system version detection
- System architecture (x86/x64/ARM) and processor identification
- CPU core count, thread count, and total memory (RAM) capacity
- Disk structure overview including partitions, and storage

---

### 🔌 Hardware Analysis
- Detection of connected hardware components and devices
- USB devices enumeration including storage, input, and peripheral
- Biometric hardware detection (fingerprint readers, IR cameras)
- Network interfaces enumeration including physical and virtual adapters

---

### 🌐 Network Configuration
- Local IP address enumeration (IPv4 and IPv6)
- Subnet mask and network segmentation details
- Default gateway identification and overview
- DHCP and DNS server detection and analysis
- Network interface status (Wi-Fi, Ethernet, virtual adapters)

---

### 📂 Shared Folders & Permissions
- Detection of shared folders and network shares
- Analysis of access permissions (read / write / full control)
- Identification of overly permissive or exposed shares
- Mapping of shared resources across the system
- Helps detect potential data exposure and unauthorized access risks

---

### 🛰️ Gateway Discovery
- Gateway vendor identification via MAC OUI lookup
- Default gateway MAC and IP address mapping
- NAT environment and VPN/Proxy detection
- Gateway testing using ICMP (ping) and HTTP probing
- Public IP identification and geolocation check

---

### 🔍 LAN Scanning and Traffic Flow
- IPv4-based local network device discovery
- Vendor identification via MAC address OUI
- Detection of common open ports and exposed network services
- Network traffic flow analysis by process, port, protocol, and direction
- Identification of active connections and potentially unusual network activity

---

### 🛡️ Endpoint Security Settings
- Antivirus / Endpoint protection status
- Firewall status (On / Off) and activity
- Auto screen lock configuration review
- User Account Control (UAC) settings
- Core isolation and memory protection
- Attack Surface Reduction (ASR) rules
- PowerShell execution policy review
- Data Execution Prevention (DEP) status
- EFS encryption protocol usage
- Disk encryption (BitLocker) status
- Office macro security policy review
- Removable storage status check
- USB Autorun configuration check
- Secure Boot configuration check
- System Restore point availability

---

### 🌍 Remote Access & Exposure
- Remote Desktop and Remote Assistance status
- PowerShell remoting configuration analysis
- RPC Print Spooler and remote service exposure
- DCOM Service vulnerability analysis
- Telnet, Rsync, NetBIOS, UPnPHost, and Bluetooth exposure
- WinRM configuration and risk level analysis
- SMB protocol versions (SMBv1 / SMBv2)

---

### 🖥️ Server & Service Exposure
- Active server roles and features, with potential exposure assessment
- Wweb server (IIS) and database (SQL Server) services
- Infrastructure services, including DHCP, DNS, DFSR, FTP, LDAP, SSH, SNMP, SMTP and more
- Analysis of remote access services and infrastructure components
- Identification of potentially insecure protocols and service configurations

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
- Multi-factor authentication (MFA) capability and enforcement detection
- Identification of weak or legacy authentication configurations
- Overall assessment of domain-level password policy strength

---

### 🧩 OS Version & Update Status
- Windows version, edition, and build identification
- Installed updates inventory (cumulative and security updates)
- Pending updates detection (Windows Update queue analysis)
- Patch level assessment against latest known security baseline

---

### 🔐 SSL Interception Module
- Certificate key types and strength (RSA/ECDSA) against minimum security thresholds
- SSL/TLS interception and potential man-in-the-middle (MITM) inspection
- Supported TLS version detection, including deprecated Ciphers

---

### 💾 Sensitive Data Exposure
- Detection of sensitive system and directory service files (e.g., *.dit, *.ldf, *.mdf, *.ndf, *.edb)
- Identification of potentially exposed database files (e.g., *.sqlite, *.sqlite3, *.db, *.ibd, *.myd, *.myi)
- Risk assessment of critical system paths, categorized as high or low risk

---

### ⚙️ Process & Connection
- Detection of suspicious processes based on behavior and execution patterns
- Digital signature validation of active non-system processes
- Analysis of active network connections, including local and external endpoints
- Correlation of processes with network activity to identify suspicious communications
- Detection of unusual external connections, including connections involving commonly abused ports

---

### 📜 Event Log Analysis
- Windows System and Security Event Logs, including selected Event IDs
- Audit of login activity, including successful and failed sign-in attempts
- Summarization of security-related events to help identify potential incidents
