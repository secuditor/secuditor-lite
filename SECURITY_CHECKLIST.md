# Secuditor Lite 2.2.1 – Security Checks & Diagnostics

This file lists the structured and comprehensive security audit elements that **Secuditor Lite** checks on Windows systems, helping identify misconfigurations, vulnerabilities, and potential risks across **endpoint, network, and operational security layers**.

For complete and accurate results, the tool should be run with **administrator privileges**.

---

### 🖥️ System Overview
- Hostname and operating system version detection  
- System architecture (x86/x64/ARM) and processor identification  
- CPU core count, thread count, and current utilization overview  
- Memory usage analysis (total, used, and available RAM)  
- Disk structure overview including partitions, and storage utilization  

---

### 🔌 Hardware Analysis
- Detection of connected hardware components and device classes  
- USB devices enumeration including storage, input, and peripheral devices  
- Biometric hardware detection (e.g., fingerprint readers, IR cameras)  
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
- NAT environment detection and identification of potential VPN/Proxy  
- Gateway responsiveness testing using ICMP (ping) and HTTP probing  
- Public IP exposure analysis to determine external-facing network presence  

---

### 🛡️ Endpoint Security Settings
- Antivirus / Endpoint protection status  
- Firewall status (On / Off) and activity  
- Auto screen lock configuration review  
- User Account Control (UAC) settings  
- Core isolation and memory protection  
- Attack Surface Reduction (ASR) rules  
- PowerShell execution policy review  
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
- PowerShell remoting configuration  
- RPC Print Spooler and remote service exposure
- Network COM Services exposure analysis  
- Telnet, Rsync, NetBIOS, UPnPHost, and Bluetooth exposure  
- WinRM configuration and risk level analysis  
- SMB protocol versions (SMBv1 / SMBv2)  

---

### 🖥️ Server & Service Exposure
- Detection of active server roles and features  
- DHCP, DNS, DFSR, FTP, LDAP, SSH, SNMP, SMTP, and more  
- Web server (IIS) and database (SQL) services  
- Remote access and infrastructure elemnts analysis  
- Identification of unsecured protocol and services  

---

### 👥 User & Domain Settings
- Audit of local user accounts, groups, and assigned roles  
- Detection of privileged and administrative accounts  
- Identification of Workgroup, Active Directory, Azure AD, and Hybrid domain environments  
- LAPS (Local Administrator Password Solution) status and activity  
- NTLM authentication policy and enforcement configuration analysis  

---

### 🔒 Password Policy Analysis
- Password length and complexity requirements  
- Password expiration and reuse policies  
- Account lockout thresholds and duration  
- Multi-factor authentication (MFA) capability  
- Overall password policy strength assessment  

---

### 🔑 Credential Integrity
- Password length, complexity, and character requirement validation  
- Password expiration, history, and reuse policy analysis  
- Account lockout thresholds, reset timers, and lockout duration review  
- Multi-factor authentication (MFA) capability and enforcement detection  
- Identification of weak or legacy authentication configurations  
- Overall password policy strength and compliance assessment  

---

### 🔐 SSL/TLS Inspection
- Certificate validation and issuer analysis  
- Detection of SSL/TLS interception and potential man-in-the-middle  
- Verification of certificate chains and fingerprints  
- Identification of potential man-in-the-middle activity  
- Key type and strength (RSA/ECDSA) evaluated against minimum security thresholds  

---

### 💾 Sensitive Data Exposure
- Detection of sensitive system files (*.dit, *.ldf, *.mdf, *.ndf, *.edb, *.ad, etc)  
- Identification of potentially exposed database files (*.sqlite, *.sqlite3, *.db, *.ibd, *.myd, *.myi, etc)  
- Risk assessment of critical system paths (high / low risk)  

---

### ⚙️ Process & Connection
- Detection of suspicious processes based on behavior and execution patterns
- Digitally signed process validation to none system processes
- Analysis of active network connections (local and external endpoints)  
- Correlation between processes and network activity to detect suspicious communication  
- Detection of abnormal port usage, including high-numbered or commonly abused ports  

---

### 🧩 OS Version & Update Status
- Windows version, edition, and build identification
- Activation status check (genuine vs unlicensed indicators)  
- Installed updates inventory (cumulative and security updates)  
- Pending updates detection (Windows Update queue analysis)  
- Patch level assessment against latest known security baseline  

---

### 📜 Event Log Analysis
- Windows Security Event Log inspection (specific Event IDs)  
- Login activity audit including sign-in attempts  
- Simplified review of potential security incidents  
