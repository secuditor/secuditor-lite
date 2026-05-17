# Secuditor Lite 2.2.1 – Security Checks & Diagnostics

This file lists the structured and comprehensive security audit elements that **Secuditor Lite** checks on Windows systems, helping identify misconfigurations, vulnerabilities, and potential risks across **endpoint, network, and operational security layers**.

For complete and accurate results, the tool should be run with **administrator privileges**.

---

### 🖥️ System Overview
- Hostname and OS version detection  
- System architecture and processor details  
- CPU cores, threads, and memory usage  
- Disk structure, file systems, and storage utilization  

---

### 🔌 Hardware Analysis
- Detection of connected hardware components  
- USB devices and controllers  
- Bluetooth devices and adapters  
- Biometric devices (e.g. fingerprint readers)  
- Network interfaces and virtual adapters  

---

### 🌐 Network Configuration
- Local IP addresses (IPv4 / IPv6)  
- Subnet masks and routing configuration  
- Default gateway and DHCP servers  
- DNS configuration and resolution setup  
- Network interface availability (Wi-Fi / Ethernet)  

---

### 📂 Shared Folders & Permissions
- Detection of shared folders and network shares  
- Analysis of access permissions (read / write / full control)  
- Identification of overly permissive or exposed shares  
- Mapping of shared resources across the system  
- Helps detect potential data exposure and unauthorized access risks

---

### 🛰️ Gateway Discovery
- Gateway vendor identification  
- MAC and IP address mapping  
- NAT and VPN detection  
- Gateway responsiveness (ICMP / HTTP)  
- Public IP exposure analysis  

---

### 🛡️ Endpoint Security Settings
- Antivirus / endpoint protection status  
- Firewall configuration and activity
- Auto Screen Lock configuration 
- User Account Control (UAC) settings  
- Core isolation and memory protection
- Attack Surface Reduction (ASR) rules
- PowerShell execution policy
- EFS encryption protocol usage  
- Disk encryption (BitLocker) status
- Office Macro Security Policy  
- Removable storage Status  
- USB Autorun configuration  
- Secure Boot configuration  
- System restore availability  

---

### 🌍 Remote Access & Exposure
- Remote Desktop and Remote Assistance status  
- PowerShell remoting configuration  
- RPC and remote service exposure
- Network COM Services analysis
- Telnet, NetBIOS, UPnPHost, and Bluetooth exposure  
- WinRM configuration and risk level  
- SMB protocol versions (SMBv1 / SMBv2)  

---

### 🖥️ Server & Service Exposure
- Detection of active server roles and features  
- DHCP, DNS, FTP, SSH, SNMP, SMTP, and more  
- Web server (IIS) and database services  
- Remote access and infrastructure services  
- Identification of unsecured services  

---

### 👥 User & Domain Settings
- Local user accounts and roles  
- Privileged and administrative users  
- Workgroup, On-Prem Active Directory, Azure AD and Hybrid domain environments
- LAPS (Local Administrator Password Solution) status  
- NTLM authentication policy and enforcement  

---

### 🔒 Password Policy Analysis
- Password length and complexity requirements  
- Password expiration and reuse policies  
- Account lockout thresholds and duration  
- Multi-factor authentication (MFA) capability  
- Overall password policy strength assessment  

---

### 🔑 Credential Integrity
- LSASS process validation and integrity  
- Credential storage mechanisms (WDigest)  
- Credential Guard support and status  
- LSASS protection (RunAsPPL) configuration  
- Signature validation of security processes
- Local credential SAM hive access

---

### 🔐 SSL/TLS Inspection
- Certificate validation and issuer analysis  
- Detection of SSL/TLS interception  
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
