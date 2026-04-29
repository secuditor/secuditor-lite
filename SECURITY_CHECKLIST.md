# Secuditor Lite 2.1.5 – Security Checks & Diagnostics

This file lists the structured and comprehensive security audit elements that **Secuditor Lite** checks on Windows systems, helping identify misconfigurations, vulnerabilities, and potential risks across **endpoint, network, and operational security layers**.

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

### 🛡️ Basic Security Settings
- Antivirus / endpoint protection status  
- Firewall configuration and activity  
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
- Telnet, NetBIOS, UPnP, and Bluetooth exposure  
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

### 🔑 Credential Integrity
- LSASS process validation and integrity  
- Credential storage mechanisms (WDigest)  
- Credential Guard support and status  
- LSASS protection (RunAsPPL) configuration  
- Signature validation of security processes
- Local credential SAM hive access

---

### 👥 User & Domain Settings
- Local user accounts and roles  
- Privileged and administrative users  
- Workgroup / domain configuration  
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

### 🧩 OS Version & Update Status
- Windows version and build comparison  
- Activation status  
- Installed and pending updates  
- Patch level and update history  

---

### 💾 Sensitive Data Exposure
- Detection of sensitive system files (*.dit, *.ldf, *.mdf, *.ndf, *.edb, *.ad, etc)  
- Identification of potentially exposed database files (*.sqlite, *.sqlite3, *.db, *.ibd, *.myd, *.myi, etc)  
- Risk assessment of critical system paths (high / low risk)  

---

### ⚙️ Process & Connection
- Detection of suspicious processes  
- Analysis of active network connections  
- Based on unusual or high-risk behavior  

---

### 🔐 SSL/TLS Inspection
- Certificate validation and issuer analysis  
- Detection of SSL/TLS interception  
- Verification of certificate chains and fingerprints  
- Identification of potential man-in-the-middle activity  

---

### 📜 Event Log Analysis
- Windows security event logs inspection  
- Authentication and login activity audit  
- Potential security incidents review  
