## Secuditor Lite – Security Checks & Diagnostics

Secuditor Lite provides a structured and comprehensive security audit of Windows systems, helping identify misconfigurations, vulnerabilities, and potential risks across endpoint, network, and operational security layers.

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
- PowerShell execution policy  
- Disk encryption (BitLocker) status  
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
- Detection of active server roles and services  
- DHCP, DNS, FTP, SSH, SNMP, SMTP, and more  
- Web server (IIS) and database services  
- Remote access and infrastructure services  
- Identification of unnecessary or exposed services  

---

### 🔑 Credential Integrity
- LSASS process validation and integrity  
- Credential storage mechanisms (WDigest)  
- Credential Guard support and status  
- LSASS protection (RunAsPPL) configuration  
- Signature validation of security processes  

---

### 👥 User & Access Control
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
- Detection of sensitive system files (SAM, SECURITY, etc.)  
- Identification of potentially exposed configuration files  
- Risk assessment of critical system paths  

---

### ⚙️ Process & Connection Monitoring
- Detection of suspicious processes  
- Analysis of active network connections  
- Identification of unusual or high-risk behavior  

---

### 🔐 SSL/TLS Inspection
- Certificate validation and issuer analysis  
- Detection of SSL/TLS interception  
- Verification of certificate chains and fingerprints  
- Identification of potential man-in-the-middle activity  

---

### 📜 Event Log Analysis
- Windows Event Logs inspection (Security, System, Application)  
- Detection of suspicious or anomalous events  
- Analysis of authentication and login activity  
- Identification of potential security incidents  
