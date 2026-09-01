# Changelog
All notable changes to **Secuditor Lite** are documented in this file.

---

## [2.2.8] – 2026-09-01 Latest
- Added a vendor lookup feature to the LAN Scanner module
- Improved Windows 11 version and build detection
- Fixed Windows 11 compatibility issues and related bugs

---

## [2.2.7] – 2026-08-17
- Suspicious activity scanning capabilities integrated into the detection engine
- UI improvements and terminology updates

---

## [2.2.6] – 2026-08-05
- Added a Windows events node to the Events category
- Major improvements to the Suspicious Processes detection engine
- Resolved minor bugs and errors

---

## [2.2.5] – 2026-07-21 
- Added a new LAN scanner module with toolbar button integration
- Enhanced local network device detection and port auditing capabilities
- UI text and terminology improvements

---

## [2.2.4] – 2026-06-22
- Resolved internal logging timestamp issues
- IP discovery error in the gateway discovery module fixed

---

## [2.2.3] – 2026-06-06
- Data Execution Prevention (DEP) check added to Endpoint Security 
- Corrected DCOM status output in the summary report

---

## [2.2.2] – 2026-05-27
- Enhanced the WinRM remote access check and output
- Added DCOM service vulnerability evaluation to summary report

---

## [2.2.1] – 2026-05-17
- Improved SSL/TLS interception module detection logic and formatting
- Added digitally signed process validation to the detection engine
- Added LOLBins (Living Off The Land Binaries) detection intelligence
- Resolved duplicate results issue in Suspicious Connections detection module
- Clipboard events evaluation logic fixed via improved timestamp correlation

---

## [2.2.0] – 2026-05-10
- Added a report building window (via Tk) with selectable views
- Auto Screen Lock check added to Endpoint Security
- UI text and terminology improvements
- Removed pillow dependency, reducing executable size from 28 MB to 21 MB

---

## [2.1.9] – 2026-05-05
- Added detection for Azure AD / Hybrid domain environments (Domain Settings)
- Improved Server Features scanning with multi-service evaluation per feature
- Updated terminology: Local Firewall → Host-based Firewall
- General UI and output text refinements

---

## [2.1.8] – 2026-04-30
- Added removable storage & USB Autorun checks (Basic Security) 
- Added Office macro policy system-based check (Basic Security)
- Enhanced sensitive path scanning with support for additional data types
- Fixed issue where sensitive path scanning caused unexpected window jumps
- Corrected Server Features output to accurately display "Not Installed"

---

## [2.1.7] – 2026-04-20
- Added local credential hive access check (Credential Integrity)
- Added Microsoft Defender attack surface reduction (ASR) rules check
- Removed remote assistance from summary
- Removed unused dependency: dns.resolver
- Removed unused import: packaging.version

---

## [2.1.6] – 2026-04-15
- Minor textual updates and UI tweaks 
- Enhanced security layer for the speed test feature 
- Enhanced the system process scanning module with behavior-based detection 
- Added incoming and outgoing traffic detection per-process (Suspicious Connections) 
- Added multi-port activity detection per-process (Suspicious Connections) 
- Added command shell activity detection (potential reverse shell indicators) 
- Added high-entropy binary indicators (packed or obfuscated executables) 

---

## [2.1.5] – 2026-03-14
- Added IAS (Internet Authentication Service) server check
- Added RRAS (Routing and Remote Access Service) server check
- Added VMMS virtualization service detection (Hyper-V / VMware / VirtualBox)
- Added UPnP remote access check
- Resolved caching issue affecting certain system checks

---

## [2.1.4] – 2026-03-07
- Right-click "Run Check" option to execute single security checks
- Controlled timestamps for console messages and exported logs
- Resolved network gateway detection issues on IPv6 networks
- Resolved MAC/Vendor lookup attempting to run on IPv6 gateways

---

## [2.1.3] – 2026-03-02
- Gateway discovery now supports dual-stack (IPv4 + IPv6)
- Network settings check now supports dual-stack (IPv4 + IPv6)

---

## [2.1.2] – 2026-02-05
- Minor improvement to the logging workflow
- Resolved WinRM feature cache issue
- Resolved default gateway cache issue

---

## [2.1.1] – 2026-02-01
- Cache based module performance optimization
- Enhanced speed test module performance and visuals
- Resolved navigation issue when jumping from report to categories

---

## [2.1.0] – 2026-01-28
- Added speed test feature to measure internet throughput
- Added navigation links from the summary report for quick navigation
- Added NTP remote server detection feature
- Added WinRM remote access detection feature
- Optimized formatting in several categories
- UI improvements and updates

---

## [2.0.9] – 2026-01-24
- Minor performance optimizations
- Reshaped some report elements output

---

## [2.0.8] – 2026-01-16
- Renamed the software from **Secuditor Free** to **Secuditor Lite**
- Extended FTP server feature detection capabilities

---

## [2.0.7] – 2026-01-10
- Updated the main report and console window visuals
- Enhanced the sensitive path scan module

---

## [2.0.6] – 2026-01-07
- VPN connection detection module enhanced for better accuracy
- Resolved an issue with MSSQL Server feature output reporting

---

## [2.0.5] – 2026-01-01
- Added DHCP server feature check
- Added DNS server feature check
- Added WINS server feature check
- Added MSMQ server feature check
- Password policy history check enhanced
- Updated main window features description

---

## [2.0.4] – 2025-12-30
- Added MS-SQL server feature check
- Updated UI button and description
- Minor EULA (Section 1) wording changes

---

## [2.0.3] – 2025-30-27
- Added NetBIOS protocol check
- Added Certificate Authority (CA) server feature check
- Added DFS-R server feature check

---

## [2.0.2] – 2025-12-20
- Redesigned the UI main screen visuals
- Optimized threat intelligence processing
- Event logs display issue resolved

---

## [2.0.1] – 2025-12-13
- Added SNMP server feature check
- Added Rsync server feature check
- Improved the suspicious process detection mechanism
- Resolved password expiration output issue

---

## [2.0.0] – 2025-12-03
- Added NTLM policy evaluation
- Added PATH environment variable integrity check
- Added PowerShell script policy analysis
- Resolved conflicts between **Single Run** and **Run All** actions
- Fixed multiple issues affecting the logging system

---

## [1.9.9] – 2025-11-21
- Network gateway report issue resolved
- SSL/TLS interception bug fixed
- Secure Boot module now runs without requiring administrative privileges

---

## [1.9.8] – 2025-11-12
- Added descriptive text for toolbar buttons
- Resolved Windows core isolation check issue

---

## [1.9.7] – 2025-11-04
### Initial Public Release
