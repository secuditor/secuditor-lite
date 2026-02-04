# Open Scripts

A partial collection of open source Python modules developed as part of the **Secuditor project**. All **modules** in this repository are **standalone** and **[MIT-licensed](/open_scripts/LICENSE.txt)**, some modules may require the installation of third party dependencies.

For the full application, visit **[Secuditor Lite](secuditor-lite)** which is distributed separately as closed source **freeware**.

---

## Lawful Use

These tools are intended solely for lawful and authorized use. You must obtain explicit permission from the network owner before scanning, auditing, or testing any systems. The author assumes no liability for misuse or for actions that violate applicable laws or organizational policies. Use responsibly and in compliance with your local governance.

---

## Module Index

- [sp_credential_integrity.py](sp_credential_integrity.py) – Audits Windows credential protection mechanisms
- [sp_domain_settings.py](sp_domain_settings.py) – Identifies domain affiliation and discovers related settings
- [sp_gateway_detection.py](sp_gateway_detection.py) – Detects the local network's default gateway and public IP
- [sp_hash_checksum.py](sp_hash_checksum.py) – Calculates cryptographic file hashes for integrity verification
- [sp_https_scanner.py](sp_https_scanner.py) - Mini HTTPS security scanner for basic inspection (port 443 only)
- [sp_installed_apps.py](sp_installed_apps.py) – Outputs a list of applications installed on the device
- [sp_network_settings.py](sp_network_settings.py) – Presents the device's network adapters and configurations
- [sp_password_policy.py](sp_password_policy.py) – Evaluates local and domain affiliated password policies
- [sp_remote_access.py](sp_remote_access.py) – Detects remote access capabilities and services exposure
- [sp_remote_server.py](sp_remote_server.py) – Inspects the system for server side remote features
- [sp_security_events.py](sp_security_events.py) – Outputs recent Windows security event log entries (requires admin permissions)
- [sp_security_settings.py](sp_security_settings.py) – Reviews core Windows security posture settings
- [sp_shared_folders.py](sp_shared_folders.py) – Mapping shared folders on the device (requires admin permissions)
- [sp_system_audit.py](sp_system_audit.py) – Presents a detailed report of the system's settings and inventory
- [sp_workflow_example.py](sp_workflow_example.py) – An example module demonstrating audit workflow and logging 

---

## Installation

- Requires **Python 3.0** or higher  
- Compatible with **Windows**  
- Download the script and run it using Python:
  ```bash
  python script_name.py
- install third party package if needed:
  ```bash
  pip install package_name
