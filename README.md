# Detection Engineering & Threat Hunting Lab

### Overview
This repository is a live security operations and detection engineering portfolio. The purpose of this lab is to emulate specific MITRE ATT&CK techniques, generate high-fidelity adversarial telemetry, and engineer custom detection logic from bare metal to SIEM alert.

### How to Navigate This Repository
To avoid redundant indexing, this repository is organized directly by MITRE ATT&CK technique IDs. 

Browse the root directories to review specific simulated attacks. Each technique folder is a self-contained operation that includes:
* The simulation script used to emulate the adversary.
* The engineered detection rule (Sigma, Splunk SPL, or Wazuh XML).
* Raw SIEM validation artifacts, JSON logs, and telemetry proofs.

### Infrastructure & Telemetry Pipeline
The lab operates on a distributed virtualized network architecture to simulate a realistic enterprise endpoint environment.

* **SIEM / Search Head:** Ubuntu Server (Splunk Enterprise v10.x / Wazuh v4.x)
* **Target Endpoint:** Windows 11 Enterprise
* **Log Forwarder:** Splunk Universal Forwarder
* **Telemetry Sources:** * Sysmon (Process Creation, Process Access, Network Connections)
  * Windows Security Event Logs (Event ID 4688)
  * PowerShell Operational Logs