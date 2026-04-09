# Featured Detection: LSASS Credential Dumping (T1003.001)

### Objective
Detect adversaries attempting to dump the memory of the Local Security Authority Subsystem Service (LSASS) to steal credentials.

### Methodology
Initially, I attempted to detect this via **Sysmon Event ID 10 (Process Access)**. However, during testing, I discovered that specific access flags (e.g., `0x1010`) were inconsistent in the lab environment, leading to false negatives. 

**The Pivot:** I shifted the detection strategy to **Sysmon Event ID 1 (Process Creation)**, focusing on the specific command-line arguments used by the `comsvcs.dll` Living-off-the-Land (LotL) technique. This detection was originally built and validated in a Wazuh environment. I have since migrated my home lab to Splunk and upgraded the detection logic to a platform-agnostic **Sigma** rule, demonstrating how this detection scales across different SIEMs.

### Technical Stack
* **SIEM:** Splunk (Current) / Wazuh Manager v4.x (Legacy)
* **Endpoint:** Windows 11 Enterprise
* **Telemetry:** Sysmon (Configured for Event ID 1 & 10)

### The Rule Logic
The core concept hinges on identifying the execution of `rundll32.exe` while passing the `MiniDump` function call to `comsvcs.dll` via the command line.

Splunk SPL Equivalent:
`index="main" source="*Sysmon*" EventCode=1 Image="*\\rundll32.exe" CommandLine="*comsvcs.dll*" AND CommandLine="*MiniDump*"`

### Proof of Detection

<img src="poc_splunk_lsass_dump.png" alt="Splunk Proof of Concept">

Splunk successfully triggering on the malicious command execution, revealing the credential dumping attempt.

<details>
<summary>Click to view Legacy Wazuh Validation</summary>

*(Original Level 12 Alert on the malicious command execution)*
<img src="legacy_wazuh/wazuh-detection.png" alt="Wazuh Proof of Concept">

```json
{
  "timestamp": "2026-02-10T13:53:59.343-0500",
  "rule": {
    "level": 12,
    "description": "Credential Dumping detected via comsvcs.dll",
    "id": "100001",
    "mitre": {
      "id": ["T1003.001"],
      "tactic": ["Credential Access"],
      "technique": ["LSASS Memory"]
    }
  },
  "agent": {
    "id": "001",
    "name": "Win11-Detection-Lab",
    "ip": "192.168.209.134"
  },
  "data": {
    "win": {
      "eventdata": {
        "image": "C:\\\\Windows\\\\System32\\\\rundll32.exe",
        "commandLine": "\"C:\\\\WINDOWS\\\\system32\\\\rundll32.exe\" C:\\\\windows\\\\System32\\\\comsvcs.dll MiniDump 792 C:\\\\Users\\\\labuser\\\\AppData\\\\Local\\\\Temp\\\\lsass.dmp full",
        "originalFileName": "RUNDLL32.EXE",
        "processId": "6904",
        "user": "DESKTOP-G08D067\\\\labuser"
      }
    }
  }
}