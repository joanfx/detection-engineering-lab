# T1059.001 - PowerShell Encoded Command Simulation
# This simulates an adversary executing an obfuscated base64 command.

$OriginalCommand = "Write-Host 'Malicious Payload Executed'; New-Item -Path 'C:\Splunk_Dopamine_Test.txt' -ItemType File"
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($OriginalCommand)
$EncodedCommand = [Convert]::ToBase64String($Bytes)

Write-Host "Executing Encoded Command..."
powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand $EncodedCommand