# Nexus Agent (Windows) installer — run in an ELEVATED PowerShell from the
# directory containing nexus_agent.ps1. Idempotent: re-run to upgrade in
# place (token + cert binding preserved).
#
#   .\install.ps1              # -> C:\Program Files\NexusAgent on :9143
#   .\install.ps1 -Port 9200
#   .\install.ps1 -Uninstall
param(
    [int]$Port = 9143,
    [switch]$Uninstall
)
$ErrorActionPreference = 'Stop'
$Dir = 'C:\Program Files\NexusAgent'
$DataDir = Join-Path $env:ProgramData 'NexusAgent'
$RunAs = 'NETWORK SERVICE'   # http.sys owns the TLS key; the agent needs no privilege

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this from an elevated PowerShell.'
}

if ($Uninstall) {
    Unregister-ScheduledTask -TaskName NexusAgent -Confirm:$false -ErrorAction SilentlyContinue
    Get-NetFirewallRule -Name NexusAgent -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    netsh http delete sslcert ipport=0.0.0.0:$Port | Out-Null
    netsh http delete urlacl url=https://+:$Port/ | Out-Null
    Write-Output "Task/firewall/bindings removed. Files (incl. token) left at $Dir and $DataDir."
    return
}

New-Item -ItemType Directory -Force -Path $Dir, $DataDir | Out-Null
Copy-Item -Force (Join-Path $PSScriptRoot 'nexus_agent.ps1') $Dir

# Self-signed cert + machine-level TLS binding (once; the controller pins it).
$have = netsh http show sslcert ipport=0.0.0.0:$Port 2>$null | Select-String 'Certificate Hash'
if (-not $have) {
    Write-Output '==> generating self-signed TLS certificate + http.sys binding'
    $cert = New-SelfSignedCertificate -DnsName $env:COMPUTERNAME `
        -CertStoreLocation Cert:\LocalMachine\My -NotAfter (Get-Date).AddYears(10)
    $appid = [guid]::NewGuid().ToString('B')
    netsh http add sslcert ipport=0.0.0.0:$Port certhash=$($cert.Thumbprint) appid=$appid certstorename=MY | Out-Null
}
netsh http add urlacl url=https://+:$Port/ user=$RunAs 2>$null | Out-Null

# Token: pre-mint so this script can print it (the agent self-mints otherwise).
$TokenFile = Join-Path $DataDir 'token'
if (-not (Test-Path $TokenFile)) {
    $bytes = New-Object byte[] 32
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    Set-Content -NoNewline -Path $TokenFile -Value ('na_' + ([Convert]::ToBase64String($bytes) -replace '\+','-' -replace '/','_' -replace '=',''))
}
icacls $DataDir /inheritance:r /grant 'SYSTEM:(OI)(CI)F' /grant 'Administrators:(OI)(CI)F' /grant "${RunAs}:(OI)(CI)RX" | Out-Null

Get-NetFirewallRule -Name NexusAgent -ErrorAction SilentlyContinue | Remove-NetFirewallRule
New-NetFirewallRule -Name NexusAgent -DisplayName 'Nexus Agent' -Direction Inbound `
    -Protocol TCP -LocalPort $Port -Action Allow | Out-Null

# Boot persistence: a Scheduled Task (a .ps1 can't be a real SCM service
# without a wrapper binary, and the agent stays dependency-free).
Write-Output "==> scheduled task NexusAgent (runs as $RunAs)"
$action = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument ('-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "' + (Join-Path $Dir 'nexus_agent.ps1') + '"')
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId $RunAs -LogonType ServiceAccount
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Unregister-ScheduledTask -TaskName NexusAgent -Confirm:$false -ErrorAction SilentlyContinue
Register-ScheduledTask -TaskName NexusAgent -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings | Out-Null
Start-ScheduledTask -TaskName NexusAgent
Start-Sleep -Seconds 2
if ((Get-ScheduledTask -TaskName NexusAgent).State -ne 'Running') {
    throw 'NexusAgent task failed to start — check: Get-ScheduledTaskInfo NexusAgent'
}

$ip = (Get-NetIPAddress -AddressFamily IPv4 |
       Where-Object { $_.IPAddress -notlike '169.*' -and $_.IPAddress -ne '127.0.0.1' } |
       Select-Object -First 1).IPAddress
Write-Output ''
Write-Output 'Nexus Agent is running.'
Write-Output '  Enroll in the controller as host type ''Nexus Agent'':'
Write-Output "    Base URL:  https://${ip}:$Port"
Write-Output ('    Token:     ' + (Get-Content $TokenFile -Raw).Trim())
