# Nexus Agent (Windows) — the Windows implementation of the SAME
# /api/v1/metrics contract as agent/nexus_agent.py. PowerShell 5.1+, no
# modules, no downloads. Read-only by construction (CIM queries only).
#
# TLS: terminated by http.sys via the machine-level sslcert binding that
# install.ps1 creates — this process never touches the private key, which is
# why it can run as NETWORK SERVICE. Auth: Bearer token (minted on first run
# or by install.ps1). The controller enrolls it as host type 'Nexus Agent';
# the payload's platform field says windows.
$ErrorActionPreference = 'Stop'
$AGENT_VERSION = '1.0.0'
$Port    = if ($env:AGENT_PORT) { [int]$env:AGENT_PORT } else { 9143 }
$DataDir = if ($env:AGENT_DATA_DIR) { $env:AGENT_DATA_DIR } else { Join-Path $env:ProgramData 'NexusAgent' }
$TokenFile = Join-Path $DataDir 'token'

if (-not (Test-Path $DataDir)) { New-Item -ItemType Directory -Path $DataDir -Force | Out-Null }
if (Test-Path $TokenFile) {
    $Token = (Get-Content $TokenFile -Raw).Trim()
} else {
    $bytes = New-Object byte[] 32
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $Token = 'na_' + ([Convert]::ToBase64String($bytes) -replace '\+','-' -replace '/','_' -replace '=','')
    Set-Content -Path $TokenFile -Value $Token -NoNewline
    Write-Output "nexus-agent: minted new API token (enroll the host with it): $Token"
}

function Get-Metrics {
    $os    = Get-CimInstance Win32_OperatingSystem
    $procs = @(Get-CimInstance Win32_Processor)
    $disks = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3')   # fixed drives

    $loads = @($procs | ForEach-Object { $_.LoadPercentage } | Where-Object { $null -ne $_ })
    $cpuPct = if ($loads.Count) { [math]::Round(($loads | Measure-Object -Average).Average, 1) } else { $null }

    $memTotal = [int64]$os.TotalVisibleMemorySize * 1024   # CIM reports KB
    $memFree  = [int64]$os.FreePhysicalMemory * 1024
    $memUsed  = $memTotal - $memFree

    $mounts = @()
    foreach ($d in $disks) {
        if (-not $d.Size) { continue }
        $total = [int64]$d.Size; $free = [int64]$d.FreeSpace; $used = $total - $free
        $mounts += [ordered]@{
            device = $d.DeviceID; mountpoint = ($d.DeviceID + '\')
            fstype = $d.FileSystem
            total = $total; used = $used; free = $free
            percent = [math]::Round($used / $total * 100, 1)
        }
    }

    [ordered]@{
        agent = 'nexus-agent'; version = $AGENT_VERSION; platform = 'windows'
        hostname = $env:COMPUTERNAME
        os = $os.Caption; kernel = $os.Version; arch = $os.OSArchitecture
        uptime_seconds = [int]((Get-Date) - $os.LastBootUpTime).TotalSeconds
        sampled_at = [double][DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        cpu = [ordered]@{ percent = $cpuPct
                          count = [int]$env:NUMBER_OF_PROCESSORS; load1 = $null }
        memory = [ordered]@{ total = $memTotal; available = $memFree
                             used = $memUsed
                             percent = if ($memTotal) { [math]::Round($memUsed / $memTotal * 100, 1) } else { $null } }
        mounts = $mounts
    }
}

$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add("https://+:$Port/")
$listener.Start()
Write-Output "nexus-agent v$AGENT_VERSION (windows) on https://+:$Port"

while ($true) {
    try {
        $ctx = $listener.GetContext()
        $req = $ctx.Request; $res = $ctx.Response
        $path = $req.Url.AbsolutePath.TrimEnd('/')
        if (-not $path) { $path = '/' }
        $code = 200
        if ($path -eq '/') {
            $body = [ordered]@{ app = 'nexus-agent'; version = $AGENT_VERSION }
        } elseif ($path -eq '/api/v1/metrics' -or $path -eq '/metrics') {
            $auth = $req.Headers['Authorization']
            if ($auth -and $auth.StartsWith('Bearer ') -and ($auth.Substring(7).Trim() -ceq $Token)) {
                $body = Get-Metrics
            } else {
                $body = [ordered]@{ error = 'authentication required' }; $code = 401
            }
        } else {
            $body = [ordered]@{ error = 'not found' }; $code = 404
        }
        $buf = [Text.Encoding]::UTF8.GetBytes(($body | ConvertTo-Json -Depth 5 -Compress))
        $res.StatusCode = $code
        $res.ContentType = 'application/json'
        $res.ContentLength64 = $buf.Length
        $res.OutputStream.Write($buf, 0, $buf.Length)
        $res.OutputStream.Close()
    } catch {
        Start-Sleep -Milliseconds 100   # one bad request must never kill the loop
    }
}
