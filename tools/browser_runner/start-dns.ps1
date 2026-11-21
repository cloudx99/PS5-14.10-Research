# Persistent DNS hijack for PS5 research — run once from admin PowerShell
# Blocks svchost DNS for LAN, starts dns_hijack with auto-restart, registers at logon

$ErrorActionPreference = 'Stop'
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$pythonExe = (Get-Command python).Source
$dnsScript = Join-Path $scriptDir 'dns_hijack.py'

# 1. Firewall rule (idempotent)
$ruleName = 'BlockDnscacheExternal_PS5Research'
$existing = netsh advfirewall firewall show rule name=$ruleName 2>$null
if ($LASTEXITCODE -ne 0) {
    netsh advfirewall firewall add rule name=$ruleName dir=in action=block protocol=UDP localport=53 program="$env:SystemRoot\System32\svchost.exe" remoteip="10.99.99.0/24"
    Write-Host "Firewall rule added." -ForegroundColor Green
} else {
    Write-Host "Firewall rule already exists." -ForegroundColor Yellow
}

# 2. Kill any stale dns_hijack
Get-Process python -ErrorAction SilentlyContinue | Where-Object {
    try { (Get-CimInstance Win32_Process -Filter "ProcessId=$($_.Id)").CommandLine -match 'dns_hijack' } catch { $false }
} | ForEach-Object { Stop-Process -Id $_.Id -Force -Confirm:$false; Write-Host "Killed stale PID $($_.Id)" }

# 3. Register scheduled task (runs at logon, elevated, auto-restart loop)
$taskName = 'PS5Research_DnsHijack'
$loopCmd = "while (`$true) { try { & '$pythonExe' '$dnsScript' --ip 10.99.99.78 --bind 10.99.99.78 } catch {} ; Start-Sleep 2 }"
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -Command `"$loopCmd`""
$trigger = New-ScheduledTaskTrigger -AtLogon
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 999 -RestartInterval (New-TimeSpan -Seconds 10) -ExecutionTimeLimit ([TimeSpan]::Zero)
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -RunLevel Highest -LogonType Interactive
try { Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop } catch {}
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal | Out-Null
Write-Host "Scheduled task '$taskName' registered." -ForegroundColor Green

# 4. Start it now
Start-ScheduledTask -TaskName $taskName
Start-Sleep 3

# 5. Verify
$result = nslookup manuals.playstation.net 10.99.99.78 2>&1 | Out-String
if ($result -match '10\.99\.99\.78') {
    Write-Host "`nDNS hijack is working!" -ForegroundColor Green
} else {
    Write-Host "`nDNS test failed — check output:" -ForegroundColor Red
    Write-Host $result
}
