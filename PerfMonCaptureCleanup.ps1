<# 
PerfMonCaptureCleanup.ps1

What it does:
- Disables/ends the scheduled task FIRST to prevent restart
- Stops the PerfMon Data Collector Set (logman) robustly (retries + -ets)
- Deletes the Data Collector Set
- Removes the scheduled task
- Zips logs from the target folder into:
    <CollectorName>_<COMPUTERNAME>_<FirstDate>_<LastDate>.zip
  where First/Last are derived from file LastWriteTime.
- Purges logs by default after successful zip (opt-out with -KeepLogs)

Usage examples:
  .\PerfMonCaptureCleanup.ps1
  .\PerfMonCaptureCleanup.ps1 -KeepLogs
  .\PerfMonCaptureCleanup.ps1 -EnablePlaRestartFallback
  .\PerfMonCaptureCleanup.ps1 -LogPath "C:\PerfLogs\Attentus" -ArchiveRoot "C:\PerfLogs\Archives"
#>

[CmdletBinding()]
param(
    [string]$CollectorName = "Attentus_PerfMonitor",
    [string]$LogPath = "C:\PerfLogs\Attentus",

    # Where to store the ZIP(s). Defaults to a sibling folder next to LogPath.
    [string]$ArchiveRoot = (Join-Path (Split-Path -Parent $LogPath) "PerfMonCaptureArchives"),

    # If set, logs are NOT deleted after creating the ZIP.
    [switch]$KeepLogs,

    # If set, will restart the PLA service as a last resort if the collector refuses to stop.
    # This can affect other data collector sets; leave off unless you need it.
    [switch]$EnablePlaRestartFallback,

    # Stop retry tuning
    [int]$StopRetries = 6,
    [int]$StopDelaySeconds = 3
)

$ErrorActionPreference = "Stop"

function Test-IsAdministrator {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

function Get-CollectorStatus {
    param([string]$Name)

    try {
        $out = logman query $Name 2>$null
        if (-not $out) { return "NotFound" }

        $statusLine = $out | Where-Object { $_ -match '^\s*Status:' } | Select-Object -First 1
        if ($statusLine) {
            return ($statusLine -replace '^\s*Status:\s*', '').Trim()
        }

        # Fallback heuristic
        if (($out | Out-String) -match 'Running') { return "Running" }
        return "Unknown"
    }
    catch {
        return "NotFound"
    }
}

function Disable-And-EndScheduledTask {
    param([string]$TaskName)

    $disabled = $false

    # Disable task so it cannot restart the collector
    try {
        $null = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
        Disable-ScheduledTask -TaskName $TaskName | Out-Null
        Write-Host "Disabled scheduled task: $TaskName"
        $disabled = $true
    }
    catch {
        # Fall back to schtasks
        try {
            schtasks /Change /TN $TaskName /Disable | Out-Null
            Write-Host "Disabled scheduled task (schtasks): $TaskName"
            $disabled = $true
        }
        catch {
            Write-Host "Scheduled task not found to disable: $TaskName"
        }
    }

    if ($disabled) {
        # If the task is currently running, end it (non-fatal if not running)
        try {
            schtasks /End /TN $TaskName 2>$null | Out-Null
            Write-Host "Ended running scheduled task (if running): $TaskName"
        }
        catch { }
    }
}

function Stop-CollectorRobust {
    param(
        [string]$Name,
        [int]$Retries,
        [int]$DelaySeconds,
        [switch]$PlaRestartFallback
    )

    $status = Get-CollectorStatus -Name $Name
    Write-Host "Collector status before stop: $Name => $status"

    if ($status -eq "NotFound") {
        Write-Host "Collector not found: $Name"
        return
    }

    for ($i = 1; $i -le $Retries; $i++) {

        # Attempt standard stop (counter logs)
        try { logman stop $Name | Out-Null } catch { }

        Start-Sleep -Seconds $DelaySeconds
        $status = Get-CollectorStatus -Name $Name
        if ($status -ne "Running") {
            Write-Host "Collector stopped (non-running state): $Name => $status"
            return
        }

        # Attempt ETS stop (trace sessions / stubborn cases)
        try { logman stop $Name -ets | Out-Null } catch { }

        Start-Sleep -Seconds $DelaySeconds
        $status = Get-CollectorStatus -Name $Name
        if ($status -ne "Running") {
            Write-Host "Collector stopped after ETS stop: $Name => $status"
            return
        }

        Write-Host "Stop attempt $i/$Retries did not stop collector yet: $Name still Running"
    }

    if ($PlaRestartFallback.IsPresent) {
        try {
            Write-Host "Collector still running. Attempting last-resort stop via PLA service restart (opt-in enabled)."
            Stop-Service -Name pla -Force -ErrorAction Stop
            Start-Sleep -Seconds 2
            Start-Service -Name pla -ErrorAction Stop
            Start-Sleep -Seconds 2

            $status = Get-CollectorStatus -Name $Name
            Write-Host "Collector status after PLA restart: $Name => $status"
        }
        catch {
            Write-Host "PLA restart fallback failed or not permitted: $($_.Exception.Message)"
        }
    } else {
        Write-Host "Collector still appears to be running after retries. PLA fallback is disabled (use -EnablePlaRestartFallback if needed)."
    }
}

function Try-DeleteCollector {
    param([string]$Name)

    try {
        logman delete $Name | Out-Null
        Write-Host "Deleted Data Collector Set: $Name"
    }
    catch {
        Write-Host "Data Collector Set not found or already deleted: $Name"
    }
}

function Try-RemoveScheduledTask {
    param([string]$TaskName)

    try {
        $null = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Host "Removed scheduled task: $TaskName"
        return
    }
    catch {
        # fall through
    }

    try {
        schtasks /Delete /TN $TaskName /F | Out-Null
        Write-Host "Removed scheduled task (schtasks): $TaskName"
    }
    catch {
        Write-Host "Scheduled task not found or already removed: $TaskName"
    }
}

function New-LogArchiveZip {
    param(
        [string]$SourcePath,
        [string]$ArchiveRootPath,
        [string]$BaseName
    )

    if (-not (Test-Path $SourcePath)) {
        Write-Host "Log path not found; nothing to archive: $SourcePath"
        return $null
    }

    # Exclude existing ZIPs so we don’t re-zip archives.
    $files = Get-ChildItem -Path $SourcePath -File -Recurse -ErrorAction SilentlyContinue |
             Where-Object { $_.Extension -ne ".zip" }

    if (-not $files -or $files.Count -eq 0) {
        Write-Host "No log files found to archive in: $SourcePath"
        return $null
    }

    $first = ($files | Sort-Object LastWriteTime | Select-Object -First 1).LastWriteTime
    $last  = ($files | Sort-Object LastWriteTime | Select-Object -Last 1).LastWriteTime

    $firstStamp = $first.ToString("yyyyMMdd-HHmmss")
    $lastStamp  = $last.ToString("yyyyMMdd-HHmmss")
    $computer   = $env:COMPUTERNAME

    if (-not (Test-Path $ArchiveRootPath)) {
        New-Item -ItemType Directory -Path $ArchiveRootPath -Force | Out-Null
    }

    $zipName = "{0}_{1}_{2}_{3}.zip" -f $BaseName, $computer, $firstStamp, $lastStamp
    $zipPath = Join-Path $ArchiveRootPath $zipName

    if (Test-Path $zipPath) {
        $suffix = (Get-Date).ToString("yyyyMMdd-HHmmss")
        $zipName = "{0}_{1}_{2}_{3}_{4}.zip" -f $BaseName, $computer, $firstStamp, $lastStamp, $suffix
        $zipPath = Join-Path $ArchiveRootPath $zipName
    }

    Write-Host "Creating archive: $zipPath"
    Compress-Archive -Path (Join-Path $SourcePath "*") -DestinationPath $zipPath -Force

    return $zipPath
}

Write-Host "=== PerfMonCapture Cleanup Start ==="
Write-Host "CollectorName:               $CollectorName"
Write-Host "LogPath:                     $LogPath"
Write-Host "ArchiveRoot:                 $ArchiveRoot"
Write-Host "KeepLogs (opt-out purge):    $KeepLogs"
Write-Host "PLA restart fallback enabled:$EnablePlaRestartFallback"
Write-Host ""

if (-not (Test-IsAdministrator)) {
    Write-Host "Warning: Not running as Administrator. Stopping/deleting collectors and managing tasks may fail."
}

# 1) Disable + end scheduled task FIRST (prevents restart)
Disable-And-EndScheduledTask -TaskName $CollectorName

# 2) Stop collector robustly
Stop-CollectorRobust -Name $CollectorName -Retries $StopRetries -DelaySeconds $StopDelaySeconds -PlaRestartFallback:$EnablePlaRestartFallback

# 3) Delete data collector set
Try-DeleteCollector -Name $CollectorName

# 4) Remove the scheduled task
Try-RemoveScheduledTask -TaskName $CollectorName

# 5) Zip logs
$zip = New-LogArchiveZip -SourcePath $LogPath -ArchiveRootPath $ArchiveRoot -BaseName $CollectorName

if ($zip) {
    Write-Host "Archive created: $zip"

    # 6) Purge by default unless -KeepLogs is provided
    if (-not $KeepLogs.IsPresent) {
        try {
            Write-Host "Purging logs from: $LogPath"
            Get-ChildItem -Path $LogPath -Recurse -Force -ErrorAction SilentlyContinue |
                Remove-Item -Recurse -Force -ErrorAction Stop
            Write-Host "Logs purged."
        }
        catch {
            Write-Host "Failed to purge logs from $LogPath. Error: $($_.Exception.Message)"
        }
    } else {
        Write-Host "KeepLogs specified; logs were NOT deleted."
    }
} else {
    Write-Host "No archive created (no logs found or log path missing). Logs will NOT be deleted."
}

Write-Host ""
Write-Host "Cleanup completed."
