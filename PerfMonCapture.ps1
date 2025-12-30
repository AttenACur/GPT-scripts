# Attentus Generic Perfmon Collector with Proper Counter Setup and Delays

$CollectorName = "Attentus_PerfMonitor"
$LogPath = "C:\PerfLogs\Attentus"
$DurationSeconds = 604800  # 7 days
$Interval = 15  # 15-second collection interval

# Ensure log directory exists
if (!(Test-Path $LogPath)) {
    New-Item -ItemType Directory -Path $LogPath -Force
}

 # Define counters to collect (space-separated for logman)
$counters = @(
    # ===== CPU & Scheduling (system) =====
    '\Processor(_Total)\% Processor Time',
    '\Processor(_Total)\% Privileged Time',
    '\Processor(_Total)\% DPC Time',
    '\Processor(_Total)\% Interrupt Time',
    '\System\Processor Queue Length',
    '\System\Context Switches/sec',
    '\Processor Information(_Total)\Processor Frequency',
    '\Power\Percent Processor Performance',

    # ===== Disk Throughput & Latency =====
    '\PhysicalDisk(_Total)\Avg. Disk Queue Length',
    '\PhysicalDisk(_Total)\Disk Bytes/sec',
    '\PhysicalDisk(_Total)\Disk Transfers/sec',
    '\PhysicalDisk(_Total)\Avg. Disk sec/Read',
    '\PhysicalDisk(_Total)\Avg. Disk sec/Write',
    '\PhysicalDisk(_Total)\Split IO/Sec',
    '\PhysicalDisk(_Total)\% Idle Time',

    # ===== Memory Pressure =====
    '\Memory\Available MBytes',
    '\Memory\Pages/sec',
    '\Memory\% Committed Bytes In Use',
    '\Paging File(_Total)\% Usage',
    '\Memory\Cache Bytes',
    '\Memory\Cache Faults/sec',

    # ===== Network Health =====
    '\Network Interface(*)\Bytes Total/sec',
    '\Network Interface(*)\Output Queue Length',
    '\Network Interface(*)\Packets Outbound Errors',
    '\Network Interface(*)\Packets Received Errors',
    '\TCPv4\Segments Retransmitted/sec',

    # ===== System Object Usage =====
    '\System\Threads',
    '\System\Processes',
    '\Process(_Total)\Handle Count',

    # ===== Per-Process Attribution (CPU/RAM culprits) =====
    '\Process(*)\% Processor Time',
    '\Process(*)\Working Set - Private',
    '\Process(*)\Private Bytes',
    '\Process(*)\Handle Count',
    '\Process(*)\Thread Count',
    '\Process(*)\ID Process'

    # Optional I/O (enable if needed)
    # '\Process(*)\IO Data Bytes/sec'
)


# Clean up existing collector if present
if ((logman query $CollectorName 2>$null)) {
    logman stop $CollectorName -ets
    logman delete $CollectorName
}

# Sleep before creation to avoid timing issues
Write-Host "Waiting 15 seconds before creating collector..."
Start-Sleep -Seconds 15

# Create collector with all counters defined up front
logman create counter $CollectorName `
    -c $counters `
    -f csv `
    -o "$LogPath\$CollectorName" `
    -v mmddhhmm `
    -max $DurationSeconds `
    -si ${Interval} `
    -r


# Register autostart on boot
schtasks /Create /TN "$CollectorName" /TR "logman start $CollectorName" /SC ONLOGON /RU "SYSTEM" /RL HIGHEST /F


# Sleep after creation before starting
Write-Host "Waiting 15 seconds after creating collector..."
Start-Sleep -Seconds 15

# Start collection now
logman start $CollectorName

# --- Start the collector with retry logic ---
$maxAttempts = 3
$attempt = 1
$started = $false

while (-not $started -and $attempt -le $maxAttempts) {
    Write-Host "Attempt $attempt to start $CollectorName..."
    logman start $CollectorName | Out-Null
    Start-Sleep -Seconds 5

    # Verify if it's running
    $query = logman query $CollectorName 2>$null
    if ($query -match 'Status:\s+Running') {
        Write-Host "$CollectorName is running."
        $started = $true
    } else {
        Write-Warning "$CollectorName not detected as running. Retrying..."
        $attempt++
        Start-Sleep -Seconds 10
    }
}

if (-not $started) {
    Write-Error "Failed to start $CollectorName after $maxAttempts attempts."
    exit 1
}

# --- First wait for data collection ---
Write-Host "Waiting 1 minutes to allow log generation..."
Start-Sleep -Seconds 60

# --- First log file check ---
$logFile = Get-ChildItem -Path $LogPath -Filter "$CollectorName*.csv" | Sort-Object LastWriteTime -Descending | Select-Object -First 1

if (-not $logFile) {
    Write-Warning "No log file detected after 2 minutes. Attempting to restart the collector..."

    # Restart collector
    logman stop $CollectorName | Out-Null
    Start-Sleep -Seconds 10
    logman start $CollectorName | Out-Null

    Write-Host "Waiting another 2 minutes for log generation..."
    Start-Sleep -Seconds 120

    $logFile = Get-ChildItem -Path $LogPath -Filter "$CollectorName*.csv" | Sort-Object LastWriteTime -Descending | Select-Object -First 1

    if (-not $logFile) {
        Write-Error "Still no log file found in $LogPath. Collector may be misconfigured or lacking permissions."
        exit 2
    }
}

Write-Host "Log file found: $($logFile.Name)"
Write-Host "Perfmon collector '$CollectorName' is successfully running and writing to: $LogPath"
