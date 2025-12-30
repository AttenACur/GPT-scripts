<#
.SYNOPSIS
  Export the 5 primary Windows event logs to CSV files named "<PC>_<Log>.csv".

.DESCRIPTION
  Exports: Application, Security, System, Setup, ForwardedEvents.
  Requires elevation to read Security (and sometimes ForwardedEvents).
  Use -OutputFolder to choose where CSVs are written (defaults to current directory).
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputFolder = (Get-Location).Path,

    # Optional: cap the number of newest events per log (omit or set $null for ALL).
    [Parameter(Mandatory=$false)]
    [Nullable[int]]$MaxEvents = $null
)

# Ensure output directory exists
if (-not (Test-Path -LiteralPath $OutputFolder)) {
    New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
}

$pc=$env:COMPUTERNAME
$logs = @(
    'System'
    'Application'
	#'Setup'
    'Microsoft-Windows-WindowsUpdateClient/Operational'
    #'Microsoft-Windows-Servicing'
    #'Microsoft-Windows-Setup/Operational'
	#'Microsoft-Windows-Winlogon/Operational'
	#'Microsoft-Windows-User Device Registration/Admin'
	#'Microsoft-Windows-TPM/Operational'
    #'Microsoft-Windows-Diagnostics-Performance/Operational'
	#'Microsoft-Windows-GroupPolicy/Operational'
	#'Microsoft-Windows-Netlogon / Operational'
	#'Microsoft-Windows-Kernel-Boot'
	#'Microsoft-Windows-Kernel-General'
    #'Security'
)
# Used this line if you want to pull all logs
# $logs = @('Application','Security','System','Setup','ForwardedEvents')

# Check for elevation (needed for Security log on most systems)
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$IsAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsAdmin) {
    Write-Warning "Not running elevated. Reading the Security log (and sometimes ForwardedEvents) may fail or return partial data."
}

foreach ($log in $logs) {
    try {
        # Confirm the log exists on this system
        $logInfo = Get-WinEvent -ListLog $log -ErrorAction Stop

		#Build a safe filename from the log name (avoid / creating subfolders)
		$safeLog = $log -replace '[\\/:*?"<>|]', '-'   # replace invalid filename chars, incl. /

		$outPath = Join-Path -Path $OutputFolder -ChildPath ("{0}_{1}.csv" -f $pc, $safeLog)


        Write-Host "Exporting '$log' -> $outPath ..."

        # Pull events (optionally capped), selecting useful columns
        $events =
            if ($MaxEvents -gt 0) {
                # Newest first for speed, then export
                Get-WinEvent -LogName $log -ErrorAction Stop -MaxEvents $MaxEvents
            } else {
                Get-WinEvent -LogName $log -ErrorAction Stop
            }

        $events |
            Select-Object `
                TimeCreated,
                Id,
                LevelDisplayName,
                ProviderName,
                MachineName,
                LogName,
                RecordId,
                TaskDisplayName,
                OpcodeDisplayName,
                ActivityId,
                RelatedActivityId,
                ProcessId,
                ThreadId,
                @{n='Keywords'; e={ $_.KeywordsDisplayNames -join '; ' }},
                Message |
            Export-Csv -Path $outPath -NoTypeInformation -Encoding UTF8

        Write-Host "Done: $outPath"
    }
    catch {
        Write-Warning "Failed to export log '$log': $($_.Exception.Message)"
    }
}

Write-Host "All requested exports attempted. Files are in: $OutputFolder"