<# 
.SYNOPSIS
  Trace AD account lockouts and likely causes for a user.

.DESCRIPTION
  1) Enumerates all DCs and pulls Security log events:
     - 4740 (Account lockout)
     - 4625 (Failed logon)
     Uses Get-WinEvent with fallback to wevtutil XML parsing when needed.
  2) Extracts CallerComputerName (source hosts).
  3) On each source host:
     - Pulls 4625s for the user (Get-WinEvent + wevtutil fallback).
     - Lists services and scheduled tasks running as the user.
  4) Exports CSVs and prints a concise console summary.

.PARAMETER User
  'DOMAIN\SamAccountName' or plain 'SamAccountName' (domain auto-detected if omitted)

.PARAMETER LookBackDays
  Days of event history to scan. Default: 30

.PARAMETER OutputFolder
  Folder for CSV exports. Default: "$env:USERPROFILE\Desktop\AD-Lockout-Report"

.EXAMPLE
  .\Trace-Lockouts.ps1 -User 'BrandyM' -LookBackDays 30 -Verbose
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)]
  [string]$User,

  [int]$LookBackDays = 30,

  [string]$OutputFolder = "$env:USERPROFILE\Desktop\AD-Lockout-Report"
)

# Ensure AD module (on DC this should be present)
try { Import-Module ActiveDirectory -ErrorAction Stop } catch { }

# ------------------------- Helpers -------------------------
function New-OutputFolder {
  if (!(Test-Path -LiteralPath $OutputFolder)) {
    New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null
  }
}

function Split-DomainUser {
  param([string]$DomainUser)

  if ($DomainUser -match '\\') {
    $parts = $DomainUser.Split('\',2)
    return [PSCustomObject]@{
      Domain = $parts[0]
      User   = $parts[1]
    }
  }

  # No backslash given; resolve from AD and current domain
  try {
    $adUser = Get-ADUser -Identity $DomainUser -Properties SamAccountName -ErrorAction Stop
  } catch {
    throw ("User '{0}' not found in AD. Try 'DOMAIN\{0}' or verify the username." -f $DomainUser)
  }

  $domain = (Get-ADDomain).NetBIOSName
  [PSCustomObject]@{
    Domain = $domain
    User   = $adUser.SamAccountName
  }
}

function Get-DCList {
  try {
    (Get-ADDomainController -Filter * -ErrorAction Stop).HostName
  } catch {
    throw ("Failed to enumerate Domain Controllers. Ensure RSAT/AD module is available and you have permission. {0}" -f $_)
  }
}

function Convert-ToSystemTimeUtc {
  param([datetime]$dt)
  # wevtutil wants Zulu with millisecond precision
  return ($dt.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.000Z"))
}

function Invoke-WevtutilQuery {
  param(
    [string]$ComputerName,
    [int]$EventId,
    [datetime]$StartTime
  )
  $sysTime = Convert-ToSystemTimeUtc $StartTime
  $xpath = "*[System[(EventID=$EventId) and TimeCreated[@SystemTime>='$sysTime']]]"
  $args = @('qe','Security','/q:'+$xpath,'/f:xml','/r:'+ $ComputerName,'/c:50000')
  $xmlText = & wevtutil @args 2>$null
  if (-not $xmlText) { return @() }

  $events = @()
  $chunks = ($xmlText -split '(?=<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event")') | Where-Object { $_.Trim() }
  foreach ($chunk in $chunks) {
    try {
      $x = [xml]$chunk
      $ed = @{}
      foreach ($d in $x.Event.EventData.Data) { $ed[$d.Name] = $d.'#text' }

      $events += [PSCustomObject]@{
        TimeCreated       = [datetime]$x.Event.System.TimeCreated.SystemTime
        EventId           = [int]$x.Event.System.EventID.'#text'
        TargetUserName    = $ed['TargetUserName']
        TargetDomainName  = $ed['TargetDomainName']
        CallerComputer    = $ed['CallerComputerName']
        IpAddress         = $ed['IpAddress']
        IpPort            = $ed['IpPort']
        LogonType         = $ed['LogonType']
        SubStatus         = $ed['SubStatus']
        FailureReason     = $ed['FailureReason']
        AuthenticationPkg = $ed['AuthenticationPackageName']
        Message           = $chunk
      }
    } catch { }
  }
  return $events
}

# ------------------------- Event Queries -------------------------
function Get-DCEvents {
  param(
    [string[]]$DCs,
    [string]$SamAccount,
    [datetime]$StartTime
  )
  Write-Verbose ("Querying DC Security logs for 4740 and 4625 since {0} ..." -f $StartTime)
  $results = @()

  foreach ($dc in $DCs) {
    Write-Verbose ("  DC: {0}" -f $dc)
    foreach ($id in 4740,4625) {
      $flt = @{ LogName='Security'; Id=$id; StartTime=$StartTime }
      $evts = @()

      # Try Get-WinEvent first
      try {
        $evts = Get-WinEvent -ComputerName $dc -FilterHashtable $flt -ErrorAction Stop
      } catch {
        Write-Verbose ("    Get-WinEvent failed on {0} for {1}, falling back to wevtutil. Error: {2}" -f $dc,$id,$_.Exception.Message)
        $evts = @()
      }

      if (-not $evts -or $evts.Count -eq 0) {
        # Fallback to wevtutil
        try {
          $wev = Invoke-WevtutilQuery -ComputerName $dc -EventId $id -StartTime $StartTime
          if ($wev) {
            foreach ($rec in $wev) {
              $tgt = $rec.TargetUserName
              $msgHit = $false
              if (-not $tgt) {
                $msgHit = ($rec.Message -match ("(?i)TargetUserName\s*:\s*{0}\b" -f [regex]::Escape($SamAccount)))
              }
              if (($tgt -and $tgt -ieq $SamAccount) -or $msgHit) {
                # Attach DC name for uniformity
                $results += [PSCustomObject]@{
                  TimeCreated       = $rec.TimeCreated
                  DC                = $dc
                  EventId           = $rec.EventId
                  TargetUserName    = $rec.TargetUserName
                  TargetDomainName  = $rec.TargetDomainName
                  CallerComputer    = $rec.CallerComputer
                  IpAddress         = $rec.IpAddress
                  IpPort            = $rec.IpPort
                  LogonType         = $rec.LogonType
                  SubStatus         = $rec.SubStatus
                  FailureReason     = $rec.FailureReason
                  AuthenticationPkg = $rec.AuthenticationPkg
                  Message           = $rec.Message
                }
              }
            }
          }
          continue
        } catch {
          Write-Warning ("    wevtutil also failed on {0} for {1}: {2}" -f $dc,$id,$_)
          continue
        }
      }

      # Parse Get-WinEvent XML
      foreach ($ev in $evts) {
        try {
          $xml  = [xml]$ev.ToXml()
          $data = @{}
          foreach ($d in $xml.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }

          $target = $data['TargetUserName']
          $msgHit = $false
          if (-not $target) {
            $msgHit = ($ev.Message -match ("(?i)TargetUserName\s*:\s*{0}\b" -f [regex]::Escape($SamAccount)))
          }
          if (($target -and $target -ieq $SamAccount) -or $msgHit) {
            $results += [PSCustomObject]@{
              TimeCreated       = $ev.TimeCreated
              DC                = $dc
              EventId           = $ev.Id
              TargetUserName    = $data['TargetUserName']
              TargetDomainName  = $data['TargetDomainName']
              CallerComputer    = $data['CallerComputerName']
              IpAddress         = $data['IpAddress']
              IpPort            = $data['IpPort']
              LogonType         = $data['LogonType']
              SubStatus         = $data['SubStatus']
              FailureReason     = $data['FailureReason']
              AuthenticationPkg = $data['AuthenticationPackageName']
              Message           = $ev.Message
            }
          }
        } catch { }
      }
    }
  }
  $results | Sort-Object TimeCreated
}

function Get-Remote4625ForUser {
  param(
    [string[]]$Computers,
    [string]$SamAccount,
    [datetime]$StartTime
  )
  $rows = @()
  foreach ($comp in $Computers | Where-Object { $_ -and $_ -ne '-' } | Select-Object -Unique) {
    Write-Verbose ("  Querying 4625 on source computer: {0}" -f $comp)

    $evts = @()
    try {
      $evts = Get-WinEvent -ComputerName $comp -FilterHashtable @{LogName='Security'; Id=4625; StartTime=$StartTime} -ErrorAction Stop
    } catch {
      Write-Verbose ("    Get-WinEvent failed on {0} (4625), falling back to wevtutil. Error: {1}" -f $comp,$_.Exception.Message)
      $evts = @()
    }

    if (-not $evts -or $evts.Count -eq 0) {
      try {
        $wev = Invoke-WevtutilQuery -ComputerName $comp -EventId 4625 -StartTime $StartTime
        foreach ($rec in $wev) {
          $tgt = $rec.TargetUserName
          $msgHit = $false
          if (-not $tgt) {
            $msgHit = ($rec.Message -match ("(?i)TargetUserName\s*:\s*{0}\b" -f [regex]::Escape($SamAccount)))
          }
          if (($tgt -and $tgt -ieq $SamAccount) -or $msgHit) {
            $rows += [PSCustomObject]@{
              TimeCreated       = $rec.TimeCreated
              Computer          = $comp
              EventId           = 4625
              TargetUserName    = $rec.TargetUserName
              IpAddress         = $rec.IpAddress
              LogonType         = $rec.LogonType
              SubStatus         = $rec.SubStatus
              FailureReason     = $rec.FailureReason
              AuthenticationPkg = $rec.AuthenticationPkg
              ProcessName       = $null
              Message           = $rec.Message
            }
          }
        }
        continue
      } catch {
        Write-Warning ("    wevtutil also failed on {0} (4625): {1}" -f $comp,$_)
        continue
      }
    }

    foreach ($ev in $evts) {
      try {
        $xml  = [xml]$ev.ToXml()
        $data = @{}
        foreach ($d in $xml.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }

        $target = $data['TargetUserName']
        $msgHit = $false
        if (-not $target) {
          $msgHit = ($ev.Message -match ("(?i)TargetUserName\s*:\s*{0}\b" -f [regex]::Escape($SamAccount)))
        }

        if (($target -and $target -ieq $SamAccount) -or $msgHit) {
          $rows += [PSCustomObject]@{
            TimeCreated       = $ev.TimeCreated
            Computer          = $comp
            EventId           = 4625
            TargetUserName    = $data['TargetUserName']
            IpAddress         = $data['IpAddress']
            LogonType         = $data['LogonType']
            SubStatus         = $data['SubStatus']
            FailureReason     = $data['FailureReason']
            AuthenticationPkg = $data['AuthenticationPackageName']
            ProcessName       = $data['ProcessName']
            Message           = $ev.Message
          }
        }
      } catch { }
    }
  }
  $rows | Sort-Object TimeCreated
}

# ------------------------- Inventory (services & tasks) -------------------------
function Get-ServicesAndTasksForUser {
  param(
    [string]$DomainUser,      # DOMAIN\user
    [string[]]$Computers
  )
  $svcRows = @()
  $taskRows = @()

  foreach ($comp in $Computers | Where-Object { $_ } | Select-Object -Unique) {
    Write-Verbose ("  Inspecting services & scheduled tasks on: {0}" -f $comp)

    # Services
    try {
      $svcs = Get-CimInstance -ClassName Win32_Service -ComputerName $comp -ErrorAction Stop |
        Where-Object { $_.StartName -ieq $DomainUser }
      foreach ($s in $svcs) {
        $svcRows += [PSCustomObject]@{
          Computer  = $comp
          Type      = 'Service'
          Name      = $s.Name
          Display   = $s.DisplayName
          StartMode = $s.StartMode
          State     = $s.State
          StartName = $s.StartName
        }
      }
    } catch {
      Write-Warning ("    Could not query services on {0}: {1}" -f $comp,$_)
    }

    # Scheduled Tasks
    try {
      $session = New-CimSession -ComputerName $comp -ErrorAction Stop
      $tasks = Get-ScheduledTask -CimSession $session -ErrorAction Stop |
        Where-Object { $_.Principal.UserId -ieq $DomainUser }
      foreach ($t in $tasks) {
        $taskRows += [PSCustomObject]@{
          Computer  = $comp
          Type      = 'ScheduledTask'
          Name      = $t.TaskName
          Path      = $t.TaskPath
          UserId    = $t.Principal.UserId
          RunLevel  = $t.Principal.RunLevel
          State     = (Get-ScheduledTaskInfo -TaskName $t.TaskName -TaskPath $t.TaskPath -CimSession $session -ErrorAction SilentlyContinue).State
        }
      }
      Remove-CimSession $session
    } catch {
      Write-Warning ("    Could not query scheduled tasks on {0}: {1}" -f $comp,$_)
    }
  }

  [PSCustomObject]@{
    Services = $svcRows
    Tasks    = $taskRows
  }
}

# ------------------------- Main -------------------------
try {
  New-OutputFolder

  $parsed     = Split-DomainUser -DomainUser $User
  $domain     = $parsed.Domain
  $sam        = $parsed.User
  $since      = (Get-Date).AddDays(-[math]::Abs($LookBackDays))
  $stamp      = (Get-Date -Format 'yyyyMMdd-HHmmss')

  Write-Host ("Tracing lockouts for {0}\{1} since {2} ..." -f $domain,$sam,$since) -ForegroundColor Cyan

  $dcs        = Get-DCList
  $dcEvents   = Get-DCEvents -DCs $dcs -SamAccount $sam -StartTime $since

  $dcOutFile  = Join-Path $OutputFolder ("DC-Events-{0}_{1}-{2}.csv" -f $domain,$sam,$stamp)
  $dcEvents | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $dcOutFile

  # Unique source computers (from 4740 primarily; also 4625 CallerComputer if present)
  $sourceComputers = @()
  $from4740 = $dcEvents | Where-Object { $_.EventId -eq 4740 -and $_.CallerComputer } | Select-Object -ExpandProperty CallerComputer -Unique
  if ($from4740) { $sourceComputers += $from4740 }

  $from4625 = $dcEvents | Where-Object { $_.EventId -eq 4625 -and $_.CallerComputer } | Select-Object -ExpandProperty CallerComputer -Unique
  if ($from4625) { $sourceComputers += $from4625 }

  $sourceComputers = $sourceComputers | Where-Object { $_ -and $_ -ne '-' } | Sort-Object -Unique
  if (-not $sourceComputers) {
    Write-Warning "No CallerComputerName values found on DCs. If lockouts are coming from mobile apps/cloud, you may need AAD/Entra Sign-In logs."
  } else {
    Write-Host ("Potential source computers: {0}" -f ($sourceComputers -join ', ')) -ForegroundColor Yellow
  }

  # Query those computers for local 4625s
  $host4625   = Get-Remote4625ForUser -Computers $sourceComputers -SamAccount $sam -StartTime $since
  $hostOut    = Join-Path $OutputFolder ("SourceHost-4625-{0}_{1}-{2}.csv" -f $domain,$sam,$stamp)
  $host4625 | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $hostOut

  # Query services & tasks running as the user
  $svcTask    = Get-ServicesAndTasksForUser -Computers $sourceComputers -DomainUser ("{0}\{1}" -f $domain,$sam)
  $svcOut     = Join-Path $OutputFolder ("Services-{0}_{1}-{2}.csv" -f $domain,$sam,$stamp)
  $taskOut    = Join-Path $OutputFolder ("ScheduledTasks-{0}_{1}-{2}.csv" -f $domain,$sam,$stamp)
  $svcTask.Services | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $svcOut
  $svcTask.Tasks    | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $taskOut

  # --------- Console Summary ---------
  Write-Host "`n==== SUMMARY ====" -ForegroundColor Green

  $lockoutSummary =
    $dcEvents |
    Where-Object { $_.EventId -eq 4740 } |
    Group-Object CallerComputer |
    ForEach-Object {
      [PSCustomObject]@{
        SourceComputer = $_.Name
        Lockouts       = $_.Count
        FirstSeen      = ($_.Group | Sort-Object TimeCreated | Select-Object -First 1 -ExpandProperty TimeCreated)
        LastSeen       = ($_.Group | Sort-Object TimeCreated | Select-Object -Last  1 -ExpandProperty TimeCreated)
      }
    } |
    Sort-Object -Property Lockouts -Descending

  if ($lockoutSummary) {
    $lockoutSummary | Format-Table -AutoSize
  } else {
    Write-Host "No 4740 lockouts found in the specified window." -ForegroundColor Yellow
  }

  Write-Host "`nTop failure patterns on source hosts (by SubStatus & LogonType):" -ForegroundColor Green
  $host4625 |
    Group-Object SubStatus, LogonType |
    Sort-Object Count -Descending |
    Select-Object Count, @{n='SubStatus';e={$_.Group[0].SubStatus}}, @{n='LogonType';e={$_.Group[0].LogonType}} |
    Format-Table -AutoSize

  if ($svcTask.Services.Count -or $svcTask.Tasks.Count) {
    Write-Host ("`nServices/Tasks found running as {0}:" -f ("{0}\{1}" -f $domain,$sam)) -ForegroundColor Green
    $svcTask.Services | Select-Object Computer,Type,Name,StartMode,State | Format-Table -AutoSize
    $svcTask.Tasks    | Select-Object Computer,Type,Path,Name,State | Format-Table -AutoSize
  } else {
    Write-Host "`nNo services or scheduled tasks found using the account on the source computers." -ForegroundColor Yellow
  }

  Write-Host "`nCSV outputs:" -ForegroundColor Cyan
  Write-Host ("  DC Events:        {0}" -f $dcOutFile)
  Write-Host ("  Source 4625s:     {0}" -f $hostOut)
  Write-Host ("  Services:         {0}" -f $svcOut)
  Write-Host ("  Scheduled Tasks:  {0}" -f $taskOut)

  Write-Host "`nTip: SubStatus 0xC000006A = bad password; 0xC0000234 = locked; 0xC000006D = bad creds; LogonType 5=Service, 4=Batch (task), 3=Network (mapped drive), 2=Interactive." -ForegroundColor DarkCyan

} catch {
  Write-Error $_
}
