<# 
================================================================================
Trace-Lockouts.ps1
================================================================================
Purpose:
  End-to-end triage for AD account lockouts, with optional Entra ID (Azure AD)
  sign-in failure pull via Microsoft Graph.

Parameters & Switches:
  -User <string>                REQUIRED. 'DOMAIN\SamAccountName' OR 'SamAccountName'
  -LookBackDays <int>           Days of log history to scan. Default: 30
  -OutputFolder <string>        Output folder for CSVs. Default: "$env:USERPROFILE\Desktop\AD-Lockout-Report"
  -IncludeAAD                   Also pull Entra (Azure AD) sign-in FAILURES via Microsoft Graph
  -UserPrincipalName <string>   REQUIRED with -IncludeAAD (e.g. brandym@htipolymer.com)
  -Help                         Show usage and exit

What it does:
  1) Queries DC Security logs (PDC first) for 4740 (lockout) & 4625 (failed logon)
     - Uses Get-WinEvent; falls back to wevtutil XML parsing if needed
  2) Extracts CallerComputerName; checks those hosts for 4625
  3) On source hosts: lists Windows Services & Scheduled Tasks running as the user
  4) Exports CSVs; prints concise console summary
  5) Optional: Queries Entra ID sign-in failures (Microsoft Graph)

CSV Outputs:
  DC-Events-<DOMAIN>_<user>-<timestamp>.csv
  DC-Auditing-<timestamp>.csv
  SourceHost-4625-<DOMAIN>_<user>-<timestamp>.csv
  Services-<DOMAIN>_<user>-<timestamp>.csv
  ScheduledTasks-<DOMAIN>_<user>-<timestamp>.csv
  (Optional) AAD-SignInFailures-<user>-<timestamp>.csv

Examples:
  .\Trace-Lockouts.ps1 -User 'BrandyM' -LookBackDays 30 -Verbose
  .\Trace-Lockouts.ps1 -User 'HTIPOLYMER\BrandyM' -IncludeAAD -UserPrincipalName 'brandym@htipolymer.com' -Verbose
  .\Trace-Lockouts.ps1 -Help

Tip:
  SubStatus 0xC000006A = bad password; 0xC0000234 = locked; 0xC000006D = bad creds
  LogonType 5=Service, 4=Batch (task), 3=Network (mapped drive), 2=Interactive
================================================================================
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$true, HelpMessage="DOMAIN\SamAccountName or SamAccountName")]
  [string]$User,

  [int]$LookBackDays = 30,

  [string]$OutputFolder = "$env:USERPROFILE\Desktop\AD-Lockout-Report",

  [switch]$IncludeAAD,

  [string]$UserPrincipalName,

  [switch]$Help
)

# ------------------------- Usage -------------------------
function Show-Usage {
  $usage = @"
Trace-Lockouts.ps1 - Trace AD/Entra lockouts

PARAMS:
  -User <string>                REQUIRED. 'DOMAIN\SamAccountName' OR 'SamAccountName'
  -LookBackDays <int>           Days of history (default 30)
  -OutputFolder <string>        Output folder (default Desktop\AD-Lockout-Report)
  -IncludeAAD                   Include Entra (Azure AD) sign-in failures (requires Microsoft Graph)
  -UserPrincipalName <string>   REQUIRED when -IncludeAAD (e.g. brandym@htipolymer.com)
  -Help                         Show this usage and exit

EXAMPLES:
  .\Trace-Lockouts.ps1 -User 'BrandyM' -LookBackDays 30 -Verbose
  .\Trace-Lockouts.ps1 -User 'HTIPOLYMER\BrandyM' -IncludeAAD -UserPrincipalName 'brandym@htipolymer.com' -Verbose
"@
  Write-Host $usage -ForegroundColor Cyan
}

if ($Help) { Show-Usage; return }

# Ensure AD module
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
    return [PSCustomObject]@{ Domain = $parts[0]; User = $parts[1] }
  }
  try {
    $adUser = Get-ADUser -Identity $DomainUser -Properties SamAccountName -ErrorAction Stop
  } catch {
    throw ("User '{0}' not found in AD. Try 'DOMAIN\{0}' or verify the username." -f $DomainUser)
  }
  $domain = (Get-ADDomain).NetBIOSName
  [PSCustomObject]@{ Domain = $domain; User = $adUser.SamAccountName }
}

function Get-DCListPrioritizingPDC {
  try {
    $d       = Get-ADDomain
    $pdcFqdn = $d.PDCEmulator
    $pdc     = (Get-ADDomainController -Identity $pdcFqdn).HostName
    $all     = (Get-ADDomainController -Filter *).HostName
    $ordered = @()
    if ($pdc) { $ordered += $pdc }
    $ordered += ($all | Where-Object { $_ -ne $pdc } | Sort-Object)
    return $ordered
  } catch {
    throw ("Failed to enumerate Domain Controllers. {0}" -f $_)
  }
}

function Convert-ToSystemTimeUtc {
  param([datetime]$dt)
  $dt.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.000Z")
}

function Invoke-WevtutilQuery {
  param(
    [string]$ComputerName,
    [int]$EventId,
    [datetime]$StartTime
  )
  $sysTime = Convert-ToSystemTimeUtc $StartTime
  $xpath   = "*[System[(EventID=$EventId) and TimeCreated[@SystemTime>='$sysTime']]]"
  $args    = @('qe','Security','/q:'+$xpath,'/f:xml','/r:'+ $ComputerName,'/c:50000')
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
  $events
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
      try {
        $evts = Get-WinEvent -ComputerName $dc -FilterHashtable $flt -ErrorAction Stop
      } catch {
        Write-Verbose ("    Get-WinEvent failed on {0} for {1}, falling back to wevtutil. Error: {2}" -f $dc,$id,$_.Exception.Message)
        $evts = @()
      }

      if (-not $evts -or $evts.Count -eq 0) {
        try {
          $wev = Invoke-WevtutilQuery -ComputerName $dc -EventId $id -StartTime $StartTime
          foreach ($rec in $wev) {
            $tgt = $rec.TargetUserName
            $msgHit = $false
            if (-not $tgt) { $msgHit = ($rec.Message -match ("(?i)TargetUserName\s*:\s*{0}\b" -f [regex]::Escape($SamAccount))) }
            if (($tgt -and $tgt -ieq $SamAccount) -or $msgHit) {
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
          continue
        } catch {
          Write-Warning ("    wevtutil also failed on {0} for {1}: {2}" -f $dc,$id,$_)
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
          if (-not $target) { $msgHit = ($ev.Message -match ("(?i)TargetUserName\s*:\s*{0}\b" -f [regex]::Escape($SamAccount))) }
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
          if (-not $tgt) { $msgHit = ($rec.Message -match ("(?i)TargetUserName\s*:\s*{0}\b" -f [regex]::Escape($SamAccount))) }
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
        if (-not $target) { $msgHit = ($ev.Message -match ("(?i)TargetUserName\s*:\s*{0}\b" -f [regex]::Escape($SamAccount))) }
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

# ------------------------- Auditing Health -------------------------
function Get-AuditPolicySummary {
  param([string[]]$DCs)
  $subs = @(
    'Account Lockout',
    'Logon',
    'Account Logon',
    'Credential Validation',
    'Kerberos Authentication Service',
    'Kerberos Service Ticket Operations'
  )
  $rows = @()
  foreach ($dc in $DCs) {
    foreach ($s in $subs) {
      try {
        $out = Invoke-Command -ComputerName $dc -ScriptBlock { param($sub) auditpol /get /subcategory:$sub } -ArgumentList $s -ErrorAction Stop
        $rows += [PSCustomObject]@{
          DC     = $dc
          Subcat = $s
          Raw    = ($out -join ' ')
        }
      } catch {
        $rows += [PSCustomObject]@{ DC=$dc; Subcat=$s; Raw="auditpol query failed: $($_.Exception.Message)" }
      }
    }
  }
  $rows
}

# ------------------------- Services/Tasks -------------------------
function Get-ServicesAndTasksForUser {
  param([string]$DomainUser, [string[]]$Computers)
  $svcRows = @()
  $taskRows = @()
  foreach ($comp in $Computers | Where-Object { $_ } | Select-Object -Unique) {
    Write-Verbose ("  Inspecting services & scheduled tasks on: {0}" -f $comp)
    try {
      $svcs = Get-CimInstance -ClassName Win32_Service -ComputerName $comp -ErrorAction Stop |
        Where-Object { $_.StartName -ieq $DomainUser }
      foreach ($s in $svcs) {
        $svcRows += [PSCustomObject]@{
          Computer=$comp; Type='Service'; Name=$s.Name; Display=$s.DisplayName; StartMode=$s.StartMode; State=$s.State; StartName=$s.StartName
        }
      }
    } catch { Write-Warning ("    Could not query services on {0}: {1}" -f $comp,$_) }
    try {
      $session = New-CimSession -ComputerName $comp -ErrorAction Stop
      $tasks = Get-ScheduledTask -CimSession $session -ErrorAction Stop | Where-Object { $_.Principal.UserId -ieq $DomainUser }
      foreach ($t in $tasks) {
        $taskRows += [PSCustomObject]@{
          Computer=$comp; Type='ScheduledTask'; Name=$t.TaskName; Path=$t.TaskPath; UserId=$t.Principal.UserId; 
          RunLevel=$t.Principal.RunLevel; State=(Get-ScheduledTaskInfo -TaskName $t.TaskName -TaskPath $t.TaskPath -CimSession $session -ErrorAction SilentlyContinue).State
        }
      }
      Remove-CimSession $session
    } catch { Write-Warning ("    Could not query scheduled tasks on {0}: {1}" -f $comp,$_) }
  }
  [PSCustomObject]@{ Services=$svcRows; Tasks=$taskRows }
}

# ------------------------- Entra ID (Graph) -------------------------
function Ensure-GraphModules {
  # Install/Import only when -IncludeAAD is used
  # Prefer TLS1.2 for PowerShellGet
  try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.ServicePointManager]::SecurityProtocol } catch {}
  # Ensure PSGallery is trusted (best effort)
  try { $repo = Get-PSRepository -Name 'PSGallery' -ErrorAction Stop; if ($repo.InstallationPolicy -ne 'Trusted') { Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted -ErrorAction SilentlyContinue } } catch {}
  $needed = @('Microsoft.Graph.Authentication','Microsoft.Graph.Beta.Reports','Microsoft.Graph.Reports')
  foreach ($m in $needed) {
    if (-not (Get-Module -ListAvailable -Name $m)) {
      try { Install-Module $m -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop } catch { Write-Warning ("    Failed to install {0}: {1}" -f $m,$_.Exception.Message) }
    }
  }
  foreach ($m in $needed) {
    try { Import-Module $m -ErrorAction Stop } catch { Write-Warning ("    Failed to import {0}: {1}" -f $m,$_.Exception.Message) }
  }
}

function Get-AADSignInFailures {
  param([string]$UserPrincipalName, [datetime]$StartTime)
  Ensure-GraphModules
  if (-not (Get-MgContext)) { 
    try { Connect-MgGraph -Scopes "AuditLog.Read.All","Directory.Read.All" | Out-Null } catch { Write-Warning ("    Connect-MgGraph failed: {0}" -f $_.Exception.Message); return @() }
    try { Select-MgProfile -Name "beta" } catch { }
  }
  $startIso = $StartTime.ToUniversalTime().ToString("o")
  $filter   = "userPrincipalName eq '$UserPrincipalName' and createdDateTime ge $startIso"
  $records = @()
  try { $records = Get-MgBetaAuditLogSignIn -All -Filter $filter } catch {
    try { $records = Get-MgAuditLogSignIn -All -Filter $filter } catch { Write-Warning ("    Microsoft Graph sign-in query failed: {0}" -f $_.Exception.Message); return @() }
  }
  $records | Where-Object { $_.Status.ErrorCode -ne 0 } | ForEach-Object {
    [PSCustomObject]@{
      CreatedDateTime = $_.CreatedDateTime
      AppDisplayName  = $_.AppDisplayName
      ClientAppUsed   = $_.ClientAppUsed
      IPAddress       = $_.IpAddress
      Location        = ($_.Location.City + ', ' + $_.Location.State + ', ' + $_.Location.CountryOrRegion)
      FailureReason   = $_.Status.FailureReason
      ErrorCode       = $_.Status.ErrorCode
      ConditionalAccessStatus = $_.ConditionalAccessStatus
      DeviceDetail    = $_.DeviceDetail.DisplayName
      OS              = $_.DeviceDetail.OperatingSystem
      Browser         = $_.DeviceDetail.Browser
      AuthenticationRequirement = $_.AuthenticationRequirement
      CorrelationId   = $_.CorrelationId
    }
  }
}

# ------------------------- Main -------------------------
try {
  if ($IncludeAAD -and [string]::IsNullOrWhiteSpace($UserPrincipalName)) {
    Show-Usage
    throw "When using -IncludeAAD you must supply -UserPrincipalName (e.g., brandym@htipolymer.com)."
  }

  New-OutputFolder

  $parsed     = Split-DomainUser -DomainUser $User
  $domain     = $parsed.Domain
  $sam        = $parsed.User
  $since      = (Get-Date).AddDays(-[math]::Abs($LookBackDays))
  $stamp      = (Get-Date -Format 'yyyyMMdd-HHmmss')

  Write-Host ("Tracing lockouts for {0}\{1} since {2} ..." -f $domain,$sam,$since) -ForegroundColor Cyan

  $dcs        = Get-DCListPrioritizingPDC
  $dcEvents   = Get-DCEvents -DCs $dcs -SamAccount $sam -StartTime $since
  $auditRows  = Get-AuditPolicySummary -DCs $dcs

  $dcOutFile  = Join-Path $OutputFolder ("DC-Events-{0}_{1}-{2}.csv" -f $domain,$sam,$stamp)
  $auditOut   = Join-Path $OutputFolder ("DC-Auditing-{0}-{1}.csv" -f $domain,$stamp)
  $dcEvents  | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $dcOutFile
  $auditRows | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $auditOut

  # Determine source computers
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

  # Host 4625s
  $host4625   = Get-Remote4625ForUser -Computers $sourceComputers -SamAccount $sam -StartTime $since
  $hostOut    = Join-Path $OutputFolder ("SourceHost-4625-{0}_{1}-{2}.csv" -f $domain,$sam,$stamp)
  $host4625 | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $hostOut

  # Services & tasks
  $svcTask    = Get-ServicesAndTasksForUser -Computers $sourceComputers -DomainUser ("{0}\{1}" -f $domain,$sam)
  $svcOut     = Join-Path $OutputFolder ("Services-{0}_{1}-{2}.csv" -f $domain,$sam,$stamp)
  $taskOut    = Join-Path $OutputFolder ("ScheduledTasks-{0}_{1}-{2}.csv" -f $domain,$sam,$stamp)
  $svcTask.Services | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $svcOut
  $svcTask.Tasks    | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $taskOut

  # AAD (optional)
  $aadOut = $null
  if ($IncludeAAD) {
    Write-Host ("Querying Entra ID sign-in failures for {0} since {1} ..." -f $UserPrincipalName,$since) -ForegroundColor Cyan
    $aadFails = Get-AADSignInFailures -UserPrincipalName $UserPrincipalName -StartTime $since
    $aadOut   = Join-Path $OutputFolder ("AAD-SignInFailures-{0}-{1}.csv" -f $sam,$stamp)
    $aadFails | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $aadOut
  }

  # --------- Console Summary ---------
  Write-Host "`n==== SUMMARY ====" -ForegroundColor Green
  $lockoutSummary =
    $dcEvents | Where-Object { $_.EventId -eq 4740 } |
    Group-Object CallerComputer |
    ForEach-Object {
      [PSCustomObject]@{
        SourceComputer = $_.Name
        Lockouts       = $_.Count
        FirstSeen      = ($_.Group | Sort-Object TimeCreated | Select-Object -First 1 -ExpandProperty TimeCreated)
        LastSeen       = ($_.Group | Sort-Object TimeCreated | Select-Object -Last  1 -ExpandProperty TimeCreated)
      }
    } | Sort-Object -Property Lockouts -Descending

  if ($lockoutSummary) { $lockoutSummary | Format-Table -AutoSize }
  else { Write-Host "No 4740 lockouts found in the specified window." -ForegroundColor Yellow }

  Write-Host "`nTop failure patterns on source hosts (by SubStatus & LogonType):" -ForegroundColor Green
  $host4625 |
    Group-Object SubStatus, LogonType |
    Sort-Object Count -Descending |
    Select-Object Count, @{n='SubStatus';e={$_.Group[0].SubStatus}}, @{n='LogonType';e={$_.Group[0].LogonType}} |
    Format-Table -AutoSize

  if ($IncludeAAD -and $aadOut) {
    Write-Host ("`nAAD/Entra sign-in failures exported to: {0}" -f $aadOut) -ForegroundColor Yellow
  }

  if ($svcTask.Services.Count -or $svcTask.Tasks.Count) {
    Write-Host ("`nServices/Tasks found running as {0}:" -f ("{0}\{1}" -f $domain,$sam)) -ForegroundColor Green
    $svcTask.Services | Select-Object Computer,Type,Name,StartMode,State | Format-Table -AutoSize
    $svcTask.Tasks    | Select-Object Computer,Type,Path,Name,State | Format-Table -AutoSize
  } else {
    Write-Host "`nNo services or scheduled tasks found using the account on the source computers." -ForegroundColor Yellow
  }

  Write-Host "`nCSV outputs:" -ForegroundColor Cyan
  Write-Host ("  DC Events:        {0}" -f $dcOutFile)
  Write-Host ("  DC Auditing:      {0}" -f $auditOut)
  Write-Host ("  Source 4625s:     {0}" -f $hostOut)
  Write-Host ("  Services:         {0}" -f $svcOut)
  Write-Host ("  Scheduled Tasks:  {0}" -f $taskOut)

} catch {
  Write-Error $_
}
