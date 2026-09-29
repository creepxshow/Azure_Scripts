<#
.SYNOPSIS
    Read-only audit of Azure Recovery Services vaults and backup coverage.

.DESCRIPTION
    Scans every Recovery Services vault you can see and checks it against common
    backup security and reliability practices:

      - Soft delete (and whether it is set to always-on)
      - Immutability
      - Multi-user authorization (Resource Guard)
      - Storage redundancy and cross-region restore
      - Azure Monitor alerts for backup job failures
      - Public network access
      - Diagnostic data sent to Log Analytics
      - Daily retention below a minimum
      - Protected items whose last backup failed or is stale
      - Protected items where protection is stopped or paused
      - Virtual machines with no backup at all

    Results are printed as a score per vault plus a prioritized fix list, and can
    optionally be exported to CSV.

    THIS SCRIPT IS READ-ONLY. It only runs Get-* and Search-AzGraph calls and never
    changes anything. The Reader role on the target subscriptions is enough.

.PARAMETER SubscriptionId
    One or more subscription IDs to scan. Defaults to every enabled subscription in
    the current tenant.

.PARAMETER StaleHours
    A protected item whose last backup is older than this is flagged. Default 48.

.PARAMETER MinDailyRetentionDays
    Daily retention below this many days is flagged. Default 14.

.PARAMETER CsvPath
    Optional path to export all findings as CSV.

.EXAMPLE
    Connect-AzAccount
    ./Invoke-AzBackupAudit.ps1

.EXAMPLE
    ./Invoke-AzBackupAudit.ps1 -SubscriptionId 00000000-0000-0000-0000-000000000000 -CsvPath ./audit.csv

.NOTES
    Requires: Az.Accounts, Az.ResourceGraph. Optional: Az.Monitor (diagnostics check).
    Install:  Install-Module Az.Accounts, Az.ResourceGraph, Az.Monitor -Scope CurrentUser

    Azure property names can change between API versions. Anything the script can't
    read is reported as "Not reported" rather than guessed. Test in a non-production
    subscription first and verify findings in the portal before acting on them.

    License: MIT. Provided as-is, without warranty.
#>

[CmdletBinding()]
param(
    [string[]]$SubscriptionId,
    [int]$StaleHours = 48,
    [int]$MinDailyRetentionDays = 14,
    [string]$CsvPath
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

foreach ($module in @('Az.Accounts', 'Az.ResourceGraph')) {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        throw "Module '$module' is missing. Install it with: Install-Module $module -Scope CurrentUser"
    }
}
Import-Module Az.Accounts, Az.ResourceGraph -ErrorAction Stop

$context = Get-AzContext
if (-not $context) {
    throw "Not signed in. Run Connect-AzAccount first."
}

if (-not $SubscriptionId) {
    $SubscriptionId = @(Get-AzSubscription -TenantId $context.Tenant.Id -WarningAction SilentlyContinue |
        Where-Object { $_.State -eq 'Enabled' } |
        Select-Object -ExpandProperty Id)
}
if (-not $SubscriptionId -or $SubscriptionId.Count -eq 0) {
    throw "No enabled subscriptions found for this account."
}

$hasMonitor = [bool](Get-Module -ListAvailable -Name Az.Monitor)
if ($hasMonitor) { Import-Module Az.Monitor -ErrorAction SilentlyContinue }

$findings = New-Object System.Collections.Generic.List[object]

function Add-Finding {
    param(
        [string]$Scope,
        [string]$Subscription,
        [string]$Check,
        [ValidateSet('Pass', 'Warn', 'Fail', 'Info')][string]$Status,
        [string]$Detail,
        [string]$Recommendation = ''
    )
    $findings.Add([pscustomobject]@{
        Scope          = $Scope
        Subscription   = $Subscription
        Check          = $Check
        Status         = $Status
        Detail         = $Detail
        Recommendation = $Recommendation
    })
}

function Invoke-GraphQuery {
    param([string]$Query)
    $rows = New-Object System.Collections.Generic.List[object]
    # Resource Graph accepts up to 1000 subscriptions per call.
    for ($i = 0; $i -lt $SubscriptionId.Count; $i += 1000) {
        $last = [Math]::Min($i + 999, $SubscriptionId.Count - 1)
        $batch = $SubscriptionId[$i..$last]
        $skipToken = $null
        do {
            $params = @{ Query = $Query; First = 1000; Subscription = $batch }
            if ($skipToken) { $params['SkipToken'] = $skipToken }
            $response = Search-AzGraph @params
            $data = $null
            if ($response.PSObject.Properties.Name -contains 'Data') { $data = $response.Data } else { $data = $response }
            foreach ($row in @($data)) { if ($null -ne $row) { $rows.Add($row) } }
            $skipToken = $null
            if ($response.PSObject.Properties.Name -contains 'SkipToken') { $skipToken = $response.SkipToken }
        } while ($skipToken)
    }
    return , $rows
}

function Show-Value {
    param($Value)
    if ([string]::IsNullOrWhiteSpace([string]$Value)) { return 'Not reported' }
    return [string]$Value
}

# ---------------------------------------------------------------------------
# Queries (Azure Resource Graph, read-only)
# ---------------------------------------------------------------------------

$vaultQuery = @"
resources
| where type =~ 'microsoft.recoveryservices/vaults'
| project id = tolower(id), name, resourceGroup, subscriptionId, location,
    softDelete = tostring(properties.securitySettings.softDeleteSettings.softDeleteState),
    immutability = tostring(properties.securitySettings.immutabilitySettings.state),
    mua = tostring(properties.securitySettings.multiUserAuthorization),
    redundancy = tostring(properties.redundancySettings.standardTierStorageRedundancy),
    crossRegionRestore = tostring(properties.redundancySettings.crossRegionRestore),
    jobFailureAlerts = tostring(properties.monitoringSettings.azureMonitorAlertSettings.alertsForAllJobFailures),
    publicNetworkAccess = tostring(properties.publicNetworkAccess)
"@

$itemQuery = @"
recoveryservicesresources
| where type =~ 'microsoft.recoveryservices/vaults/backupfabrics/protectioncontainers/protecteditems'
| extend vaultId = tolower(strcat_array(array_slice(split(id, '/'), 0, 8), '/'))
| project vaultId,
    itemName = tostring(properties.friendlyName),
    workloadType = tostring(properties.workloadType),
    sourceId = tolower(coalesce(tostring(properties.sourceResourceId), tostring(properties.dataSourceInfo.resourceID))),
    protectionState = tostring(properties.protectionState),
    lastBackupStatus = tostring(properties.lastBackupStatus),
    lastBackupTime = tostring(properties.lastBackupTime)
"@

$policyQuery = @"
recoveryservicesresources
| where type =~ 'microsoft.recoveryservices/vaults/backuppolicies'
| extend vaultId = tolower(strcat_array(array_slice(split(id, '/'), 0, 8), '/'))
| project vaultId, policyName = name,
    dailyRetention = toint(properties.retentionPolicy.dailySchedule.retentionDuration.count)
"@

$vmQuery = @"
resources
| where type =~ 'microsoft.compute/virtualmachines'
| project id = tolower(id), name, resourceGroup, subscriptionId
"@

Write-Host "Scanning $($SubscriptionId.Count) subscription(s)..." -ForegroundColor Cyan

$vaults   = Invoke-GraphQuery -Query $vaultQuery
$items    = Invoke-GraphQuery -Query $itemQuery
$vms      = Invoke-GraphQuery -Query $vmQuery
$policies = New-Object System.Collections.Generic.List[object]
try { $policies = Invoke-GraphQuery -Query $policyQuery } catch { Write-Verbose "Policy query not available: $_" }

Write-Host ("Found {0} vault(s), {1} protected item(s), {2} VM(s)." -f $vaults.Count, $items.Count, $vms.Count) -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# Vault checks
# ---------------------------------------------------------------------------

foreach ($v in $vaults) {
    $scope = "$($v.name) ($($v.resourceGroup))"
    $sub = $v.subscriptionId

    # Soft delete
    switch -Regex ([string]$v.softDelete) {
        '^AlwaysON$' { Add-Finding $scope $sub 'Soft delete' 'Pass' 'Always-on (cannot be disabled)' }
        '^Enabled$'  { Add-Finding $scope $sub 'Soft delete' 'Warn' 'Enabled, but can still be turned off' 'Set soft delete to always-on so an attacker with vault access cannot disable it.' }
        '^Disabled$' { Add-Finding $scope $sub 'Soft delete' 'Fail' 'Disabled' 'Enable soft delete (ideally always-on). Deleted backups are otherwise unrecoverable.' }
        default      { Add-Finding $scope $sub 'Soft delete' 'Warn' (Show-Value $v.softDelete) 'Verify soft delete settings in the portal.' }
    }

    # Immutability
    switch -Regex ([string]$v.immutability) {
        '^Locked$'   { Add-Finding $scope $sub 'Immutability' 'Pass' 'Enabled and locked' }
        '^Unlocked$' { Add-Finding $scope $sub 'Immutability' 'Warn' 'Enabled but not locked' 'Lock immutability once retention settings are final, so it cannot be reversed.' }
        default      { Add-Finding $scope $sub 'Immutability' 'Fail' (Show-Value $v.immutability) 'Enable immutability to stop recovery points being deleted before they expire.' }
    }

    # Multi-user authorization
    if ([string]$v.mua -eq 'Enabled') {
        Add-Finding $scope $sub 'Multi-user authorization' 'Pass' 'Protected by a Resource Guard'
    } else {
        Add-Finding $scope $sub 'Multi-user authorization' 'Warn' (Show-Value $v.mua) 'Consider a Resource Guard so critical operations need a second approver.'
    }

    # Redundancy
    switch -Regex ([string]$v.redundancy) {
        '^GeoRedundant$'      { Add-Finding $scope $sub 'Storage redundancy' 'Pass' 'Geo-redundant' }
        '^ZoneRedundant$'     { Add-Finding $scope $sub 'Storage redundancy' 'Info' 'Zone-redundant (survives zone loss, not region loss)' 'Use geo-redundant storage for workloads that must survive a regional outage.' }
        '^LocallyRedundant$'  { Add-Finding $scope $sub 'Storage redundancy' 'Warn' 'Locally redundant (single datacenter)' 'Review whether critical workloads need geo-redundant storage.' }
        default               { Add-Finding $scope $sub 'Storage redundancy' 'Info' (Show-Value $v.redundancy) }
    }

    if ([string]$v.redundancy -eq 'GeoRedundant') {
        if ([string]$v.crossRegionRestore -eq 'Enabled') {
            Add-Finding $scope $sub 'Cross-region restore' 'Pass' 'Enabled'
        } else {
            Add-Finding $scope $sub 'Cross-region restore' 'Info' (Show-Value $v.crossRegionRestore) 'Enable cross-region restore if you need to restore in the paired region during an outage.'
        }
    }

    # Alerts
    switch -Regex ([string]$v.jobFailureAlerts) {
        '^Enabled$'  { Add-Finding $scope $sub 'Job failure alerts' 'Pass' 'Azure Monitor alerts on for all job failures' }
        '^Disabled$' { Add-Finding $scope $sub 'Job failure alerts' 'Fail' 'Disabled' 'Enable Azure Monitor alerts for job failures and route them to an action group.' }
        default      { Add-Finding $scope $sub 'Job failure alerts' 'Warn' (Show-Value $v.jobFailureAlerts) 'Confirm Azure Monitor alerts are configured with an action group (classic alerts were deprecated 31 March 2026).' }
    }

    # Network
    if ([string]$v.publicNetworkAccess -eq 'Disabled') {
        Add-Finding $scope $sub 'Public network access' 'Pass' 'Disabled (private endpoints)'
    } else {
        Add-Finding $scope $sub 'Public network access' 'Info' (Show-Value $v.publicNetworkAccess) 'Consider private endpoints if your network design supports them.'
    }

    # Diagnostics
    if ($hasMonitor -and (Get-Command Get-AzDiagnosticSetting -ErrorAction SilentlyContinue)) {
        try {
            $diag = @(Get-AzDiagnosticSetting -ResourceId $v.id -WarningAction SilentlyContinue -ErrorAction Stop)
            $toWorkspace = @($diag | Where-Object { $_.WorkspaceId })
            if ($toWorkspace.Count -gt 0) {
                Add-Finding $scope $sub 'Diagnostics to Log Analytics' 'Pass' 'Configured'
            } else {
                Add-Finding $scope $sub 'Diagnostics to Log Analytics' 'Warn' 'No Log Analytics destination' 'Send vault diagnostics to Log Analytics for reporting and long-term history.'
            }
        } catch {
            Add-Finding $scope $sub 'Diagnostics to Log Analytics' 'Info' 'Could not read diagnostic settings' 'Check that you have Reader access to this subscription.'
        }
    } else {
        Add-Finding $scope $sub 'Diagnostics to Log Analytics' 'Info' 'Skipped (Az.Monitor not installed)'
    }

    # Retention
    $vaultPolicies = @($policies | Where-Object { $_.vaultId -eq $v.id -and $null -ne $_.dailyRetention -and [int]$_.dailyRetention -gt 0 })
    foreach ($p in $vaultPolicies) {
        if ([int]$p.dailyRetention -lt $MinDailyRetentionDays) {
            Add-Finding $scope $sub "Retention: $($p.policyName)" 'Warn' "Daily retention $($p.dailyRetention) day(s)" "Short retention limits how far back you can recover (for example, from ransomware found late). Minimum used by this audit: $MinDailyRetentionDays days."
        }
    }

    # Protected items
    $vaultItems = @($items | Where-Object { $_.vaultId -eq $v.id })
    if ($vaultItems.Count -eq 0) {
        Add-Finding $scope $sub 'Protected items' 'Info' 'Vault protects nothing' 'Remove unused vaults or confirm this is expected.'
    }
    $now = (Get-Date).ToUniversalTime()
    foreach ($item in $vaultItems) {
        $name = Show-Value $item.itemName
        if ([string]$item.protectionState -match 'ProtectionStopped|ProtectionPaused') {
            Add-Finding $scope $sub "Item: $name" 'Warn' "Protection state: $($item.protectionState)" 'Resume protection or confirm the item is intentionally retired.'
            continue
        }
        if ([string]$item.lastBackupStatus -eq 'Failed') {
            Add-Finding $scope $sub "Item: $name" 'Fail' 'Last backup failed' 'Check the job error in the vault and rerun the backup.'
            continue
        }
        $parsed = [datetime]::MinValue
        if ([datetime]::TryParse([string]$item.lastBackupTime, [ref]$parsed)) {
            $age = ($now - $parsed.ToUniversalTime()).TotalHours
            if ($age -gt $StaleHours) {
                Add-Finding $scope $sub "Item: $name" 'Warn' ("Last backup {0:N0} hours ago" -f $age) "Backups older than $StaleHours hours may mean a schedule or agent problem."
            }
        }
    }
}

# ---------------------------------------------------------------------------
# Unprotected VMs
# ---------------------------------------------------------------------------

$protectedIds = New-Object 'System.Collections.Generic.HashSet[string]'
foreach ($item in $items) {
    if (-not [string]::IsNullOrWhiteSpace([string]$item.sourceId)) { [void]$protectedIds.Add([string]$item.sourceId) }
}
foreach ($vm in $vms) {
    if (-not $protectedIds.Contains([string]$vm.id)) {
        Add-Finding "VM $($vm.name) ($($vm.resourceGroup))" $vm.subscriptionId 'VM backup coverage' 'Fail' 'No Azure Backup protection found' 'Protect this VM, or document why it does not need backup (for example, stateless or rebuilt from code).'
    }
}

# ---------------------------------------------------------------------------
# Scoring and output
# ---------------------------------------------------------------------------

function Get-Score {
    param($Rows)
    $scored = @($Rows | Where-Object { $_.Status -in @('Pass', 'Warn', 'Fail') })
    if ($scored.Count -eq 0) { return $null }
    $points = 0.0
    foreach ($r in $scored) {
        if ($r.Status -eq 'Pass') { $points += 1 } elseif ($r.Status -eq 'Warn') { $points += 0.5 }
    }
    return [int][Math]::Round(100 * $points / $scored.Count)
}

$colors = @{ Pass = 'Green'; Warn = 'Yellow'; Fail = 'Red'; Info = 'Gray' }

Write-Host ''
Write-Host 'Azure Backup configuration audit' -ForegroundColor Cyan
Write-Host ('=' * 60) -ForegroundColor Cyan

$overall = Get-Score $findings
if ($null -ne $overall) {
    $overallColor = 'Red'
    if ($overall -ge 80) { $overallColor = 'Green' } elseif ($overall -ge 60) { $overallColor = 'Yellow' }
    Write-Host ("Overall score: {0}/100" -f $overall) -ForegroundColor $overallColor
}
$counts = $findings | Group-Object Status | ForEach-Object { "{0}: {1}" -f $_.Name, $_.Count }
Write-Host ($counts -join '   ')
Write-Host ''

Write-Host 'Score by vault' -ForegroundColor Cyan
foreach ($group in ($findings | Where-Object { $_.Scope -notlike 'VM *' } | Group-Object Scope)) {
    $s = Get-Score $group.Group
    if ($null -ne $s) { Write-Host ("  {0,3}/100  {1}" -f $s, $group.Name) }
}
Write-Host ''

$priority = @{ Fail = 0; Warn = 1 }
$toFix = @($findings | Where-Object { $_.Status -in @('Fail', 'Warn') } |
    Sort-Object @{ Expression = { $priority[$_.Status] } }, Scope, Check)

if ($toFix.Count -eq 0) {
    Write-Host 'No failures or warnings found.' -ForegroundColor Green
} else {
    Write-Host "Fix list ($($toFix.Count) item(s), most urgent first)" -ForegroundColor Cyan
    foreach ($f in $toFix) {
        Write-Host ("  [{0}] " -f $f.Status.ToUpper()) -ForegroundColor $colors[$f.Status] -NoNewline
        Write-Host ("{0}: {1} - {2}" -f $f.Scope, $f.Check, $f.Detail)
        if ($f.Recommendation) { Write-Host ("         {0}" -f $f.Recommendation) -ForegroundColor DarkGray }
    }
}

if ($CsvPath) {
    $findings | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
    Write-Host ''
    Write-Host "All findings exported to $CsvPath" -ForegroundColor Cyan
}

Write-Host ''
Write-Host 'Want this audit to run automatically, across every tenant you manage,' -ForegroundColor Cyan
Write-Host 'with a client-ready report each week? Join the waitlist: [YOUR-WAITLIST-URL]' -ForegroundColor Cyan
