<#
    .NOTES
    ===========================================================================
     Created on:    28-08-2026
     Created by:    Michael Morten Sonne
     Organization:  Sonne´s Cloud
     Filename:      Find-MissingServicePrincipalsFromSignInLogs.ps1
     Version:       1.1
    ===========================================================================
    .SYNOPSIS
        Identifies applications from sign-in logs that are missing as service principals in Entra ID.

    .DESCRIPTION
        Reads interactive and non-interactive sign-in logs from Microsoft Graph and identifies
        applications (by appId/appDisplayName) that do not have a corresponding service principal
        in the tenant. Use this to discover what to add via CreateMissingServicePrincipals.ps1.

    .PARAMETER TenantId
        Optional tenant ID to connect to a specific Microsoft Entra tenant.

    .PARAMETER DaysBack
        Number of days back to query sign-in logs. Default is 1.

    .PARAMETER StartDate
        Optional explicit start date/time for the log query. Overrides DaysBack.

    .PARAMETER EndDate
        Optional explicit end date/time for the log query. Defaults to now.

    .PARAMETER Top
        Maximum number of non-interactive log entries to retrieve per page. Default is 500.

    .PARAMETER SkipInteractive
        Skip querying interactive sign-in logs.

    .PARAMETER SkipNonInteractive
        Skip querying non-interactive sign-in logs.

    .NOTES
        Requires:    Microsoft.Graph.Authentication, Microsoft.Graph.Reports
        Permissions: AuditLog.Read.All, Application.Read.All
        License:     Entra ID P1 or higher (sign-in logs require P1/P2)

    .EXAMPLE
        .\Find-MissingServicePrincipalsFromSignInLogs.ps1
        Check the last 24 hours of sign-in logs

    .EXAMPLE
        .\Find-MissingServicePrincipalsFromSignInLogs.ps1 -DaysBack 7
        Check the last 7 days of sign-in logs

    .EXAMPLE
        .\Find-MissingServicePrincipalsFromSignInLogs.ps1 -StartDate "2026-08-01" -EndDate "2026-08-28"
        Check a specific date range

    .EXAMPLE
        .\Find-MissingServicePrincipalsFromSignInLogs.ps1 -SkipNonInteractive
        Check only interactive sign-in logs

    .EXAMPLE
        .\Find-MissingServicePrincipalsFromSignInLogs.ps1 -TenantId "00000000-0000-0000-0000-000000000000"
        Check a specific tenant
#>

[CmdletBinding()]
param(
    [string]$TenantId,
    [int]$DaysBack = 1,
    [datetime]$StartDate,
    [datetime]$EndDate,
    [int]$Top = 500,
    [switch]$SkipInteractive,
    [switch]$SkipNonInteractive
)

#region Functions

function Write-Step {
    param([string]$Message)
    Write-Host "`n==== $Message ====" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "[OK] $Message" -ForegroundColor Green
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[WARNING]  $Message" -ForegroundColor Yellow
}

function Write-Error {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

#endregion Functions

#region Date range setup

if (-not $EndDate) {
    $EndDate = [datetime]::UtcNow
}

# An explicit StartDate takes precedence over DaysBack
if ($StartDate) {
    if ($StartDate -ge $EndDate) {
        Write-Error "StartDate must be earlier than EndDate"
        exit 1
    }
}
else {
    $StartDate = $EndDate.AddDays(-$DaysBack)
}

# Graph audit log filters require UTC timestamps in ISO 8601 format
$startIso = $StartDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
$endIso   = $EndDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")

#endregion

#region Module check

Write-Step "Checking required modules"

$requiredModules = @(
    'Microsoft.Graph.Authentication',
    'Microsoft.Graph.Reports'
)

foreach ($module in $requiredModules) {
    if (!(Get-Module -ListAvailable -Name $module)) {
        Write-Error "Required module $module is not installed. Install it with: Install-Module $module"
        exit 1
    }
    try {
        Import-Module $module -ErrorAction Stop
        Write-Success "Module $module loaded"
    }
    catch {
        # Assembly load failures usually mean mismatched Microsoft.Graph module versions
        if ($_.Exception.Message -match 'Could not load file or assembly' -or
            $_.Exception.InnerException.Message -match 'Could not load file or assembly') {
            Write-Error "Module version mismatch detected for $module"
            Write-Host "  Fix: Reinstall all Microsoft.Graph modules cleanly:" -ForegroundColor Yellow
            Write-Host "    Get-InstalledModule Microsoft.Graph* | Uninstall-Module -AllVersions -Force" -ForegroundColor Gray
            Write-Host "    Install-Module Microsoft.Graph -Scope CurrentUser -Force" -ForegroundColor Gray
        }
        else {
            Write-Error "Failed to import module $module"
            Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Red
        }
        exit 1
    }
}

#endregion

#region Connect to Microsoft Graph

Write-Step "Connecting to Microsoft Graph"

$requiredScopes = @(
    'AuditLog.Read.All',
    'Application.Read.All'
)

$connectParams = @{
    Scopes      = $requiredScopes
    NoWelcome   = $true
    ErrorAction = 'Stop'
}

if ($TenantId) {
    $connectParams.TenantId = $TenantId
}

try {
    Connect-MgGraph @connectParams
    Write-Success "Connected to Microsoft Graph"

    $context = Get-MgContext
    Write-Host "  Tenant: $($context.TenantId)" -ForegroundColor Gray
    Write-Host "  Account: $($context.Account)" -ForegroundColor Gray
}
catch {
    Write-Error "Failed to connect to Microsoft Graph"
    Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

#endregion

#region Fetch existing service principals

Write-Step "Fetching existing service principals"

try {
    Write-Host "  Fetching all service principals..." -ForegroundColor Gray
    $allSp = Get-MgServicePrincipal -All -Property AppId, DisplayName, Id -ErrorAction Stop

    # Two lookups are needed because logs reference SPs differently:
    # client apps by AppId, resources by SP object Id (sometimes AppId)
    $spLookup   = @{}  # keyed by AppId - for client app checks
    $spIdLookup = @{}  # keyed by SP object Id - for resource checks
    foreach ($sp in $allSp) {
        $spLookup[$sp.AppId] = $sp.DisplayName
        $spIdLookup[$sp.Id]  = $sp.DisplayName
    }

    Write-Success "Found $($spLookup.Count) existing service principals"
}
catch {
    Write-Error "Failed to fetch service principals"
    Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

#endregion

#region Fetch sign-in logs

Write-Step "Querying sign-in logs"
Write-Host "  Period: $startIso  ->  $endIso" -ForegroundColor Gray

$interactiveLogs    = @()
$nonInteractiveLogs = [System.Collections.Generic.List[object]]::new()
$resourcesFromLogs  = @{}

# Interactive sign-in logs via Get-MgAuditLogSignIn
if (-not $SkipInteractive) {
    Write-Host "  Querying interactive logs..." -ForegroundColor Gray
    try {
        $interactiveFilter = "createdDateTime ge $startIso and createdDateTime lt $endIso"
        $interactiveLogs = Get-MgAuditLogSignIn `
            -Filter $interactiveFilter `
            -All `
            -Property appId, appDisplayName, resourceId, resourceDisplayName `
            -ErrorAction Stop
        Write-Success "$($interactiveLogs.Count) interactive log entries retrieved"
    }
    catch {
        Write-Error "Failed to retrieve interactive logs"
        Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Red
    }
}
else {
    Write-Host "  [SKIP] Interactive logs skipped (-SkipInteractive)" -ForegroundColor DarkGray
}

# Non-interactive summarized logs via Invoke-MgGraphRequest (beta-only endpoint)
if (-not $SkipNonInteractive) {
    Write-Host "  Querying non-interactive logs..." -ForegroundColor Gray
    try {
        # getSummarizedNonInteractiveSignIns is a beta-only endpoint with no dedicated cmdlet
        $niBase = "https://graph.microsoft.com/beta/auditLogs/getSummarizedNonInteractiveSignIns(aggregationWindow='d1')"
        $niUri  = $niBase + '?$filter=(firstSignInDateTime ge ' + $startIso + ' and firstSignInDateTime lt ' + $endIso + ')&$top=' + $Top + '&$orderby=firstSignInDateTime desc&$select=appId,appDisplayName,resourceId,resourceDisplayName'

        # Follow @odata.nextLink until all pages are consumed
        $page = 0
        do {
            $response = Invoke-MgGraphRequest -Method GET -Uri $niUri -ErrorAction Stop
            foreach ($entry in $response.value) {
                $nonInteractiveLogs.Add($entry)
            }
            $page++
            Write-Host "  Page $page - retrieved $($nonInteractiveLogs.Count) entries so far" -ForegroundColor DarkGray
            $niUri = $response.'@odata.nextLink'
        } while ($niUri)

        Write-Success "$($nonInteractiveLogs.Count) non-interactive log entries retrieved"
    }
    catch {
        Write-Error "Failed to retrieve non-interactive logs"
        Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Red
    }
}
else {
    Write-Host "  [SKIP] Non-interactive logs skipped (-SkipNonInteractive)" -ForegroundColor DarkGray
}

#endregion

#region Analyse results

Write-Step "Analysing results"

# Build a lookup: appId -> { DisplayName, SeenIn }
# SeenIn tracks whether each app was found in interactive and/or non-interactive logs
$appsFromLogs = @{}

foreach ($entry in $interactiveLogs) {
    $id = $entry.AppId
    # Skip the all-zero GUID which represents an unknown/absent app
    if (-not $id -or $id -eq '00000000-0000-0000-0000-000000000000') { continue }

    if (-not $appsFromLogs.ContainsKey($id)) {
        $appsFromLogs[$id] = @{
            DisplayName = $entry.AppDisplayName
            SeenIn      = [System.Collections.Generic.List[string]]::new()
        }
    }
    if (-not $appsFromLogs[$id].SeenIn.Contains('Interactive')) {
        $appsFromLogs[$id].SeenIn.Add('Interactive')
    }

    $rid = $entry.ResourceId
    if ($rid -and $rid -ne '00000000-0000-0000-0000-000000000000') {
        if (-not $resourcesFromLogs.ContainsKey($rid)) {
            $resourcesFromLogs[$rid] = @{
                DisplayName = $entry.ResourceDisplayName
                SeenIn      = [System.Collections.Generic.List[string]]::new()
            }
        }
        if (-not $resourcesFromLogs[$rid].SeenIn.Contains('Interactive')) {
            $resourcesFromLogs[$rid].SeenIn.Add('Interactive')
        }
    }
}

foreach ($entry in $nonInteractiveLogs) {
    $id = $entry.appId
    if (-not $id -or $id -eq '00000000-0000-0000-0000-000000000000') { continue }

    if (-not $appsFromLogs.ContainsKey($id)) {
        $appsFromLogs[$id] = @{
            DisplayName = $entry.appDisplayName
            SeenIn      = [System.Collections.Generic.List[string]]::new()
        }
    }
    if (-not $appsFromLogs[$id].SeenIn.Contains('NonInteractive')) {
        $appsFromLogs[$id].SeenIn.Add('NonInteractive')
    }

    $rid = $entry.resourceId
    if ($rid -and $rid -ne '00000000-0000-0000-0000-000000000000') {
        if (-not $resourcesFromLogs.ContainsKey($rid)) {
            $resourcesFromLogs[$rid] = @{
                DisplayName = $entry.resourceDisplayName
                SeenIn      = [System.Collections.Generic.List[string]]::new()
            }
        }
        if (-not $resourcesFromLogs[$rid].SeenIn.Contains('NonInteractive')) {
            $resourcesFromLogs[$rid].SeenIn.Add('NonInteractive')
        }
    }
}

Write-Host "  Unique client apps seen in logs:  $($appsFromLogs.Count)" -ForegroundColor Gray
Write-Host "  Unique resources seen in logs:    $($resourcesFromLogs.Count)" -ForegroundColor Gray

# Find client apps with no service principal (checked by AppId)
$missingApps = [System.Collections.Generic.List[object]]::new()

foreach ($appId in $appsFromLogs.Keys) {
    # An app is missing if its AppId has no corresponding service principal
    if (-not $spLookup.ContainsKey($appId)) {
        $missingApps.Add([PSCustomObject]@{
            AppId       = $appId
            DisplayName = $appsFromLogs[$appId].DisplayName
            SeenIn      = ($appsFromLogs[$appId].SeenIn -join ', ')
        })
    }
}

# Find resources with no service principal (resourceId can be either SP object Id or AppId)
$missingResources = [System.Collections.Generic.List[object]]::new()

foreach ($resourceId in $resourcesFromLogs.Keys) {
    # resourceId may be an SP object Id or an AppId, so check both lookups
    if (-not $spIdLookup.ContainsKey($resourceId) -and -not $spLookup.ContainsKey($resourceId)) {
        $missingResources.Add([PSCustomObject]@{
            ResourceId  = $resourceId
            DisplayName = $resourcesFromLogs[$resourceId].DisplayName
            SeenIn      = ($resourcesFromLogs[$resourceId].SeenIn -join ', ')
        })
    }
}

#endregion

#region Report

Write-Step "Missing Client App Service Principals"

if ($missingApps.Count -eq 0) {
    Write-Host "`n[OK] All client applications seen in sign-in logs already have a service principal." -ForegroundColor Green
}
else {
    Write-Host "  The following $($missingApps.Count) client app(s) appear in sign-in logs but have no service principal:`n" -ForegroundColor Yellow

    $sorted = $missingApps | Sort-Object DisplayName

    foreach ($app in $sorted) {
        Write-Host "  $($app.DisplayName)" -ForegroundColor White -NoNewline
        Write-Host " [$($app.AppId)]" -ForegroundColor DarkGray -NoNewline
        Write-Host "  ($($app.SeenIn))" -ForegroundColor DarkYellow
    }

    Write-Host ""
    Write-Host "  To add these as entries in CreateMissingServicePrincipals.ps1, use:" -ForegroundColor Cyan
    Write-Host ""
    foreach ($app in $sorted) {
        $safeName = if ($app.DisplayName) { $app.DisplayName } else { "Unknown" }
        Write-Host "    @{ AppId = `"$($app.AppId)`"; ExpectedName = `"$safeName`" }" -ForegroundColor Gray
    }
}

Write-Step "Missing Resource Service Principals"

if ($missingResources.Count -eq 0) {
    Write-Host "`n[OK] All resources seen in sign-in logs already have a service principal." -ForegroundColor Green
}
else {
    Write-Host "  The following $($missingResources.Count) resource(s) appear in sign-in logs but have no matching service principal:`n" -ForegroundColor Yellow
    Write-Host "  [NOTE] Resource SPs cannot be auto-created - resourceId is an SP object ID, not an AppId." -ForegroundColor DarkCyan
    Write-Host "         Investigate each entry manually and register via its AppId if available.`n" -ForegroundColor DarkCyan

    $sortedRes = $missingResources | Sort-Object DisplayName

    foreach ($res in $sortedRes) {
        Write-Host "  $($res.DisplayName)" -ForegroundColor White -NoNewline
        Write-Host " [SP Id: $($res.ResourceId)]" -ForegroundColor DarkGray -NoNewline
        Write-Host "  ($($res.SeenIn))" -ForegroundColor DarkYellow
    }
}

#endregion

#region Summary

Write-Step "Summary"

Write-Host "`n  Period checked:                 $startIso  ->  $endIso" -ForegroundColor White
Write-Host "  Interactive log entries:        $($interactiveLogs.Count)" -ForegroundColor White
Write-Host "  Non-interactive log entries:    $($nonInteractiveLogs.Count)" -ForegroundColor White
Write-Host "  Unique client apps in logs:     $($appsFromLogs.Count)" -ForegroundColor White
Write-Host "  Unique resources in logs:       $($resourcesFromLogs.Count)" -ForegroundColor White
Write-Host "  Existing service principals:    $($spLookup.Count)" -ForegroundColor White

if ($missingApps.Count -gt 0) {
    Write-Host "  Missing client app SPs:         $($missingApps.Count)" -ForegroundColor Red
}
else {
    Write-Host "  Missing client app SPs:         0" -ForegroundColor Green
}

if ($missingResources.Count -gt 0) {
    Write-Host "  Missing resource SPs:           $($missingResources.Count)" -ForegroundColor Red
}
else {
    Write-Host "  Missing resource SPs:           0" -ForegroundColor Green
}

#endregion
