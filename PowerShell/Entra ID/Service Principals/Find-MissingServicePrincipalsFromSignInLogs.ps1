<#
    .NOTES
    ===========================================================================
     Created on:    28-08-2026
     Created by:    Michael Morten Sonne
     Organization:  Sonne´s Cloud
     Filename:      Find-MissingServicePrincipalsFromSignInLogs.ps1
     Version:       1.3
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

    .PARAMETER ExportPath
        Optional path to export the missing client apps and missing resources. Use a .json
        extension for JSON output, otherwise the results are exported as CSV. Both sets are
        combined into a single file distinguished by a Type column (ClientApp/Resource).

    .PARAMETER LogPath
        Optional path to a log file. When supplied, all log messages are also written to this file
        via a thread-safe logging function.

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

    .EXAMPLE
        .\Find-MissingServicePrincipalsFromSignInLogs.ps1 -ExportPath "C:\Reports\MissingSPs.csv" -LogPath "C:\Logs\MissingSPs.log"
        Check the last 24 hours, export the missing apps/resources to CSV, and log console output to a file
#>

[CmdletBinding()]
param(
    [string]$TenantId,
    [int]$DaysBack = 1,
    [datetime]$StartDate,
    [datetime]$EndDate,
    [int]$Top = 500,
    [switch]$SkipInteractive,
    [switch]$SkipNonInteractive,
    [string]$ExportPath,
    [string]$LogPath
)

#region Functions

#
# Function: Logging with Console Output (thread safe)
#
# This function will log messages to the console and a log file.
# It uses a global lock object to ensure thread safety.
# Input parameters:
# - Message: The message to log.
# - Level: The log level (ERROR, WARNING, INFO, DEBUG, SUCCESS). Default is INFO.
# - Color: Overrides the level's default console color (used for custom-formatted rows/tables).
# - NoPrefix: Skips the "[timestamp] [Level]" prefix (used for pre-formatted lines like table rows).
# - NoNewline: Keeps the cursor on the same line (used to combine multiple colors on one row).
function Write-Log {
    param (
        [string]$Message,
        [ValidateSet("ERROR", "WARNING", "INFO", "DEBUG", "SUCCESS")]
        [string]$Level = "INFO",
        [System.ConsoleColor]$Color,
        [switch]$NoPrefix,
        [switch]$NoNewline
    )

    $levels = @("ERROR", "WARNING", "INFO", "DEBUG")
    $currentIndex = $levels.IndexOf($script:LogLevel.ToUpper())
    $messageIndex = $levels.IndexOf($Level.ToUpper())

    [System.Threading.Monitor]::Enter($script:LogLockObject)
    try {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $logMessage = if ($NoPrefix) { $Message } else { "[$timestamp] [$Level] $Message" }

        if ($messageIndex -le $currentIndex -or $Level -eq "SUCCESS") {
            $consoleColor = if ($PSBoundParameters.ContainsKey('Color')) {
                $Color
            }
            else {
                switch ($Level) {
                    "ERROR" { "Red" }
                    "WARNING" { "Yellow" }
                    "INFO" { "Gray" }
                    "DEBUG" { "Cyan" }
                    "SUCCESS" { "Green" }
                }
            }
            if ($NoNewline) {
                Write-Host $logMessage -ForegroundColor $consoleColor -NoNewline
            }
            else {
                Write-Host $logMessage -ForegroundColor $consoleColor
            }
        }

        if ($script:LogFilePath) {
            $fileStream = [System.IO.File]::Open($script:LogFilePath, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)
            $streamWriter = New-Object System.IO.StreamWriter($fileStream)
            try {
                if ($NoNewline) {
                    $streamWriter.Write($logMessage)
                }
                else {
                    $streamWriter.WriteLine($logMessage)
                }
            }
            finally {
                $streamWriter.Close()
                $fileStream.Close()
            }
        }
    }
    finally {
        [System.Threading.Monitor]::Exit($script:LogLockObject)
    }
}

function Write-Step {
    param([string]$Message)
    Write-Log -Message "`n==== $Message ====" -Color Cyan -NoPrefix
}

function Write-Success {
    param([string]$Message)
    Write-Log -Message $Message -Level SUCCESS
}

function Write-Warning {
    param([string]$Message)
    Write-Log -Message $Message -Level WARNING
}

function Write-Error {
    param([string]$Message)
    Write-Log -Message $Message -Level ERROR
}

#endregion Functions

#region Start logging

$script:LogLevel = 'INFO'
$script:LogFilePath = $null
$script:LogLockObject = [object]::new()

if ($LogPath) {
    # Resolve to an absolute path: .NET file APIs use the process directory, not PowerShell's $PWD
    $script:LogFilePath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($LogPath)
    $logDir = Split-Path -Path $script:LogFilePath -Parent
    if ($logDir -and -not (Test-Path -Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }
    Write-Log -Message "[INFORMATION]  Logging console output to: $script:LogFilePath" -Color Cyan -NoPrefix
}

#endregion

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
            Write-Log -Message "  Fix: Reinstall all Microsoft.Graph modules cleanly:" -Level WARNING -NoPrefix
            Write-Log -Message "    Get-InstalledModule Microsoft.Graph* | Uninstall-Module -AllVersions -Force" -NoPrefix
            Write-Log -Message "    Install-Module Microsoft.Graph -Scope CurrentUser -Force" -NoPrefix
        }
        else {
            Write-Error "Failed to import module $module`: $($_.Exception.Message)"
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
    Write-Log -Message "  Tenant: $($context.TenantId)" -NoPrefix
    Write-Log -Message "  Account: $($context.Account)" -NoPrefix
}
catch {
    Write-Error "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
    exit 1
}

#endregion

#region Fetch existing service principals

Write-Step "Fetching existing service principals"

try {
    Write-Log -Message "  Fetching all service principals..." -NoPrefix
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
    Write-Error "Failed to fetch service principals: $($_.Exception.Message)"
    exit 1
}

#endregion

#region Fetch sign-in logs

Write-Step "Querying sign-in logs"
Write-Log -Message "  Period: $startIso  ->  $endIso" -NoPrefix

$interactiveLogs    = @()
$nonInteractiveLogs = [System.Collections.Generic.List[object]]::new()
$resourcesFromLogs  = @{}

# Interactive sign-in logs via Get-MgAuditLogSignIn
if (-not $SkipInteractive) {
    Write-Log -Message "  Querying interactive logs..." -NoPrefix
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
        Write-Error "Failed to retrieve interactive logs: $($_.Exception.Message)"
    }
}
else {
    Write-Log -Message "  [SKIP] Interactive logs skipped (-SkipInteractive)" -Color DarkGray -NoPrefix
}

# Non-interactive summarized logs via Invoke-MgGraphRequest (beta-only endpoint)
if (-not $SkipNonInteractive) {
    Write-Log -Message "  Querying non-interactive logs..." -NoPrefix
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
            Write-Log -Message "  Page $page - retrieved $($nonInteractiveLogs.Count) entries so far" -Color DarkGray -NoPrefix
            $niUri = $response.'@odata.nextLink'
        } while ($niUri)

        Write-Success "$($nonInteractiveLogs.Count) non-interactive log entries retrieved"
    }
    catch {
        Write-Error "Failed to retrieve non-interactive logs: $($_.Exception.Message)"
    }
}
else {
    Write-Log -Message "  [SKIP] Non-interactive logs skipped (-SkipNonInteractive)" -Color DarkGray -NoPrefix
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

Write-Log -Message "  Unique client apps seen in logs:  $($appsFromLogs.Count)" -NoPrefix
Write-Log -Message "  Unique resources seen in logs:    $($resourcesFromLogs.Count)" -NoPrefix

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
    Write-Log -Message "`n[OK] All client applications seen in sign-in logs already have a service principal." -Level SUCCESS -NoPrefix
}
else {
    Write-Log -Message "  The following $($missingApps.Count) client app(s) appear in sign-in logs but have no service principal:`n" -Level WARNING -NoPrefix

    $sorted = $missingApps | Sort-Object DisplayName

    foreach ($app in $sorted) {
        Write-Log -Message "  $($app.DisplayName)" -Color White -NoPrefix -NoNewline
        Write-Log -Message " [$($app.AppId)]" -Color DarkGray -NoPrefix -NoNewline
        Write-Log -Message "  ($($app.SeenIn))" -Color DarkYellow -NoPrefix
    }

    Write-Host ""
    Write-Log -Message "  To add these as entries in CreateMissingServicePrincipals.ps1, use:" -Color Cyan -NoPrefix
    Write-Host ""
    foreach ($app in $sorted) {
        $safeName = if ($app.DisplayName) { $app.DisplayName } else { "Unknown" }
        Write-Log -Message "    @{ AppId = `"$($app.AppId)`"; ExpectedName = `"$safeName`" }" -NoPrefix
    }
}

Write-Step "Missing Resource Service Principals"

if ($missingResources.Count -eq 0) {
    Write-Log -Message "`n[OK] All resources seen in sign-in logs already have a service principal." -Level SUCCESS -NoPrefix
}
else {
    Write-Log -Message "  The following $($missingResources.Count) resource(s) appear in sign-in logs but have no matching service principal:`n" -Level WARNING -NoPrefix
    Write-Log -Message "  [NOTE] Resource SPs cannot be auto-created - resourceId is an SP object ID, not an AppId." -Color DarkCyan -NoPrefix
    Write-Log -Message "         Investigate each entry manually and register via its AppId if available.`n" -Color DarkCyan -NoPrefix

    $sortedRes = $missingResources | Sort-Object DisplayName

    foreach ($res in $sortedRes) {
        Write-Log -Message "  $($res.DisplayName)" -Color White -NoPrefix -NoNewline
        Write-Log -Message " [SP Id: $($res.ResourceId)]" -Color DarkGray -NoPrefix -NoNewline
        Write-Log -Message "  ($($res.SeenIn))" -Color DarkYellow -NoPrefix
    }
}

#endregion

#region Summary

Write-Step "Summary"

Write-Log -Message "`n  Period checked:                 $startIso  ->  $endIso" -Color White -NoPrefix
Write-Log -Message "  Interactive log entries:        $($interactiveLogs.Count)" -Color White -NoPrefix
Write-Log -Message "  Non-interactive log entries:    $($nonInteractiveLogs.Count)" -Color White -NoPrefix
Write-Log -Message "  Unique client apps in logs:     $($appsFromLogs.Count)" -Color White -NoPrefix
Write-Log -Message "  Unique resources in logs:       $($resourcesFromLogs.Count)" -Color White -NoPrefix
Write-Log -Message "  Existing service principals:    $($spLookup.Count)" -Color White -NoPrefix

if ($missingApps.Count -gt 0) {
    Write-Log -Message "  Missing client app SPs:         $($missingApps.Count)" -Level ERROR -NoPrefix
}
else {
    Write-Log -Message "  Missing client app SPs:         0" -Level SUCCESS -NoPrefix
}

if ($missingResources.Count -gt 0) {
    Write-Log -Message "  Missing resource SPs:           $($missingResources.Count)" -Level ERROR -NoPrefix
}
else {
    Write-Log -Message "  Missing resource SPs:           0" -Level SUCCESS -NoPrefix
}

#endregion

#region Export

if ($ExportPath) {
    $exportRows = [System.Collections.Generic.List[object]]::new()
    foreach ($app in $missingApps) {
        $exportRows.Add([PSCustomObject]@{
            Type        = 'ClientApp'
            Id          = $app.AppId
            DisplayName = $app.DisplayName
            SeenIn      = $app.SeenIn
        })
    }
    foreach ($res in $missingResources) {
        $exportRows.Add([PSCustomObject]@{
            Type        = 'Resource'
            Id          = $res.ResourceId
            DisplayName = $res.DisplayName
            SeenIn      = $res.SeenIn
        })
    }

    try {
        if ($ExportPath -match '\.json$') {
            $exportRows | ConvertTo-Json -Depth 3 | Out-File -FilePath $ExportPath -Encoding UTF8
        }
        else {
            $exportRows | Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8
        }
        Write-Log -Message "`n[INFORMATION]  Results exported to: $ExportPath" -Color Cyan -NoPrefix
    }
    catch {
        Write-Error "Failed to export results to $ExportPath`: $($_.Exception.Message)"
    }
}

#endregion
