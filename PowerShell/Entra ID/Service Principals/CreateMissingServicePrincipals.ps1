<#
    .NOTES
    ===========================================================================
     Created on:    17-08-2026
     Created by:    Michael Morten Sonne
     Organization:  Sonne´s Cloud
     Filename:      CreateMissingServicePrincipals.ps1
     Version:       1.2
    ===========================================================================
    .SYNOPSIS
        Script to register missing Entra ID Enterprise Applications.

    .DESCRIPTION
        This script checks for the existence of specific Enterprise Applications in Entra ID
        and registers them if they are missing. These applications are commonly used in
        Conditional Access policies and other security configurations.

    .PARAMETER TenantId
        Optional tenant ID to connect to a specific Microsoft Entra tenant.

    .PARAMETER WhatIf
        Shows what would happen if the script runs without making actual changes.

    .NOTES
        Requires:    Microsoft.Graph.Authentication, Microsoft.Graph.Applications
        License:     Entra ID P1 or higher
        Permissions: Application.ReadWrite.All

    .Investigate sign-in logs for a specific app
        $events = Get-MgBetaAuditLogSignIn -Filter "conditionalAccessAudiences/any(i:i eq 'ea890292-c8c8-4433-b5ea-b09d0668e1a6')" -All
        $events | Select-Object appId, appDisplayName, clientAppUsed, resourceDisplayName, resourceId, servicePrincipalId | Group-Object AppDisplayName | Format-List

    .EXAMPLE
        .\CreateMissingServicePrincipals.ps1 -WhatIf
        Preview what would be created without making changes

    .EXAMPLE
        .\CreateMissingServicePrincipals.ps1
        Register missing Enterprise Applications

    .EXAMPLE
        .\CreateMissingServicePrincipals.ps1 -TenantId "00000000-0000-0000-0000-000000000000"
        Register missing Enterprise Applications in a specific tenant
#>

[CmdletBinding(SupportsShouldProcess)]
param(
 [string]$TenantId
)

#region Variables
# Insert APP IDs for Enterprise Applications to be registered
$APPIDs = @(
    @{ AppId = "9cdead84-a844-4324-93f2-b2e6bb768d07"; ExpectedName = "Azure Virtual Desktop" }
    @{ AppId = "0af06dc6-e4b5-4f28-818e-e78e62d137a5"; ExpectedName = "Windows 365" }
    @{ AppId = "d4ebce55-015a-49b5-a083-c84d1797ae8c"; ExpectedName = "Microsoft Intune Enrollment" }
    @{ AppId = "45a330b1-b1ec-4cc1-9161-9f03992aa49f"; ExpectedName = "Windows Store for Business" }
    @{ AppId = "a4a365df-50f1-4397-bc59-1a1564b8bb9c"; ExpectedName = "Microsoft Remote Desktop" }
    @{ AppId = "ba9ff945-a723-4ab5-a977-bd8c9044fe61"; ExpectedName = "My Staff" }
    @{ AppId = "fb8d773d-7ef8-4ec0-a117-179f88add510"; ExpectedName = "Microsoft 365 Copilot" }
    @{ AppId = "797f4846-ba00-4fd7-ba43-dac1f8f63013"; ExpectedName = "Azure Resource Manager" } # Old AppID for "Windows Azure Service Management API"
    @{ AppId = "ea890292-c8c8-4433-b5ea-b09d0668e1a6"; ExpectedName = "Azure Credential Configuration Endpoint Service" }
    @{ AppId = "00000002-0000-0000-c000-000000000000"; ExpectedName = "Windows Azure Active Directory" }
    @{ AppId = "19db86c3-b2b9-44cc-b339-36da233a3be2"; ExpectedName = "My Signins" }
    @{ AppId = "8c59ead7-d703-4a27-9e55-c96a0054c8d2"; ExpectedName = "My Profile" }
    @{ AppId = "0000000c-0000-0000-c000-000000000000"; ExpectedName = "Microsoft App Access Panel" }
    @{ AppId = "1b912ec3-a9dd-4c4d-a53e-76aa7adb28d7"; ExpectedName = "AADReporting" }
    @{ AppId = "00000002-0000-0ff1-ce00-000000000000"; ExpectedName = "Office 365 Exchange Online" }
    @{ AppId = "00000003-0000-0000-c000-000000000000"; ExpectedName = "Microsoft Graph" }
    @{ AppId = "499b84ac-1321-427f-aa17-267ca6975798"; ExpectedName = "Azure DevOps" }
    @{ AppId = "27922004-5251-4030-b22d-91ecd9a37ea4"; ExpectedName = "Outlook Mobile" }
    @{ AppId = "5d661950-3475-41cd-a2c3-d671a3162bc1"; ExpectedName = "Microsoft Outlook" }
    @{ AppId = "87223343-80b1-4097-be13-2332ffa1d666"; ExpectedName = "Outlook Web App Widgets" }
    @{ AppId = "9199bf20-a13f-4107-85dc-02114787ef48"; ExpectedName = "One Outlook Web" }
    @{ AppId = "bc59ab01-8403-45c6-8796-ac3ef710b3e3"; ExpectedName = "Outlook Online Add-in App" }
    @{ AppId = "e9b154d0-7658-433b-bb25-6b8e0a8a7c59"; ExpectedName = "Outlook Lite" }
    @{ AppId = "765fe668-04e7-42ba-aec0-2c96f1d8b652"; ExpectedName = "Exchange Office Graph Client for AAD - Noninteractive" }
    @{ AppId = "a150d169-7d37-47dd-9b20-156207b7b02f"; ExpectedName = "MIP Exchange Solutions" }
    @{ AppId = "6da466b6-1d13-4a2c-97bd-51a99e8d4d74"; ExpectedName = "Exchange Office Graph Client for AAD - Interactive" }
    @{ AppId = "789e8929-0390-42a2-8934-0f9dafb8ec89"; ExpectedName = "Exchange Rbac" }
    @{ AppId = "00000007-0000-0ff1-ce00-000000000000"; ExpectedName = "Microsoft Exchange Online Protection" }
    @{ AppId = "4813382a-8fa7-425e-ab75-3b753aab3abb"; ExpectedName = "Microsoft Authenticator App" }
    @{ AppId = "dd47d17a-3194-4d86-bfd5-c6ae6f5651e3"; ExpectedName = "Microsoft Defender for Mobile" } # Used by Intune Tunnel also
    @{ AppId = "3678c9e9-9681-447a-974d-d19f668fcd88"; ExpectedName = "Microsoft Tunnel Gateway" } # Intune Tunnel Service
    @{ AppId = "38aa3b87-a06d-4817-b275-7a316988d93b"; ExpectedName = "Windows Sign In" }
    # Need to be excludes in CA´s if useing VM (https://learn.microsoft.com/en-us/defender-endpoint/mobile-resources-defender-endpoint):
    @{ AppId = "a0e84e36-b067-4d5c-ab4a-3db38e598ae2"; ExpectedName = "MicrosoftDefenderATP XPlat" } # Microsoft Defender Advanced Threat Protection Cross-Platform - forwarding Defender risk signals to the Defender backend)
    @{ AppId = "e724aa31-0f56-4018-b8be-f8cb82ca1196"; ExpectedName = "Microsoft Defender for Mobile TVM" } # (Threat and Vulnerability Management)
    @{ AppId = "cde6adac-58fd-4b78-8d6d-9beaf1b0d668"; ExpectedName = "Global Secure Access Client" }
    @{ AppId = "760282b4-0cfc-4952-b467-c8e0298fee16"; ExpectedName = "ZTNA Network Access Client -- Private" }
    @{ AppId = "ca01d00c-bfd6-46d6-ae7d-be5b5267d037"; ExpectedName = "ZTNA Policy Service Client" }
    @{ AppId = "4354e225-50c9-4423-9ece-2d5afd904870"; ExpectedName = "Augmentation Loop" }
    @{ AppId = "5a6fd92b-8a2c-41d2-b3bb-98d35d258d9e"; ExpectedName = "Azure Portal Fx Copilot Web" }
    @{ AppId = "8fbcdaa8-9342-48c2-927f-3a15d30f7b8b"; ExpectedName = "Code Center Premium" }
    @{ AppId = "de50c81f-5f80-4771-b66b-cebd28ccdfc1"; ExpectedName = "Device Management Client" }
    @{ AppId = "3a4d129e-7f50-4e0d-a7fd-033add0a29f4"; ExpectedName = "Enterprise Dashboard Project" }
    @{ AppId = "ffe59ab3-5993-4931-863a-2e78afcf0d1f"; ExpectedName = "Entra-Copilot-UX" }
    @{ AppId = "4b0964e4-58f1-47f4-a552-e2e1fc56dcd7"; ExpectedName = "FXIrisClient" }
    @{ AppId = "16aeb910-ce68-41d1-9ac3-9e1673ac9575"; ExpectedName = "IrisSelectionFrontDoor" }
    @{ AppId = "c0ab8ce9-e9a0-42e7-b064-33d422df41f1"; ExpectedName = "M365ChatClient" }
    @{ AppId = "6f7e0f60-9401-4f5b-98e2-cf15bd5fd5e3"; ExpectedName = "Microsoft Application Command Service" }
    @{ AppId = "29d9ed98-a469-4536-ade2-f981bc1d605e"; ExpectedName = "Microsoft Authentication Broker" }
    @{ AppId = "8a0c2593-9cbc-4f86-a247-beb7aab00d83"; ExpectedName = "Microsoft Defender for Cloud Apps - Session Controls" }
    @{ AppId = "cab96880-db5b-4e15-90a7-f3f1d62ffe39"; ExpectedName = "Microsoft Defender Platform" }
    @{ AppId = "ecd6b820-32c2-49b6-98a6-444530e5a77a"; ExpectedName = "Microsoft Edge" }
    @{ AppId = "d7b530a4-7680-4c23-a8bf-c52c121d2e87"; ExpectedName = "Microsoft Edge Enterprise New Tab Page" }
    @{ AppId = "5f00fd34-f302-417f-81ef-1adda179d8fd"; ExpectedName = "Microsoft Forms Web" }
    @{ AppId = "fc0f3af4-6835-4174-b806-f7db311fd2f3"; ExpectedName = "Microsoft Intune Windows Agent" }
    @{ AppId = "d3590ed6-52b3-4102-aeff-aad2292ab01c"; ExpectedName = "Microsoft Office" }
    @{ AppId = "f9885e6e-6f74-46b3-b595-350157a27541"; ExpectedName = "Microsoft_AAD_UsersAndTenants" }
    @{ AppId = "50aaa389-5a33-4f1a-91d7-2c45ecd8dac8"; ExpectedName = "Microsoft_Azure_PIMCommon" }
    @{ AppId = "89bee1f7-5e6e-4d8a-9f3d-ecd601259da7"; ExpectedName = "Office365 Shell WCSS-Client" }
    @{ AppId = "4765445b-32c6-49b0-83e6-1d93765276ca"; ExpectedName = "OfficeHome" }
    @{ AppId = "bb893c22-978d-4cd4-a6f7-bb6cc0d6e6ce"; ExpectedName = "Olympus" }
    @{ AppId = "af124e86-4e96-495a-b70a-90f90ab96707"; ExpectedName = "OneDrive iOS App" }
    @{ AppId = "ab9b8c07-8f02-4f72-87fa-80105867a763"; ExpectedName = "OneDrive SyncEngine" }
    @{ AppId = "268761a2-03f3-40df-8a8b-c3db24145b6b"; ExpectedName = "Universal Store Native Client" }
    @{ AppId = "aebc6443-996d-45c2-90f0-388ff96faa56"; ExpectedName = "Visual Studio Code" }
    @{ AppId = "6dec647e-42c4-45a6-8f13-e8250d34e033"; ExpectedName = "WeveAgave" }
    @{ AppId = "26a7ee05-5602-4d76-a7ba-eae8b7b67941"; ExpectedName = "Windows Search" }
    @{ AppId = "ea8d014c-04e7-450c-a600-eaa309e42309"; ExpectedName = "ZTNA UX Portal" }
    @{ AppId = "74658136-14ec-4630-ad9b-26e160ff0fc6"; ExpectedName = "ADIbizaUX" }
    @{ AppId = "b3fa0115-39b3-4bec-8cc6-8c4fcd33e69d"; ExpectedName = "ZTNA Policy Service" }
)
#endregion Variables

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

#endregion

# Check if required modules are installed
Write-Step "Checking required modules"
    
$requiredModules = @(
    'Microsoft.Graph.Authentication',
    'Microsoft.Graph.Applications'
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
        # Assembly load failure indicates mismatched Microsoft.Graph sub-module versions
        if ($_.Exception.Message -match 'Could not load file or assembly' -or
            $_.Exception.InnerException.Message -match 'Could not load file or assembly') {
            Write-Error "Module version mismatch detected for $module"
            Write-Host "  One or more Microsoft.Graph sub-modules are at conflicting versions." -ForegroundColor Yellow
            Write-Host "  Fix: Reinstall all Microsoft.Graph modules cleanly:" -ForegroundColor Yellow
            Write-Host "    Get-InstalledModule Microsoft.Graph* | Uninstall-Module -AllVersions -Force" -ForegroundColor Gray
            Write-Host "    Install-Module Microsoft.Graph -Scope CurrentUser -Force" -ForegroundColor Gray
        }
        else {
            Write-Error "Failed to import module $module"
            Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
        }
        exit 1
    }
}
    
# Connect to Microsoft Graph
Write-Step "Connecting to Microsoft Graph"
    
$requiredScopes = @(
    'Application.ReadWrite.All'
)

$ConnectMgGraphParameters = @{
 Scopes = $requiredScopes
 NoWelcome = $true
 ErrorAction = 'Stop'
}

# Only scope the connection to a specific tenant when one is supplied
if ($TenantId)
{
 $ConnectMgGraphParameters.TenantId = $TenantId
}
    
try {
    Connect-MgGraph @ConnectMgGraphParameters
    Write-Success "Connected to Microsoft Graph"
        
    # Verify tenant context
    $context = Get-MgContext
    Write-Host "  Tenant: $($context.TenantId)" -ForegroundColor Gray
    Write-Host "  Account: $($context.Account)" -ForegroundColor Gray
}
catch {
    Write-Error "Failed to connect to Microsoft Graph"
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Register Enterprise applications
Write-Step "Checking Enterprise Applications"
Write-Host "[INFORMATION]  Checking $($APPIDs.Count) application(s)" -ForegroundColor Cyan

# Fetch all service principals once for performance
Write-Host "[INFORMATION]  Fetching existing service principals..." -ForegroundColor Cyan
try {
    $allServicePrincipals = Get-MgServicePrincipal -All -Property AppId, DisplayName, Id
    Write-Host "[INFORMATION]  Found $($allServicePrincipals.Count) existing service principals" -ForegroundColor Cyan
    
    # Build hashtable for O(1) lookup by AppId
    $spLookup = @{}
    foreach ($sp in $allServicePrincipals) {
        $spLookup[$sp.AppId] = $sp
    }
}
catch {
    # Flatten inner exceptions to detect assembly load failures from mismatched modules
    $innerMsg = $_.Exception.InnerExceptions | ForEach-Object { $_.Message } | Where-Object { $_ -match 'Could not load file or assembly' }
    if ($innerMsg -or $_.Exception.Message -match 'Could not load file or assembly') {
        Write-Error "Microsoft.Graph module version mismatch - assembly could not be loaded"
        Write-Host "  Fix: Reinstall all Microsoft.Graph modules cleanly:" -ForegroundColor Yellow
        Write-Host "    Get-InstalledModule Microsoft.Graph* | Uninstall-Module -AllVersions -Force" -ForegroundColor Gray
        Write-Host "    Install-Module Microsoft.Graph -Scope CurrentUser -Force" -ForegroundColor Gray
    }
    else {
        Write-Error "Failed to fetch service principals"
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    }
    exit 1
}

$existingCount = 0
$createdCount = 0
$toCreateCount = 0   # counts SPs that would be created under -WhatIf
$failedCount = 0
$skippedCount = 0

Write-Host ""

foreach ($app in $APPIDs) {
    $ID = $app.AppId
    $ExpectedName = $app.ExpectedName
    
    # Finds Enterprise Applications, register it if not existing
    try {
        if ($spLookup.ContainsKey($ID)) {
            $ExistingApp = $spLookup[$ID]
            $DisplayName = $ExistingApp.DisplayName
            Write-Host "  [OK]  $DisplayName" -ForegroundColor Gray -NoNewline
            Write-Host " [$ID]" -ForegroundColor DarkGray
            $existingCount++
        }
        else {
            if ($PSCmdlet.ShouldProcess("Service Principal $ID", "Create")) {
                $ServicePrincipalID = @{
                    "AppId" = "$ID"
                }
                $newApp = New-MgServicePrincipal -BodyParameter $ServicePrincipalId -ErrorAction Stop
                Write-Success "$($newApp.DisplayName) [$ID]"
                $createdCount++
            }
            else {
                Write-Host "  Will add: $ExpectedName" -ForegroundColor Magenta -NoNewline
                Write-Host " [$ID]" -ForegroundColor DarkMagenta
                $toCreateCount++
            }
        }
    }
    catch {
        # Some Microsoft first-party AppIds cannot be instantiated as SPs in a tenant
        if ($_.Exception.Message -match 'does not reference a valid application object' -or
            $_.FullyQualifiedErrorId -match 'Request_BadRequest') {
            Write-Host "  [SKIP] AppId not available for instantiation: $ExpectedName" -ForegroundColor Yellow -NoNewline
            Write-Host " [$ID]" -ForegroundColor DarkYellow
            $skippedCount++
        }
        elseif ($_.Exception.Message -match 'already in use' -or
                $_.FullyQualifiedErrorId -match 'Request_MultipleObjectsWithSameKeyValue') {
            # 409 — created by a parallel process or duplicate entry in the list
            Write-Host "  [OK]  $ExpectedName" -ForegroundColor Gray -NoNewline
            Write-Host " [$ID]" -ForegroundColor DarkGray
            $existingCount++
        }
        else {
            Write-Host "  [ERROR] Failed to process" -ForegroundColor Red -NoNewline
            Write-Host " $ExpectedName [$ID]" -ForegroundColor DarkRed
            Write-Host "     Error: $($_.Exception.Message)" -ForegroundColor DarkRed
            $failedCount++
        }
    }
}

# Summary
Write-Step "Configuration Complete"

Write-Host "`n Summary:" -ForegroundColor Cyan
Write-Host "  Total applications checked: $($APPIDs.Count)" -ForegroundColor White

if ($existingCount -gt 0) {
    Write-Host "  Already existing: $existingCount" -ForegroundColor Gray
}
if ($createdCount -gt 0) {
    Write-Host "  Successfully created: $createdCount" -ForegroundColor Green
}
if ($toCreateCount -gt 0) {
    Write-Host "  Would be created (WhatIf): $toCreateCount" -ForegroundColor Magenta
}
if ($skippedCount -gt 0) {
    Write-Host "  Skipped (AppId not globally instantiable): $skippedCount" -ForegroundColor Yellow
}
if ($failedCount -gt 0) {
    Write-Host "  Failed: $failedCount" -ForegroundColor Red
}

if ($toCreateCount -gt 0) {
    Write-Host "`n Run without -WhatIf to create the missing service principals" -ForegroundColor Yellow
}
elseif ($createdCount -gt 0) {
    Write-Host "`n[OK] Missing enterprise applications have been registered" -ForegroundColor Green
}
elseif ($existingCount -eq $APPIDs.Count) {
    Write-Host "`n[OK] All enterprise applications are already registered" -ForegroundColor Green
}