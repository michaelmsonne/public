<#	
	.NOTES
	===========================================================================
	 Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2022 v5.8.213
	 Created on:   	25-04-2023 17:41
	 Created by:   	Michael Morten Sonne
	 Organization: 	Sonne´s Cloud
	 Filename:     	PowerShell-UpdateModules.ps1
	===========================================================================
	.DESCRIPTION
		Update PowerShell Modules

        If you look for a quick way to update, please keep in mind Microsoft has a built-in CMDlzt to update ALL the PowerShell modules installed:
        Update-Module [-Verbose]

        This script is intended as a replacement of the Update-Module:
        - to provide more human readable output than the -Verbose option of Update-Module
        - to force install with -SkipPublisherCheck (Authenticode change) because Update-Module has not this option
        - to exclude some modules from the update process
        - to remove older versions because Update-Module does not remove older versions (it only installs a new version in the $env:PSModulePath\<moduleName> and keep the old module)

        This script provides informations about the module version (current and the latest available on PowerShell Gallery) and update to the latest version
        If you have a module with two or more versions, the script delete them and reinstall only the latest.

	.EXAMPLE
		.\PowerShell-UpdateModules.ps1

        Update installed modules automaticly

        .\PowerShell-UpdateModules.ps1 -SimulationMode

        Simulate the update process of installed modules - nothing is installed / removed / updated

    .NOTES
        Updated at:	18-06-2023
#>

[CmdletBinding()]
param (
    [Parameter()]
    # To exclude modules from the update process
    [String[]]$ExcludedModules,
    # To include only these modules for the update process
    [String[]]$IncludedModules,
    [switch]$SkipPublisherCheck,
    [switch]$SimulationMode
)

#Requires -Version 5.0
#Requires -RunAsAdministrator

#Start logging
Start-Transcript -Path "C:\Temp\Sonnes\Logs\PowerShell Modules\UpdateModules - $(((get-date).ToUniversalTime()).ToString("ddMMyyyyThhmmssZ")).log" -Force

Write-Host -ForegroundColor cyan 'Define PowerShell to add TLS1.2 in this session, needed since 1st April 2020 (https://devblogs.microsoft.com/powershell/powershell-gallery-tls-support/)'
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

# if needed, register PSGallery
# Register PSGallery PSprovider and set as Trusted source
# Register-PSRepository -Default -ErrorAction SilentlyContinue
# Set-PSRepository -Name PSGallery -InstallationPolicy trusted -ErrorAction SilentlyContinue

# Set simulation mode if need to test
if ($SimulationMode) {
    Write-Host -ForegroundColor yellow 'Simulation mode is ON, nothing will be installed / removed / updated'
}
else {
    Write-Host -ForegroundColor red 'Simulation mode is OFF, modules will be installed / removed / updated'
}

# Start script - getting all modules
Write-Host -ForegroundColor Cyan 'Getting all PowerShell modules...'

# Uninstall modules
function Remove-OldPowerShellModules {
    param (
        [string]$ModuleName,
        [string]$GalleryVersion
    )

    if (-not($SimulationMode)) {
        # Check and remove older versions of the modules from the PC
        Write-Host -ForegroundColor Cyan "Beginning clean-up phase for $ModuleName older than $GalleryVersion..."
    }

    try {
        $oldVersions = Get-InstalledModule -Name $ModuleName -AllVersions -ErrorAction Stop | Where-Object { $_.Version -ne $GalleryVersion }

        foreach ($oldVersion in $oldVersions) {
            Write-Host -ForegroundColor Cyan "$ModuleName - Uninstall previous version ($($oldVersion.Version))"
            if (-not($SimulationMode)) {
                Remove-Module $ModuleName -ErrorAction SilentlyContinue
                Uninstall-Module $oldVersion -Force  -ErrorAction Stop
                Write-Host -ForegroundColor Green "$module is uninstalled, version: $oldVersion"
            }
        }
    }
    catch {
        Write-Warning "$module - $($_.Exception.Message)"
    }
}

if ($IncludedModules) {
    $modules = Get-InstalledModule | Where-Object { $IncludedModules -contains $_.Name }
}
else {
    $modules = Get-InstalledModule
}

foreach ($module in $modules.Name) {
    if ($ExcludedModules -contains $module) {
        Write-Host -ForegroundColor Yellow "Module $module is excluded from the update process"
        continue
    }
    elseif ($module -like "$excludedModules") {
        Write-Host -ForegroundColor Yellow "Module $module is excluded from the update process (match $excludeModules)"
        continue
    }

    $currentVersion = $null
	
    try {
        $currentVersion = (Get-InstalledModule -Name $module -AllVersions -ErrorAction Stop).Version
    }
    catch {
        Write-Warning "$module - $($_.Exception.Message)"
        continue
    }
	
    try {
        $moduleGalleryInfo = Find-Module -Name $module -ErrorAction Stop
    }
    catch {
        Write-Warning "$module not found in the PowerShell Gallery. $($_.Exception.Message)"
    }
	
    if ($null -eq $currentVersion) {
        Write-Host -ForegroundColor Cyan "$module - Install from PowerShellGallery version $($moduleGalleryInfo.Version) - Release date: $($moduleGalleryInfo.PublishedDate)"
		
        if (-not($SimulationMode)) {
            try {
                Install-Module -Name $module -Force -SkipPublisherCheck -ErrorAction Stop
                Write-Host -ForegroundColor Green "$module is installed, version: $($moduleGalleryInfo.Version)"
            }
            catch {
                Write-Warning "$module - $($_.Exception.Message)"
            }
        }
    }
    elseif ($moduleGalleryInfo.Version -eq $currentVersion) {
        Write-Host -ForegroundColor Green "$module already in latest version: $currentVersion - Release date: $($moduleGalleryInfo.PublishedDate)"
    }
    elseif ($currentVersion.count -gt 1) {
        Write-Host -ForegroundColor Yellow "$module is installed in $($currentVersion.count) versions (versions: $($currentVersion -join ' | '))"
        Write-Host -ForegroundColor Cyan "$module - Uninstall previous $module version(s) below the latest version ($($moduleGalleryInfo.Version))"
        
        Remove-OldPowerShellModules -ModuleName $module -GalleryVersion $moduleGalleryInfo.Version

        # Check again the current Version as we uninstalled some old versions
        $currentVersion = (Get-InstalledModule -Name $module).Version

        if ($moduleGalleryInfo.Version -ne $currentVersion) {
            Write-Host -ForegroundColor Cyan "$module - Install from PowerShellGallery version $($moduleGalleryInfo.Version) - Release date: $($moduleGalleryInfo.PublishedDate)"  
            if (-not($SimulationMode)) {
                try {
                    Install-Module -Name $module -Force -ErrorAction Stop

                    Write-Host -ForegroundColor Green "$module is installed, version: $($moduleGalleryInfo.Version)"

                    Remove-OldPowerShellModules -ModuleName $module -GalleryVersion $moduleGalleryInfo.Version
                }
                catch {
                    Write-Warning "$module - $($_.Exception.Message)"
                }
            }
        }
    }
    elseif ([version]$currentVersion -gt [version]$moduleGalleryInfo.Version) {   
        Write-Host -ForegroundColor Yellow "$module - the current version $currentVersion is newer than the version available on PowerShell Gallery $($moduleGalleryInfo.Version) (Release date: $($moduleGalleryInfo.PublishedDate)). Sometimes happens when you install a module from another repository or via .exe/.msi or if you change the version number manually."
    }
    elseif ([version]$currentVersion -lt [version]$moduleGalleryInfo.Version) {
        Write-Host -ForegroundColor Cyan "$module - Update from PowerShellGallery version " -NoNewline
        Write-Host -ForegroundColor White "$currentVersion -> $($moduleGalleryInfo.Version) " -NoNewline 
        Write-Host -ForegroundColor Cyan "- Release date: $($moduleGalleryInfo.PublishedDate)"
        
        if (-not($SimulationMode)) {
            try {
                Update-Module -Name $module -Force -ErrorAction Stop
                Remove-OldPowerShellModules -ModuleName $module -GalleryVersion $moduleGalleryInfo.Version
            }
            catch {
                if ($_.Exception.Message -match 'Authenticode') {
                    Write-Host -ForegroundColor Yellow "$module - The module certificate used by the creator is either changed since the last module install or the module sign status has changed." 
                
                    if ($SkipPublisherCheck.IsPresent) {
                        Write-Host -ForegroundColor Cyan "$module - SkipPublisherCheck Parameter is present, so install will run without Authenticode check"
                        Write-Host -ForegroundColor Cyan "$module - Install from PowerShellGallery version $($moduleGalleryInfo.Version) - Release date: $($moduleGalleryInfo.PublishedDate)"  
                        try {
                            Install-Module -Name $module -Force -SkipPublisherCheck

                            Write-Host -ForegroundColor Green "$module is installed (SkipPublisherCheck), version: $($moduleGalleryInfo.Version)"
                        }
                        catch {
                            Write-Warning "$module - $($_.Exception.Message)"
                        }
                    
                        Remove-OldPowerShellModules -ModuleName $module -GalleryVersion $moduleGalleryInfo.Version
                    }
                    else {
                        Write-Warning "$module - If you want to update this module, run again with -SkipPublisherCheck switch, but please keep in mind the security risk"
                    }
                }
                else {
                    Write-Warning "$module - $($_.Exception.Message)"
                }
            }
        }
    }
}

# Stop Logging
Stop-Transcript