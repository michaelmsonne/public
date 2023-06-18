<#	
	.NOTES
	===========================================================================
	 Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2022 v5.8.213
	 Created on:   	18-06-2023 17:41
	 Created by:   	Michael Morten Sonne
	 Organization: 	Sonne´s Cloud
	 Filename:     	PowerShell-CheckModuleUpdates.ps1
	===========================================================================
	.DESCRIPTION
		Check for Updates for PowerShell Modules from PowerShell Gallery

        If you look for a quick way to update, please keep in mind Microsoft has a built-in cmdlet to update ALL the PowerShell modules installed:
        Update-Module [-Verbose]

        This script provides informations about the module version (current installed and the latest available on PowerShell Gallery)

	.EXAMPLE
		.\PowerShell-CheckModuleUpdates.ps1
        Show modules there is updates to

        .\PowerShell-CheckModuleUpdates.ps1 -Verbose
        Show modules there is updates to and all running tasks and information provided

    .NOTES
        
#>

[cmdletbinding()]
[outputtype("moduleInfo")]
Param(
    [Parameter(Position = 0, HelpMessage = "Enter a module name or names. Wildcards are allowed.")]
    [ValidateNotNullorEmpty()]
    [string[]]$Name = "*"
)

Write-Host -ForegroundColor Cyan "Getting installed modules..."
Try
{
    $modules = Get-Module -Name $name -ListAvailable -ErrorAction Stop
}
Catch
{
    Throw $_
}

if ($modules)
{
    Write-Verbose "Found $($modules.count) matching modules"
    
    # Group to identify modules with multiple versions installed
    Write-Verbose "Grouping modules"
    $g = $modules | Group-Object name -NoElement | Where-Object count -GT 1

    # Filter modules
    Write-Verbose "Filter to modules from the PowerShellGallery"
    $gallery = $modules.where( { $_.repositorysourcelocation })

    <#Write-Verbose "Comparing to online versions"
    foreach ($module in $gallery) {
        #find the current version in the gallery
        Try {
            Write-Verbose "Looking online for $($module.name)"
            $online = Find-Module -Name $module.name -Repository PSGallery -ErrorAction Stop
            #compare versions
            if (($online.version -as [version]) -gt ($module.version -as [version])) {
                $UpdateAvailable = $True
            }
            else {
                $UpdateAvailable = $False
            }

            #write a custom object to the pipeline
            [pscustomobject]@{
                PSTypeName       = "moduleInfo"
                Name             = $module.name
                MultipleVersions = ($g.name -contains $module.name)
                InstalledVersion = $module.version
                OnlineVersion    = $online.version
                Update           = $UpdateAvailable
                Path             = $module.modulebase
            } | Format-Table -AutoSize 
        }
        Catch {
            Write-Warning "Module $($module.name) was not found in the PSGallery"
        }

    } #foreach#>
    Write-Host -ForegroundColor Cyan "Comparing installed versions to online versions at PowerShellGallery..."
    $moduleInfoList = foreach ($module in $gallery)
    {
        # Find the current version in the gallery
        try
        {
            Write-Verbose "Looking online for $($module.name) version..."
            $online = Find-Module -Name $module.name -Repository PSGallery -ErrorAction Stop
            
            # Compare versions
            if (($online.version -as [version]) -gt ($module.version -as [version])) {
                $UpdateAvailable = $true
            }
            else {
                $UpdateAvailable = $false
            }

            # Create a custom object for each module
            [pscustomobject]@{
                PSTypeName       = "moduleInfo"
                Name             = $module.name
                Update           = $UpdateAvailable
                MultipleVersions = ($g.name -contains $module.name)
                InstalledVersion = $module.version
                OnlineVersion    = $online.version
                #Path             = $module.modulebase
            }
        }
        catch
        {
            # If module not found
            Write-Warning "Module $($module.name) was not found in the PowerShellGallery"
        }
    }

    # Output
    Write-Host -ForegroundColor Cyan "List of PowerShell Module(s) there is found an update to:"

    # Filter the moduleInfo list where Update is true and format as a table
    $moduleInfoList | Where-Object { $_.Update } | Format-Table -AutoSize
}
else
{
    # No modules found
    Write-Warning "No matching modules found."
}

# Complete
Write-Host "Check is complete for updates to PowerShell Module(s)"