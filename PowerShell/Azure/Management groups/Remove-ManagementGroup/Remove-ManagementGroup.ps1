<#	
	.NOTES
	===========================================================================
	 Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2022 v5.8.213
	 Created on:   	23-03-2024 21:41
	 Created by:   	Michael Morten Sonne
	 Organization: 	Sonne´s Cloud
	 Blog:          https://blog.sonnes.cloud
	 GitHub:        https://github.com/michaelmsonne
	 Filename:     	Remove-ManagementGroup.ps1
	===========================================================================
	.DESCRIPTION
		Remove all management groups in hierarchy up to and including prefix

    .REQUREMENT
        - Azure subscription
        - Microsoft Azure PowerShell Az module (at least 'Az.Accounts' and 'Az.Resources')
        - Right permissions to move and remove management groups and subscriptions

    .CHANGELOG
        23-03-2024 - Michael Morten Sonne - Initial release
    
	.EXAMPLE
        Delete all management groups with a specific prefix and move their subscriptions to the root
        PS C:\> .\Remove-ManagementGroup.ps1 -Prefix "MyPrefix"
#>

[CmdletBinding(SupportsShouldProcess)]
param (
    [Parameter(Mandatory = $true, Position = 0)]
    [String]
    $Prefix
)

function Invoke-Script
{
    <# 
    .SYNOPSIS
        Starts the script and checks for required modules and login to Azure

    .EXAMPLE
        Invoke-Script -Checks
    #>

    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$false)][switch]$Checks = $null,
    [Parameter(Mandatory=$false)][switch]$CheckLogin = $null)

    # Check if the user is logged in to Azure
    If ($CheckLogin)
    {
        #Login Check
        $AZSUser = Get-AzContext
        if(!$AZSUser)
        {
            # Prompt the user to login to Azure
            Write-Host "Please login with Connect-AzAccount - see popup promt" -ForegroundColor Yellow
            
            # Try to connect to Azure via Az module
            try{
                # Connect to Azure via Az module
                Connect-AzAccount
            }catch{
                # Failed to connect to Azure
                Write-Host "Failed to call Connect-AzAccount: $($_.Exception.Message)" -ForegroundColor Red
                return $False
            }
        }
    }

    # Check if the required modules are installed and supported PowerShell version
    If($Checks)
    {
        # Set ErrorActionPreference to Stop
        $ErrorActionPreference = "Stop"

        # Check for supported PowerShell version
        $Version = $PSVersionTable.PSVersion.Major
        If ($Version -lt 5)
        {
            # PowerShell version is not supported - 5.1 or later is required
            Write-Host "Az requires at least PowerShell 5.1 - Exiting..." -ForegroundColor Red
            Exit
        }

        # Check Modules Az.Accounts and Az.Resources is installed
        $Modules = Get-InstalledModule
        if ($Modules.Name -notcontains 'Az.Accounts' -and $Modules.Name -notcontains 'Az.Resources')
        {
            # Az PowerShell Modules not installed - prompt the user to install the modules
            Write-host "Install Az PowerShell Modules?" -ForegroundColor Yellow 
            $Readhost = Read-Host " ( y / n ) " 

            # Install Az PowerShell Modules if the user confirms
            if ($ReadHost -eq 'y' -or $Readhost -eq 'yes')
            {
                try {
                    # Install Az PowerShell Modules
                    Install-Module -Name Az -AllowClobber -Scope CurrentUser

                    # Get installed modules
                    $Modules = Get-InstalledModule

                    # Check if the Az PowerShell Modules are installed
                    if ($Modules.Name -contains 'Az.Accounts' -and $Modules.Name -contains 'Az.Resources')
                    {
                        Write-Host "Successfully installed Az modules" -ForegroundColor Green
                    }
                }
                catch {
                    # Failed to install Az PowerShell Modules show error message
                    Write-Host "Failed to install Az modules: $($_.Exception.Message)" -ForegroundColor Red
                }                
            }
            # Exit if the user does not confirm to install the Az PowerShell Modules
            if ($ReadHost -eq 'n' -or $Readhost -eq 'no') 
            {
                # User did not confirm to install the Az PowerShell Modules - exit
                Write-Host "Az PowerShell not installed, This script cannot operate without this modules, exiting..." -ForegroundColor Red
                Exit
            }
        }
        else
        {
            # Az PowerShell Modules needed is installed!
            Write-Host "Az PowerShell Modules needed is installed - good!`n" -ForegroundColor Green
        }

        #Login Check
        $AZSStartUser = Get-AzContext
        if(!$AZSStartUser)
        {
            Write-Host "Remember to login with Connect-AzAccount if you will remove management groups!`n" -ForegroundColor Yellow
        }
    }

    # If not logged in to Azure
    if(!$Checks -and !$CheckLogin)
    {
        Write-Host "Please login with Connect-AzAccount" -ForegroundColor Red
	}            
}

function CheckConnectionToAzure {
    # Check if connected to Azure
    $azContext = Get-AzContext -ErrorAction SilentlyContinue

    # If connected to Azure
    if ($azContext) {
        # If connected to Azure - prompt for logout if connected to Azure before exiting the script
        Write-Host "You are currently connected to Azure." -ForegroundColor Yellow
        $confirmLogout = Read-Host "Do you want to log out from Azure? (Type 'yes' to confirm)"

        # Check user confirmation
        if ($confirmLogout.ToLower() -eq 'yes' -or $confirmLogout.ToLower() -eq 'y') {
            try {
                # Log out from Azure
                Disconnect-AzAccount

                # Show logged out from Azure
                Write-Host "Logged out from Azure." -ForegroundColor Green
            } catch {
                # Show error message if failed to log out from Azure
                Write-Host "Not logged out from Azure." -ForegroundColor Red
                Write-Host "An error occurred while logging out from Azure: $($_.Exception.Message)" -ForegroundColor Red
            }
        } else {
            # Show message if the user selected to not logout from Azure - Session is active in your console
            Write-Host "You selected to not logout from Azure - Session is active in your console." -ForegroundColor Red
        }
    } else {
        # Show message if not connected to Azure - do nothing
        Write-Host "You are not currently connected to Azure." -ForegroundColor Green
    }
}

# Start the script and check for required modules
Invoke-Script -Checks

# Get the tenant ID
$tenantId = (Get-AzContext).Tenant.Id

# Initialize flag variable to track if any work is done
$workDone = $false

# Get all management groups with names matching the specified prefix
Get-AzManagementGroup | Where-Object Name -match "^$Prefix" | Sort-Object -Descending | ForEach-Object {
    # Get the management group name and display name
    $managementGroupName = $PSItem.Name
    $managementGroupDisplayName = $PSItem.DisplayName

    # Inform about checking subscriptions under the current management group
    Write-Output "Checking subscription(s) under management group '$managementGroupDisplayName'..."

    try {
        # Iterate through subscriptions under the current management group
        Get-AzManagementGroupSubscription -GroupName $managementGroupName | ForEach-Object {
            # Get the subscription ID
            $subscriptionId = $PSItem.Id -split "/" | Select-Object -Last 1

            # Inform about moving subscription to the root
            Write-Output "Moving subscription '$managementGroupDisplayName' to /..."

            try {
                # Move the subscription to the root
                New-AzManagementGroupSubscription -GroupName $tenantId -SubscriptionId $subscriptionId -ErrorAction Stop | Out-Null
                Write-Output "Subscription '$subscriptionId' moved successfully."
            } catch {
                Write-Output "Failed to move subscription '$subscriptionId': $_"
            }
        }

        # Inform about removing management group
        Write-Output "Removing management group '$managementGroupDisplayName'..."

        try {
            # Remove the management group
            Remove-AzManagementGroup -GroupName $managementGroupName -ErrorAction Stop | Out-Null
            Write-Output "Management group '$managementGroupDisplayName' removed successfully."

            $workDone = $true # Set flag to true if any work has been done
        } catch {
            Write-Output "Failed to remove management group '$managementGroupDisplayName': $_"
        }
    } catch {
        Write-Output "Error occurred while processing management group '$managementGroupDisplayName': $_"
    }
}

# Inform about the completion of the script or no management groups found with the specified prefix
if ($workDone) {
    # Inform about the completion of the script
    Write-Output "All management groups with prefix '$Prefix' have been removed and their subscriptions have been moved."
}
else {
    # Inform about no management groups found with the specified prefix
    Write-Output "No management groups with prefix '$Prefix' found."
}

# Check if connected to Azure and prompt for logout if connected to Azure before exiting the script
CheckConnectionToAzure