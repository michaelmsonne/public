<#	
	.NOTES
	===========================================================================
	 Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2022 v5.8.213
	 Created on:   	17-04-2024 20:21
	 Created by:   	Michael Morten Sonne
	 Organization: 	Sonne´s Cloud
	 Blog:          https://blog.sonnes.cloud
	 GitHub:        https://github.com/michaelmsonne
	 Filename:     	'Reset-DefenderForCloud.ps1'
	===========================================================================
	.DESCRIPTION
		PowerShell script to reset Defender for cloud configuration to defaults for etc. testing purposes.

        Resets Defender for cloud configuration to defaults for testing purposes.
        Takes prefix as a parameter to specify which Management Groups to target - the script will reset all subscriptions under that Management group.
        Alternatively, specify a single subscription with the subscriptionId parameter

        It will reset the Defender for Cloud configuration to the Free tier, turn off auto-provisioning, and remove the default log analytics workspace.

    .REQUREMENT
        - Azure subscription
        - Microsoft Azure PowerShell Az module (at least 'Az.Accounts' and 'Az.Security')
        - Right permissions to manage Defender for Cloud settings in the specified subscription(s) or Management Group(s) - 'Security Admin', 'Contributor' or 'Owner' role

    .CHANGELOG
        18-04-2024 - Michael Morten Sonne - Initial release

    .EXAMPLE
        PS> Reset-DefenderForCloud.ps1 -ManagementGroup 'lz-canary'

    .EXAMPLE
        PS> Reset-DefenderForCloud.ps1 -SubscriptionId 'XXXXXXXX-XXXXX-XXXX-XXXX-XXXXXXXXXXXX'

    .CHANGELOG
        18-04-2024 - Michael Morten Sonne - Initial release
#>

param (
    [Parameter(Mandatory=$false, HelpMessage="Specify the Management Group Prefix to target subscriptions under the Management Group")]
    [string]$ManagementGroupPrefix,
    [Parameter(Mandatory=$false, HelpMessage="Specify the Subscription ID to target a specific subscription")]
    [string]$SubscriptionId
)

function Invoke-Script
{
    <# 
    .SYNOPSIS
        Starts the script and checks for required modules and login to Azure

    .EXAMPLE 
        Invoke-Script -Banner
    #>

    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$false)][switch]$Checks = $null,
    [Parameter(Mandatory=$false)][switch]$CheckLogin = $null,
    [Parameter(Mandatory=$false)][switch]$Banner = $null)

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

        # Check Modules Az.Accounts and Az.Security is installed
        $Modules = Get-InstalledModule
        if ($Modules.Name -notcontains 'Az.Accounts' -and $Modules.Name -notcontains 'Az.Security')
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
                    if ($Modules.Name -contains 'Az.Accounts' -and $Modules.Name -contains 'Az.Security')
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
            Write-Host "Remember to login with Connect-AzAccount if you will reset Defender for Cloud!`n" -ForegroundColor Yellow
        }
    }

    # Banner
    if($Banner)
    {
        <#
        Write-Host "Please set your default subscription with " -ForegroundColor yellow -NoNewline 
        Write-Host "Set-AzContext " -ForegroundColor Magenta -NoNewline
        Write-Host "if you have multiple subscriptions. Functions will fail if you not set one. Use "  -ForegroundColor yellow -NoNewline 
        Write-Host "Get-AzSubscription" -ForegroundColor Magenta -NoNewline
        Write-Host " to get a list of your subscriptions.`n" -ForegroundColor Yellow
        #>
    }

    # If not logged in to Azure
    if(!$Checks -and !$CheckLogin -and !$Banner)
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

# Check if either ManagementGroupPrefix or SubscriptionId is specified
if (-not ($ManagementGroupPrefix -or $SubscriptionId)) {
    Write-Error "Specify either the -ManagementGroup for Management Group or -SubscriptionId when calling this script to target a specific subscription."
    exit
}

$subscriptions = @()

# Get all subscriptions under the specified Management Group Prefix
if ($ManagementGroupPrefix) {
    # Get all subscriptions under the specified Management Group Prefix
    $subscriptions = Get-AzManagementGroup | Where-Object { $_.Name -match $ManagementGroupPrefix } | ForEach-Object {
        # Query to get all subscriptions under the specified Management Group
        $query = "ResourceContainers | where type =~ 'microsoft.resources/subscriptions' | mv-expand managementGroupParent = properties.managementGroupAncestorsChain | where managementGroupParent.name =~ '$($_.Name)'"
        $graphResult = Search-AzGraph -Query $Query -ManagementGroup $_.Name -First 200
        if ($graphResult -and ($graphResult.properties.state -eq 'enabled')) {
            $graphResult.subscriptionid
        }
    } | Select-Object -Unique
}
# Get the specified subscription
elseif ($SubscriptionId) {
    $subscriptions = (Get-AzSubscription -SubscriptionId $SubscriptionId).Id
}

# Loop through each subscription and reset Defender for Cloud configuration
foreach ($subscription in $subscriptions) {
    Select-AzSubscription -Subscription $subscription

    # Reset Defender Plans to Free Tier
    Get-AzSecurityPricing | ForEach-Object {
        Write-Output "Resetting Defender for Cloud plan: $($_.Name) to the Free Tier"
        Set-AzSecurityPricing -Name $_.Name -PricingTier "Free"
    }

    # Turn auto-provisioning off
    Get-AzSecurityAutoProvisioningSetting | ForEach-Object {
        Write-Output "Turning off autoprovisioning for: $($_.name)"
        Set-AzSecurityAutoProvisioningSetting -Name $_.name
    }

    # Remove log analytics workspace
    Get-AzSecurityWorkspaceSetting | ForEach-Object {
        Write-Output "Removing default log analytics workspace: $($_.name)"
        Remove-AzSecurityWorkspaceSetting -Name $_.name
    }

    # Add more settings to configure below
}

# Check if connected to Azure and prompt for logout if connected to Azure before exiting the script
CheckConnectionToAzure