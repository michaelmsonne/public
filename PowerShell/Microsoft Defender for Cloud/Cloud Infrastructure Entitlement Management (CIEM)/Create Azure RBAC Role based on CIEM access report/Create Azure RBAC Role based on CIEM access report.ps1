<#	
	.NOTES
	===========================================================================
	 Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2022 v5.8.213
	 Created on:   	05-01-2024 18:41
	 Created by:   	Michael Morten Sonne
	 Organization: 	Sonne´s Cloud
     Blog:          https://blog.sonnes.cloud
	 Filename:     	'Create Azure RBAC Role based on CIEM access report - used access scopes.ps1'
	===========================================================================
	.DESCRIPTION
		PowerShell script to create custom Azure RBAC role based on output from CIEM access report in CSV format.

        The script will prompt for the name and description of the custom role to be created.
        The script will prompt for confirmation before creating the custom role.
        The script will prompt for the path to the CSV file containing the CIEM access report.
        The script will prompt for the resource group or subscription to scope the custom role to.
        The script will prompt for confirmation before creating the custom role.

    .REQUREMENT
        - Azure subscription
        - Microsoft Azure PowerShell Az module (at least 'Az.Accounts' and 'Az.Resources')
        - Right permissions to create custom Azure RBAC roles (Owner or User Access Administrator, or custom role with Microsoft.Authorization/roleDefinitions/write permission)

    .CHANGELOG
        05-01-2024 - Michael Morten Sonne - Initial release
        06-02-2024 - Michael Morten Sonne - Some small changes to the script and add GridView for large datasets if needed (some work done too before here but not documented)

	.EXAMPLE
        Create a custom Azure RBAC role based on CIEM access report in CSV format and display the unique access scopes and count in the console
        PS C:\> .\'Create Azure RBAC Role based on CIEM access report - used access scopes.ps1' -CsvFilePath "C:\Users\MichaelMortenSonne\Actions.csv"

        Create a custom Azure RBAC role based on CIEM access report in CSV format and display the unique access scopes and count in a grid view (usefull for large datasets)
        PS C:\> .\'Create Azure RBAC Role based on CIEM access report - used access scopes.ps1' -GridView -CsvFilePath "C:\Users\MichaelMortenSonne\Actions.csv"
#>

param (
    [Parameter(Mandatory=$true)]
    [string]$CsvFilePath,

    [Parameter(Mandatory=$false)]
    [switch]$GridView = $null,

    [Parameter(Mandatory=$false)]
    [string]$ResourceGroup
)

function Invoke-Script
{
    <# 
    .SYNOPSIS
        Displays info about this script and its functions.

    .EXAMPLE 
        Invoke-Script -Banner
    #>

    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$false)][switch]$Checks = $null,
    [Parameter(Mandatory=$false)][switch]$CheckLogin = $null,
    [Parameter(Mandatory=$false)][switch]$Banner = $null)

    If ($CheckLogin)
    {
        #Login Check
        $AZSUser = Get-AzContext
        if(!$AZSUser)
        {
            Write-Host "Please login with Connect-AzAccount - see popup promt" -ForegroundColor Yellow
            
            # Try to connect to Azure via Az module
            try{
                Connect-AzAccount
            }catch{
                Write-Host "Failed to call Connect-AzAccount: $($_.Exception.Message)" -ForegroundColor Red
                return $False
            }
        }
    }

    If($Checks)
    {
        $ErrorActionPreference = "Stop"
        $Version = $PSVersionTable.PSVersion.Major
        If ($Version -lt 5)
        {
            Write-Host "Az requires at least PowerShell 5.1 - Exiting..." -ForegroundColor Red
            Exit
        }

        # Check Modules Az.Accounts and Az.Resources is installed
        $Modules = Get-InstalledModule
        if ($Modules.Name -notcontains 'Az.Accounts' -and $Modules.Name -notcontains 'Az.Resources')
        {
            Write-host "Install Az PowerShell Modules?" -ForegroundColor Yellow 
            $Readhost = Read-Host " ( y / n ) " 
            if ($ReadHost -eq 'y' -or $Readhost -eq 'yes')
            {
                Install-Module -Name Az -AllowClobber -Scope CurrentUser
                $Modules = Get-InstalledModule       
                if ($Modules.Name -contains 'Az.Accounts' -and $Modules.Name -contains 'Az.Resources')
                {
                    Write-Host "Successfully installed Az modules" -ForegroundColor Green
                }
            }	
            if ($ReadHost -eq 'n' -or $Readhost -eq 'no') 
            {
                Write-Host "Az PowerShell not installed, This script cannot operate without this modules, exiting..." -ForegroundColor Red
                Exit
            }
        }
        else
        {
            Write-Host "Az PowerShell Modules needed is installed - good!`n" -ForegroundColor Green
        }

        #Login Check
        $AZSStartUser = Get-AzContext
        if(!$AZSStartUser)
        {
            Write-Host "Remember to login with Connect-AzAccount if you will create a custom role in Azure RBAC!`n" -ForegroundColor Yellow
        }
    }
    if($Banner)
    {
            Write-Host "Please set your default subscription with " -ForegroundColor yellow -NoNewline 
            Write-Host "Set-AzContext " -ForegroundColor Magenta -NoNewline
            Write-Host "if you have multiple subscriptions. Functions will fail if you not set one. Use "  -ForegroundColor yellow -NoNewline 
            Write-Host "Get-AzSubscription" -ForegroundColor Magenta -NoNewline
			Write-Host " to get a list of your subscriptions.`n" -ForegroundColor Yellow
    }
    if(!$Checks -and !$CheckLogin -and !$Banner)
    {
        Write-Host "Please login with Connect-AzAccount" -ForegroundColor Red
	}            
}

function CheckConnectionToAzure {
    # Check if connected to Azure
    $azContext = Get-AzContext -ErrorAction SilentlyContinue

    if ($azContext) {
        Write-Host "You are currently connected to Azure." -ForegroundColor Yellow

        $confirmLogout = Read-Host "Do you want to log out from Azure? (Type 'yes' to confirm)"

        if ($confirmLogout.ToLower() -eq 'yes' -or $confirmLogout.ToLower() -eq 'y') {
            try {
                Disconnect-AzAccount
                Write-Host "Logged out from Azure." -ForegroundColor Green
            } catch {
                Write-Host "Not logged out from Azure." -ForegroundColor Red
                Write-Host "An error occurred while logging out from Azure: $($_.Exception.Message)" -ForegroundColor Red
            }
        } else {
            Write-Host "You selected to not logout from Azure - Session is active in your console." -ForegroundColor Red
        }
    } else {
        Write-Host "You are not currently connected to Azure." -ForegroundColor Green
    }
}

# Start the script and check for required modules
Invoke-Script -Checks

# Read the CSV file
$data = Import-Csv -Path $CsvFilePath

# Extracting just the filename from the $CsvFilePath
$csvFileName = (Get-Item $CsvFilePath).Name

# Filter out rows where 'used' is not empty
$usedData = $data | Where-Object { $_.used -ne "" } | Select-Object -ExpandProperty used

if ($usedData.Count -gt 0) {
    # Filter out empty values and split the access scopes
    $accessScopes = $usedData -split ',' | Where-Object { $_ -ne "" } | ForEach-Object { $_.Trim() }

    # Count the unique access scopes
    $uniqueAccessScopes = $accessScopes | Sort-Object -Unique
    $numberOfAccessScopes = $uniqueAccessScopes.Count

    # Display the unique access scopes and count in a grid view or in the console
    if ($GridView){
        # Create a custom object with renamed columns
        $customuniqueAccessScopes = $uniqueAccessScopes | ForEach-Object {
            [PSCustomObject]@{
                'Custom Azure RBAC Scopes to use in new role' = $_ # Custom column name
            }
        }

        # Display the unique access scopes and count in a grid view
        $customuniqueAccessScopes | Out-GridView -Title "$numberOfAccessScopes Unique access scopes discovered within the exported file '$csvFileName' and are intended for use in a new custom Azure RBAC role" -PassThru
    }
    else {
        # Display the unique access scopes and count
        Write-Host "Unique access scopes were discovered within the exported file '$csvFileName' and are intended for use in a new custom Azure RBAC role:`n"
        
        # Display the unique access scopes
        $uniqueAccessScopes

        # Display the number of unique access scopes
        Write-Host "`nNumber of Unique Access Scopes: " -NoNewline
        Write-Host $numberOfAccessScopes `n -ForegroundColor Yellow
    }
} else {
    # No 'used' data found in the CSV file - abort
    Write-Host "`nNo 'used' data found. Aborting..."
    exit
}

# Prompt user confirmation
$confirmation = Read-Host "Do you want to proceed and create a custom role in Azure RBAC? (Type 'yes' to confirm)"

# Check user confirmation
if ($confirmation.ToLower() -eq "yes" -or $confirmation.ToLower() -eq "y") {
    # Create a new role definition - Ensure you have the necessary permissions and provide the required role definition details

    # Start the script and check for login
    Invoke-Script -CheckLogin

    # Get the current subscription data
    $subscriptionID = (Get-AzContext).Subscription.Id
    $subscriptionName = (Get-AzContext).Subscription.Name

    # Show the current Azure Subscription
    Write-Host "Current Azure Subscription for your session:`nID: $subscriptionID`nName: $subscriptionName`n"

    # Start the script and check for used subscription
    Invoke-Script -Banner

    # Prompt user confirmation
    $confirmation = Read-Host "Is the Azure Subscription above the correct one you will work with? (Type 'yes' to confirm)"

    # Check user confirmation
    if ($confirmation.ToLower() -eq "yes" -or $confirmation.ToLower() -eq "y")
    {
        # Ask for role name
        $var_RoleName = Read-Host "Enter the name of the custom role to be created"

        # Ask for role description
        $var_Description = Read-Host "Enter the description of the custom role to be created"

        # Create a new role definition - copy the role definition and update the name, description, and access scopes to match the exported data from CIEM
        $role = Get-AzRoleDefinition -Name "Reader"

        # Blank the ID to prevent overwriting
        $role.Id = $null
        $role.Name = $var_RoleName
        $role.Description = $var_Description

        # Initialize actions collections
        $role.actions = New-Object System.Collections.Generic.List[string]

        # Add access scopes to the role definition
        foreach ($scope in $accessScopes) {
            $role.Actions.Add($scope)
        }

        # Clear the assignable scopes and add the subscription ID as the assignable scope
        $role.AssignableScopes.Clear()
        if (-not $ResourceGroup) {
            $role.AssignableScopes.Add("/subscriptions/$subscriptionID")
        } else {
            $role.AssignableScopes.Add("/subscriptions/$subscriptionID/resourceGroups/$ResourceGroup/")
        }

        # Display the role definition is about to be created
        Write-Host "Creating custom role in Azure RBAC..." -ForegroundColor Yellow

        # Create the custom role in Azure RBAC
        try {
            New-AzRoleDefinition -Role $role
            Write-Host "Azure role definition created successfully.`n" -ForegroundColor Green
        } catch {
            Write-Host "An error occurred while creating the Azure role definition: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    else {
        Write-Host "Operation canceled. Set the current Azure Subscription to use."
    }    
} else {
    Write-Host "Operation canceled. Custom role creation aborted!"
}

# Check if connected to Azure and prompt for logout if connected to Azure before exiting the script
CheckConnectionToAzure