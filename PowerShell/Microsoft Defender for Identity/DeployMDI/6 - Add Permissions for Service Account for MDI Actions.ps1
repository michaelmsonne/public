<#	
	.NOTES
	===========================================================================
	 Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2022 v5.8.213
	 Created on:   	20-01-2024 13:38
	 Created by:   	Michael Morten Sonne
	 Organization: 	Sonne´s Cloud
	 Filename:     	"6 - Add Permissions for Service Account for MDI Actions.ps1"
	 Version:		1.0
	===========================================================================
	.DESCRIPTION
        This script will add permissions for the group which includes the gMSA accounts to the organization unit specified for MDI Actions.

    .EXAMPLE
        .\"6 - Add Permissions for Service Account for MDI Actions.ps1" ADGroupName "MDIActionAccounts" -OrganizationUnit "OU=Groups,DC=lab,DC=sonnes,DC=cloud"
#>

Param(
    [parameter(Mandatory = $true, HelpMessage = "Specify group which includes the gMSA account")]
    [string]$ADGroupName,
    [parameter(Mandatory = $true, HelpMessage = "Specify the OU to set permission to for gMSA account")]
    [string]$OrganizationUnit
)

# Import the required PowerShell module for Active Directory
Import-Module ActiveDirectory

try {
    # Show trying to add permissions for the group which includes the gMSA accounts to the organization unit specified for MDI Actions
    Write-Host "Trying to add permissions for $ADGroupName to $OrganizationUnit in your domain $env:USERDNSDOMAIN..." -ForegroundColor Yellow

    # Add permissions for the group which includes the gMSA accounts to the organization unit specified for MDI Actions
    $GroupDistinguishedName = $(Get-ADGroup $ADGroupName).DistinguishedName
    dsacls.exe "$($OrganizationUnit)" /I:S /G "$GroupDistinguishedName`:WP;pwdLastSet;user" "$GroupDistinguishedName`:CA;Reset Password;user" "$GroupDistinguishedName`:WP;userAccountControl;user" | Out-Null

    # Show a confirmation that permissions for the group which includes the gMSA accounts to the organization unit specified for MDI Actions has been added
    Write-Host "Done adding permissions for $ADGroupName to $OrganizationUnit in your domain $env:USERDNSDOMAIN..." -ForegroundColor Green
}
catch {
    # Show an error if the group could not be created
    Write-Host "Error creating permissions for MDI actions for $ADGroupName to $OrganizationUnit in your domain $env:USERDNSDOMAIN: $_" -ForegroundColor Red
    exit
}

# Script completed
Write-host "Script completed."