<#	
	.NOTES
	===========================================================================
	 Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2022 v5.8.213
	 Created on:   	14-02-2024 17:21
	 Created by:   	Michael Morten Sonne
	 Organization: 	Sonne´s Cloud
	 Blog:          https://blog.sonnes.cloud
	 Filename:     	RotateDKIMKeysExchangeOnline.ps1
	===========================================================================
	.DESCRIPTION
		PowerShell script to rotate DKIM keys Exchange Online. The script connects to Exchange Online, rotates the DKIM keys for all enabled domains, and then disconnects from Exchange Online.

    .REQUREMENT
        - Exchange Online PowerShell Module
        - Global Administrator or Exchange Administrator role in Microsoft 365

    .CHANGELOG
        14-02-2024 - Michael Morten Sonne - Initial release

	.EXAMPLE
        .\RotateDKIMKeysExchangeOnline.ps1
#>

## Variables
$processmessagecolor = "green"
$errormessagecolor = "red"

#Check for module availability
Write-host "Check for module availability..." 
$ExchangeOnlineManagement = (get-module ExchangeOnlineManagement -ListAvailable).Name 
if($null -eq $ExchangeOnlineManagement)
{
	Write-host -ForegroundColor $errormessagecolor "Important: Module ExchangeOnlineManagement is unavailable. It is mandatory to have this module installed in the system to run the script successfully."
	$confirm= Read-Host Are you sure you want to install module? [Y] Yes [N] No  
	if($confirm -match "[yY]")
	{
		Write-host "Installing ExchangeOnlineManagement module..."

		Install-Module ExchangeOnlineManagement -Repository PsGallery -Force -AllowClobber

		Write-host "Required Module is installed in the machine Successfully." -ForegroundColor Magenta 
	}
	elseif($confirm -cnotmatch "[yY]" )
	{ 
		Write-host "Exiting. `nNote: ExchangeOnlineManagement module must be available in your system to run the script" -ForegroundColor Red
		Exit 
	}
}

# Import the Exchange Online module
Import-Module ExchangeOnlineManagement

# Connect to Exchange Online
Connect-ExchangeOnline -ShowBanner:$false # -Organization yourorg.onmicrosoft.com # Replace yourorg.onmicrosoft.com with your organization's name

#Test if connected to Exchange Online
Write-host "Checking if connected to Exchange Online..."

# Check if connected to Exchange Online
$ModulesLoaded = Get-Module | Select-Object Name
If (!($ModulesLoaded -match "ExchangeOnlineManagement")) {
   # Not connected to Exchange Online
   Write-host -ForegroundColor $errormessagecolor "You're not connected to Exchange Online! Make sure you have ExchangeOnlineManagement mudule available on this system then use Connect-ExchangeOnline to establish connection!"; 
   exit;
}
else
{
    # Connected to Exchange Online
    Write-host -ForegroundColor $processmessagecolor "Done - Connected to Exchange Online!"
}

#Get all domains to rotete DKIM keys for all enabled domains in the tenant that are not *.onmicrosoft.com
$Domains = (Get-DkimSigningConfig | Where-Object { $_.Domain -NotLike '*.onmicrosoft.com' -and $_.Enabled -like 'True'}).domain

# Rotate the DKIM keys for each domain in the list there is active
foreach ($domain in $domains){
    # Rotate the DKIM keys
    Write-host -ForegroundColor $processmessagecolor "Rotating the DKIM keys for $domain..."
    Rotate-DkimSigningConfig -KeySize 2048 -Identity $domain
}

# Done - Rotate the DKIM keys for all enabled domains
Write-host -ForegroundColor $processmessagecolor "Done - Rotate the DKIM keys for all enabled domains!"

# Disconnect from Exchange Online
Disconnect-ExchangeOnline -Confirm:$false