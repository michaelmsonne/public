<#	
	.NOTES
	===========================================================================
	 Created on:    10-02-2022 10:53
	 Created by:    Michael Morten Sonne
	 Organization: 	Sonne´s Cloud
	 Filename:     	BlockSharedMailboxSign-in.ps1
	===========================================================================
	.DESCRIPTION
		Block SharedMailbox direct Sign-on option on Shared mailboxes.
        Report and potentially disable interactive logins to shared mailboxes

        Prerequisites = 2
        1. Connected to Exchange Online
        2. Connect to Azure AD

      NOTES
         File Name: BlockSharedMailboxSign-in.ps1

      EXAMPLE
         PS > .\BlockSharedMailboxSign-in.ps1

      Updates:
        14-02-2022: Typo fixes
#>

## If you have running scripts that don't have a certificate, run this command once to disable that level of security
## set-executionpolicy -executionpolicy bypass -scope currentuser -force

## Variables
$secure = $true  ## $true = shared mailbox login will be automatically disabled, $false = report only
$systemmessagecolor = "cyan"
$processmessagecolor = "green"
$errormessagecolor = "red"

#Log Variables
$LogFilePath = "D:\Logs\BlockSharedMailboxSign-in\Logs\"
$LogFile = "D:\Logs\BlockSharedMailboxSign-in\Logs\Log_$((Get-Date).ToString("dd-MM-yyyy")).log"

# Log Cleanup
$Path = $LogFilePath
$Daysback = "-21"
$CurrentDate = Get-Date
$DatetoDelete = $CurrentDate.AddDays($Daysback)
Get-ChildItem $Path | Where-Object { $_.LastWriteTime -lt $DatetoDelete } | Remove-Item

#Keep a count for the summary at the end
$TotalCount = 0
$UpdatedCount = 0

Write-Output "$(Get-Date -format "G") ========Script Started========" | Out-File -Encoding Ascii $LogFile -Append
Write-host "========Script Started========"

#Check for module availability
# Exchange
Write-Output "$(Get-Date -format "G") Check for module availability..." | Out-File -Encoding Ascii $LogFile -Append
Write-host "Check for module availability..." 
$ExchangeOnlineManagement = (get-module ExchangeOnlineManagement -ListAvailable).Name 
if($null -eq $ExchangeOnlineManagement)
{
    Write-Output "$(Get-Date -format "G") Important: Module ExchangeOnlineManagement is unavailable. It is mandatory to have this module installed in the system to run the script successfully." | Out-File -Encoding Ascii $LogFile -Append
	Write-host -ForegroundColor $errormessagecolor "Important: Module ExchangeOnlineManagement is unavailable. It is mandatory to have this module installed in the system to run the script successfully."
	$confirm= Read-Host Are you sure you want to install module? [Y] Yes [N] No  
	if($confirm -match "[yY]")
	{
        Write-Output "$(Get-Date -format "G") Installing ExchangeOnlineManagement module..." | Out-File -Encoding Ascii $LogFile -Append
		Write-host "Installing ExchangeOnlineManagement module..."

		Install-Module ExchangeOnlineManagement -Repository PsGallery -Force -AllowClobber

        Write-Output "$(Get-Date -format "G") Required Module is installed in the machine Successfully." | Out-File -Encoding Ascii $LogFile -Append
		Write-host "Required Module is installed in the machine Successfully." -ForegroundColor Magenta 
	}
	elseif($confirm -cnotmatch "[yY]" )
	{ 
        Write-Output "$(Get-Date -format "G") Exiting. `nNote: ExchangeOnlineManagement module must be available in your system to run the script" | Out-File -Encoding Ascii $LogFile -Append
		Write-host "Exiting. `nNote: ExchangeOnlineManagement module must be available in your system to run the script" -ForegroundColor Red
		Exit 
	}
}

# Azure
$AzureAD = (get-module AzureAD -ListAvailable).Name 
if($null -eq $AzureAD)
{
    Write-Output "$(Get-Date -format "G") Important: Module AzureAD is unavailable. It is mandatory to have this module installed in the system to run the script successfully." | Out-File -Encoding Ascii $LogFile -Append
	Write-host -ForegroundColor $errormessagecolor "Important: Module AzureAD is unavailable. It is mandatory to have this module installed in the system to run the script successfully."
	$confirm= Read-Host Are you sure you want to install module? [Y] Yes [N] No  
	if($confirm -match "[yY]")
	{ 
        Write-Output "$(Get-Date -format "G") Installing AzureAD module..." | Out-File -Encoding Ascii $LogFile -Append
		Write-host "Installing AzureAD module..."

		Install-Module AzureAD -Repository PsGallery -Force -AllowClobber 

        Write-Output "$(Get-Date -format "G") Required Module is installed in the machine Successfully." | Out-File -Encoding Ascii $LogFile -Append
		Write-host "Required Module is installed in the machine Successfully." -ForegroundColor Magenta 
	}
	elseif($confirm -cnotmatch "[yY]" )
	{
        Write-Output "$(Get-Date -format "G") Exiting. `nNote: AzureAD module must be available in your system to run the script." | Out-File -Encoding Ascii $LogFile -Append
		Write-host "Exiting. `nNote: AzureAD module must be available in your system to run the script." -ForegroundColor Red
		Exit 
	}
}
Write-Output "$(Get-Date -format "G") Check for module availability done!" | Out-File -Encoding Ascii $LogFile -Append
Write-host -ForegroundColor $processmessagecolor "Check for module availability done!"

#Connect to Exchange Online:
Write-Output "$(Get-Date -format "G") Connecting to Exchange Online..." | Out-File -Encoding Ascii $LogFile -Append
Write-host -ForegroundColor $processmessagecolor "Connecting to Exchange Online..."

Connect-ExchangeOnline -CertificateThumbprint "3980725CCECCE038F06683C96A0AE55BFCA9059F" -AppId "1111111-2222-3333-4444-8f4c55d72859" -ShowBanner:$false -Organization tenant.onmicrosoft.com

#Test if connected to Exchange Online
Write-Output "$(Get-Date -format "G") Checking if connected to Exchange Online..." | Out-File -Encoding Ascii $LogFile -Append
Write-host -ForegroundColor $processmessagecolor "Checking if connected to Exchange Online..."

$getsessions = Get-PSSession | Select-Object -Property State, Name
$isconnected = (@($getsessions) -like '@{State=Opened; Name=ExchangeOnlineInternalSession*').Count -gt 0
If ($isconnected -ne "True")
{
    Write-Output "$(Get-Date -format "G") You're not connected to Exchange Online! Make sure you have ExchangeOnlineManagement mudule available on this system then use Connect-ExchangeOnline to establish connection!" | Out-File -Encoding Ascii $LogFile -Append
    Write-host -ForegroundColor $errormessagecolor "You're not connected to Exchange Online! Make sure you have ExchangeOnlineManagement mudule available on this system then use Connect-ExchangeOnline to establish connection!"; 
    exit;
}
else
{
    Write-Output "$(Get-Date -format "G") Done - Connected to Exchange Online!" | Out-File -Encoding Ascii $LogFile -Append
    Write-host -ForegroundColor $processmessagecolor "Done - Connected to Exchange Online!"
}

#Connect to Azure AD:
Write-Output "$(Get-Date -format "G") Connecting to Azure AD..." | Out-File -Encoding Ascii $LogFile -Append
Write-host "Connecting to Azure AD..."

Connect-AzureAD -TenantId "dddddddd-bbbb-4e17-8888-e7896594d2b2" -ApplicationId  "1111111-2222-3333-4444-8f4c55d72859" -CertificateThumbprint "3980725CCECCE038F06683C96A0AE55BFCA9059F"

#Test if connected to Azure AD
try
{
    $var = Get-AzureADTenantDetail
    Write-Output "$(Get-Date -format "G") Done - You're connected to AzureAD!" | Out-File -Encoding Ascii $LogFile -Append
    Write-host -ForegroundColor $processmessagecolor "Done - You're connected to AzureAD!";
}
catch [Microsoft.Open.Azure.AD.CommonLibrary.AadNeedAuthenticationException]
{
    Write-Output "$(Get-Date -format "G") You're not connected to AzureAD! Make sure you have AzureAD mudule available on this system then use Connect-AzureAD to establish connection." | Out-File -Encoding Ascii $LogFile -Append
    Write-host -ForegroundColor $errormessagecolor "You're not connected to AzureAD! Make sure you have AzureAD mudule available on this system then use Connect-AzureAD to establish connection."; 
    exit;
}

Write-Output "$(Get-Date -format "G") Getting shared mailboxes..." | Out-File -Encoding Ascii $LogFile -Append
Write-host -ForegroundColor $processmessagecolor "Getting shared mailboxes..."

$Mailboxes = Get-Mailbox -RecipientTypeDetails SharedMailbox -ResultSize:Unlimited

Write-Output "$(Get-Date -format "G") Start checking shared mailboxes..." | Out-File -Encoding Ascii $LogFile -Append
Write-host -ForegroundColor $processmessagecolor "Start checking shared mailboxes..."

foreach ($mailbox in $mailboxes)
{
    $Updated = $false
    $TotalCount++

    $accountdetails=get-azureaduser -objectid $mailbox.userprincipalname    ## Get the Azure AD account connected to shared mailbox
    If ($accountdetails.accountenabled)                                     ## if login is enabled
    {
        Write-Output $(Get-Date -format "G") $mailbox.displayname,"["$mailbox.userprincipalname"] - Direct Login ="$accountdetails.accountenabled | Out-File -Encoding Ascii $LogFile -Append
        Write-host -foregroundcolor $errormessagecolor $mailbox.displayname,"["$mailbox.userprincipalname"] - Direct Login ="$accountdetails.accountenabled

        If ($secure)
        {   ## if the secure variable is true disable login to shared mailbox
            Set-AzureADUser -ObjectID $mailbox.userprincipalname -AccountEnabled $false     ## Disable shared mailbox account
            $accountdetails=get-azureaduser -objectid $mailbox.userprincipalname            ## Get the Azure AD account connected to shared mailbox again

            Write-Output $(Get-Date -format "G") "*** SECURED "$mailbox.displayname,"["$mailbox.userprincipalname"] - Direct Login ="$accountdetails.accountenabled | Out-File -Encoding Ascii $LogFile -Append
            Write-host -ForegroundColor $processmessagecolor "*** SECURED "$mailbox.displayname,"["$mailbox.userprincipalname"] - Direct Login ="$accountdetails.accountenabled

            $Updated = $True
        }
    }
    else
    {
        ## If shared mailbox account is disabled
        Write-Output $(Get-Date -format "G") $mailbox.displayname,"["$mailbox.userprincipalname"] - Direct Login ="$accountdetails.accountenabled | Out-File -Encoding Ascii $LogFile -Append
        Write-host -foregroundcolor $processmessagecolor $mailbox.displayname,"["$mailbox.userprincipalname"] - Direct Login ="$accountdetails.accountenabled
    }

    # Update count for changed accounts
    If($Updated)
    {
        $UpdatedCount++
    }
}

Write-Output "$(Get-Date -format "G") Finish checking mailboxes!" | Out-File -Encoding Ascii $LogFile -Append
Write-host -ForegroundColor $processmessagecolor "`nFinish checking mailboxes!"

#Disconnect from Azure AD
Write-Output "$(Get-Date -format "G") Disconnecting Azure AD..." | Out-File -Encoding Ascii $LogFile -Append
Write-host -foregroundcolor $systemmessagecolor "Disconnecting Azure AD...`n"

Disconnect-AzureAD

#Test if connected to Azure AD
try
{
    Get-AzureADTenantDetail
    Write-Output "$(Get-Date -format "G") You're connected to AzureAD! - Run: Disconnect-AzureAD" | Out-File -Encoding Ascii $LogFile -Append
    Write-host -ForegroundColor $errormessagecolor "You're connected to AzureAD! - Run: Disconnect-AzureAD`n"; 
} 
catch [Microsoft.Open.Azure.AD.CommonLibrary.AadNeedAuthenticationException]
{
    Write-Output "$(Get-Date -format "G") Done - You're not connected to AzureAD!" | Out-File -Encoding Ascii $LogFile -Append
    Write-host -ForegroundColor $processmessagecolor "Done - You're not connected to AzureAD!`n"; 
}

#Disconnect from Exchange Online
Write-Output "$(Get-Date -format "G") Disconnecting Exchange Online..." | Out-File -Encoding Ascii $LogFile -Append
Write-host -foregroundcolor $systemmessagecolor "Disconnecting Exchange Online...`n"
Disconnect-ExchangeOnline -Confirm:$false

#Test if connected to Exchange Online
$getsessions = Get-PSSession | Select-Object -Property State, Name
$isconnected = (@($getsessions) -like '@{State=Opened; Name=ExchangeOnlineInternalSession*').Count -gt 0
If ($isconnected -ne "False")
{
    Write-Output "$(Get-Date -format "G") Done - You're not connected to Exchange Online!" | Out-File -Encoding Ascii $LogFile -Append
    Write-host -ForegroundColor $processmessagecolor "Done - You're not connected to Exchange Online!";
}

#Write the summary to the log file
Write-Output "$(Get-Date -format "G") ========Summary=======" | Out-File -Encoding Ascii $LogFile -Append
Write-Output "$(Get-Date -format "G") Accounts Checked: $TotalCount " | Out-File -Encoding Ascii $LogFile -Append
Write-Output "$(Get-Date -format "G") Accounts Updated: $UpdatedCount " | Out-File -Encoding Ascii $LogFile -Append

#Write the summary to the console
Write-Host "$(Get-Date -format "G") ========Summary=======" | Out-File -Encoding Ascii $LogFile -Append
Write-Host "$(Get-Date -format "G") Accounts Checked: $TotalCount " | Out-File -Encoding Ascii $LogFile -Append
Write-Host "$(Get-Date -format "G") Accounts Updated: $UpdatedCount " | Out-File -Encoding Ascii $LogFile -Append

Write-Output "$(Get-Date -format "G") =======Script completed=======" | Out-File -Encoding Ascii $LogFile -Append
Write-host -foregroundcolor $systemmessagecolor "=======Script completed!======="