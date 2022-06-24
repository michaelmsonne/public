<#  
    .NOTES
    ===========================================================================
	Created with:  Microsoft Visual Studio 2022
	Created on:    09-12-2021 07:32
	Updated on:    21-12-2021 12:34
	Created by:    Michael Morten Sonne
	Organization:  
	Name:          Azure Admin Report
	Filename:      AzureADAdminRoleReport.ps1
    ===========================================================================
    .DESCRIPTION
        This script exports Microsoft 365 admin role group membership to CSV format (supports roles assiged to groups)

	.SYNTAX
	Export Office 365 Administrator Report: 
	By default, the script delivers all the admins and their assigned management roles. To get admin report, run the script as follows.
	.\AdminReport.ps1
	This format will help in encountering both MFA enabled and Non-MFA admin accounts.

	Get Office 365 Admin Roles and the Members: 
	Next, as an administrator, we know you will be interested on the Azure Active Directory Administrator Roles-based report. We have geared up the script to deliver the roles report also. 
	Using the -RoleBasedAdminReport switch, you will achieve the Azure active directory roles report with  associated administrators. If the report doesn"t show the role,
	it means that role doesn"t have the administrator. To get role based admin report, execute the script as follows:
	.\AdminReport.ps1 -RoleBasedAdminReport

	Get Azure AD Roles for a User: 
	You need to provide the UserPrincipalName to find the management roles assigned to the user. This report will replace the multiple executions of Get-MsolRole and Get-MsolRoleMember
	for every single admin in the tenant. To identify the roles assigned to the user(s), run the script with -AdminName param.
	.\AdminReport.ps1 -AdminName chris@contoso.com,karol@contoso.com

	List all Admins of a Specific Role: 
	Like the "AdminName," you can provide the role names in the -RoleName parameter. The script will give you the administrators for the given role(s). If there are no administrators for
	the specified role, the report will skip that. 
	.\AdminReport.ps1 -RoleName "Helpdesk Administrator,Service Support Administrator"

	List all Global Administrators in Office 365 Tenant:
	How to find what users have been assigned as global admins? 
	To deal this right, you can use the -RoleName param with "Company Administrator".
	.\AdminReport.ps1 -RoleName "Company Administrator"

	Get Scheduled Office 365 Admin Report (not for MFA):
	To schedule this script, you can use task scheduler by explicitly mentioning the credential. Take a look at the below format to get the scheduled Admin Report.
	.\AdminReport.ps1 -UserName admin@contoso.com -Password <Password>
#>

param ( 
[string] $UserName = $null, 
[string] $Password = $null, 
[switch] $RoleBasedAdminReport, 
[String] $AdminName = $null, 
[String] $RoleName = $null) 

#Check for module availability
Write-Host "Check for module availability..." 
$MSOnline = (get-module MsOnline -ListAvailable).Name 
if($MSOnline -eq $null)
{
	Write-host "Important: Module MsOnline is unavailable. It is mandatory to have this module installed in the system to run the script successfully." -ForegroundColor Red
	$confirm= Read-Host Are you sure you want to install module? [Y] Yes [N] No  
	if($confirm -match "[yY]")
	{ 
		Write-host "Installing MsOnline module..."
		Install-Module MsOnline -Repository PsGallery -Force -AllowClobber 
		Write-host "Required Module is installed in the machine Successfully" -ForegroundColor Green
	}
	elseif($confirm -cnotmatch "[yY]" )
	{ 
		Write-host "Exiting. `nNote: MSOnline module must be available in your system to run the script" -ForegroundColor Red
		Exit 
	}
}
Write-Host "Check for module availability done - MsOnline module exits!" -ForegroundColor Green

#Importing Module by default will avoid the cmdlet unrecognized error 
Import-Module MSOnline -Force 
Write-Host "Connecting to Office 365..."

#Storing credential in script for scheduling purpose/Passing credential as parameter   
if(($UserName -ne "") -and ($Password -ne ""))
{
	$securedPassword = ConvertTo-SecureString -AsPlainText $Password -Force   
	$credential  = New-Object System.Management.Automation.PSCredential $UserName,$securedPassword
	Write-Host "Using provides credentials..."
	Connect-MsolService -Credential $credential | Out-Null 
}
else   
{   
	Write-Host "Promting for credentials..."
	Connect-MsolService
}

Write-Host "Testing connecting to Office 365..."
if( $null -eq (Get-MsolCompanyInformation -ErrorAction SilentlyContinue) ) {
    Write-Host "Connecting to Office 365 error!" -ForegroundColor Red
} else {
    Write-Host "Connecting to Office 365 success!" -ForegroundColor Green
}

Write-Host "Preparing admin report..." 
$admins=@() 
$list = @() 
$outputCsv=".\AzureADAdminReport_$((Get-Date).ToString('yyyy-MM-dd_HH-mm-ss')).csv"

function process_Admin{ 
$roleList= (Get-MsolUserRole -UserPrincipalName $admins.UserPrincipalName | Select-Object -ExpandProperty Name) -join ',' 
if($admins.IsLicensed -eq $true)
{
	$licenseStatus = "Licensed" 
}
else
{ 
	$licenseStatus= "Unlicensed" 
}
if($admins.BlockCredential -eq $true)
{ 
	$signInStatus = "Blocked" 
}
else
{ 
	$signInStatus = "Allowed" 
}
$displayName= $admins.DisplayName 
$UPN= $admins.UserPrincipalName 
Write-Progress -Activity "Currently processing: $displayName" -Status "Updating CSV file"
if($roleList -ne ""){ 
	$exportResult=@{'AdminEmailAddress'=$UPN;'AdminName'=$displayName;'RoleName'=$roleList;'LicenseStatus'=$licenseStatus;'SignInStatus'=$signInStatus} 
	$exportResults= New-Object PSObject -Property $exportResult         
	$exportResults | Select-Object 'AdminName','AdminEmailAddress','RoleName','LicenseStatus','SignInStatus' | Export-csv -path $outputCsv -NoType -Append} 
} 

function process_Role{ 
$adminList = Get-MsolRoleMember -RoleObjectId $roles.ObjectId #Email,DisplayName,Usertype,islicensed 
$displayName = ($adminList | Select-Object -ExpandProperty DisplayName) -join ',' 
$UPN = ($adminList | Select-Object -ExpandProperty EmailAddress) -join ',' 
$RoleName= $roles.Name 
Write-Progress -Activity "Processing $RoleName role" -Status "Updating CSV file"
if($displayName -ne "")
{ 
	$exportResult=@{'RoleName'=$RoleName;'AdminEmailAddress'=$UPN;'AdminName'=$displayName} 
	$exportResults= New-Object PSObject -Property $exportResult 
	$exportResults | Select-Object 'RoleName','AdminName','AdminEmailAddress' | Export-csv -path $outputCsv -NoType -Append} 
} 

#Check to generate role based admin report
if($RoleBasedAdminReport.IsPresent)
{ 
	Get-MsolRole | ForEach-Object
	{ 
		$roles= $_ #$ObjId = $_.ObjectId;$_.Name 
		process_Role
	}
}

#Check to get admin roles for specific user
elseif($AdminName -ne "")
{ 
	$allUPNs = $AdminName.Split(",") 
	ForEach($admin in $allUPNs) 
	{ 
		$admins = Get-MsolUser -UserPrincipalName $admin -ErrorAction SilentlyContinue 
		if( -not $?)
		{ 
			Write-host "$admin is not available. Please check the input" -ForegroundColor Red 
		}
		else
		{ 
			process_Admin
		}
	}
}

#Check to get all admins for a specific role
elseif($RoleName -ne "")
{
	$RoleNames = $RoleName.Split(",") 
	ForEach($name in $RoleNames) 
	{ 
		$roles= Get-MsolRole -RoleName $name -ErrorAction SilentlyContinue 
		if( -not $?)
		{ 
			Write-Host "$name role is not available. Please check the input" -ForegroundColor Red 
		}
		else
		{ 
			process_Role 
		} 
	} 
}

#Generating all admins report
else
{ 
Get-MsolUser -All | ForEach-Object { 
$admins= $_ 
process_Admin}} 
write-Host "`nThe script executed successfully" -ForegroundColor Green
Write-Host "`nDisconnecting from MSOnline..."
[Microsoft.Online.Administration.Automation.ConnectMsolService]::ClearUserSessionState()
if( $null -eq (Get-MsolCompanyInformation -ErrorAction SilentlyContinue) ) {
    Write-Host "Testing if disconnected from MSOnline done - session is cleared from PowerShell!" -ForegroundColor Green
} else {
    Write-Host "Disconnecting from MSOnline error!" -ForegroundColor Red
}

#Open output file after execution 
if((Test-Path -Path $outputCsv) -eq "True") {
Write-Host "`nThe Output file availble in $outputCsv" -ForegroundColor Green
write-Host "`nPromting to user: Do you want to open output file?"
$prompt = New-Object -ComObject wscript.shell    
$userInput = $prompt.popup("Do you want to open output file?",` 0,"Open Output File",4)    
If ($userInput -eq 6) {
	Invoke-Item "$OutputCSV"}
	write-Host "User pressed yes to open exported .csv file"
	write-Host "`nOpening .csv file in default viewer for .csv...`n" -ForegroundColor Green
}
else
{
	write-Host "User pressed no to open exported .csv file`n"
}
