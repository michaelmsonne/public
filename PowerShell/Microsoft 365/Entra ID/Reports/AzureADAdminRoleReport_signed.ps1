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

# SIG # Begin signature block
# MIIm2wYJKoZIhvcNAQcCoIImzDCCJsgCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCB/HOCCC4DbfQBd
# +DBiN+wBXquE+6lofJDTPntSGUjjfaCCH8gwggVvMIIEV6ADAgECAhBI/JO0YFWU
# jTanyYqJ1pQWMA0GCSqGSIb3DQEBDAUAMHsxCzAJBgNVBAYTAkdCMRswGQYDVQQI
# DBJHcmVhdGVyIE1hbmNoZXN0ZXIxEDAOBgNVBAcMB1NhbGZvcmQxGjAYBgNVBAoM
# EUNvbW9kbyBDQSBMaW1pdGVkMSEwHwYDVQQDDBhBQUEgQ2VydGlmaWNhdGUgU2Vy
# dmljZXMwHhcNMjEwNTI1MDAwMDAwWhcNMjgxMjMxMjM1OTU5WjBWMQswCQYDVQQG
# EwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMS0wKwYDVQQDEyRTZWN0aWdv
# IFB1YmxpYyBDb2RlIFNpZ25pbmcgUm9vdCBSNDYwggIiMA0GCSqGSIb3DQEBAQUA
# A4ICDwAwggIKAoICAQCN55QSIgQkdC7/FiMCkoq2rjaFrEfUI5ErPtx94jGgUW+s
# hJHjUoq14pbe0IdjJImK/+8Skzt9u7aKvb0Ffyeba2XTpQxpsbxJOZrxbW6q5KCD
# J9qaDStQ6Utbs7hkNqR+Sj2pcaths3OzPAsM79szV+W+NDfjlxtd/R8SPYIDdub7
# P2bSlDFp+m2zNKzBenjcklDyZMeqLQSrw2rq4C+np9xu1+j/2iGrQL+57g2extme
# me/G3h+pDHazJyCh1rr9gOcB0u/rgimVcI3/uxXP/tEPNqIuTzKQdEZrRzUTdwUz
# T2MuuC3hv2WnBGsY2HH6zAjybYmZELGt2z4s5KoYsMYHAXVn3m3pY2MeNn9pib6q
# RT5uWl+PoVvLnTCGMOgDs0DGDQ84zWeoU4j6uDBl+m/H5x2xg3RpPqzEaDux5mcz
# mrYI4IAFSEDu9oJkRqj1c7AGlfJsZZ+/VVscnFcax3hGfHCqlBuCF6yH6bbJDoEc
# QNYWFyn8XJwYK+pF9e+91WdPKF4F7pBMeufG9ND8+s0+MkYTIDaKBOq3qgdGnA2T
# OglmmVhcKaO5DKYwODzQRjY1fJy67sPV+Qp2+n4FG0DKkjXp1XrRtX8ArqmQqsV/
# AZwQsRb8zG4Y3G9i/qZQp7h7uJ0VP/4gDHXIIloTlRmQAOka1cKG8eOO7F/05QID
# AQABo4IBEjCCAQ4wHwYDVR0jBBgwFoAUoBEKIz6W8Qfs4q8p74Klf9AwpLQwHQYD
# VR0OBBYEFDLrkpr/NZZILyhAQnAgNpFcF4XmMA4GA1UdDwEB/wQEAwIBhjAPBgNV
# HRMBAf8EBTADAQH/MBMGA1UdJQQMMAoGCCsGAQUFBwMDMBsGA1UdIAQUMBIwBgYE
# VR0gADAIBgZngQwBBAEwQwYDVR0fBDwwOjA4oDagNIYyaHR0cDovL2NybC5jb21v
# ZG9jYS5jb20vQUFBQ2VydGlmaWNhdGVTZXJ2aWNlcy5jcmwwNAYIKwYBBQUHAQEE
# KDAmMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5jb21vZG9jYS5jb20wDQYJKoZI
# hvcNAQEMBQADggEBABK/oe+LdJqYRLhpRrWrJAoMpIpnuDqBv0WKfVIHqI0fTiGF
# OaNrXi0ghr8QuK55O1PNtPvYRL4G2VxjZ9RAFodEhnIq1jIV9RKDwvnhXRFAZ/ZC
# J3LFI+ICOBpMIOLbAffNRk8monxmwFE2tokCVMf8WPtsAO7+mKYulaEMUykfb9gZ
# pk+e96wJ6l2CxouvgKe9gUhShDHaMuwV5KZMPWw5c9QLhTkg4IUaaOGnSDip0TYl
# d8GNGRbFiExmfS9jzpjoad+sPKhdnckcW67Y8y90z7h+9teDnRGWYpquRRPaf9xH
# +9/DUp/mBlXpnYzyOmJRvOwkDynUWICE5EV7WtgwggYaMIIEAqADAgECAhBiHW0M
# UgGeO5B5FSCJIRwKMA0GCSqGSIb3DQEBDAUAMFYxCzAJBgNVBAYTAkdCMRgwFgYD
# VQQKEw9TZWN0aWdvIExpbWl0ZWQxLTArBgNVBAMTJFNlY3RpZ28gUHVibGljIENv
# ZGUgU2lnbmluZyBSb290IFI0NjAeFw0yMTAzMjIwMDAwMDBaFw0zNjAzMjEyMzU5
# NTlaMFQxCzAJBgNVBAYTAkdCMRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQxKzAp
# BgNVBAMTIlNlY3RpZ28gUHVibGljIENvZGUgU2lnbmluZyBDQSBSMzYwggGiMA0G
# CSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQCbK51T+jU/jmAGQ2rAz/V/9shTUxjI
# ztNsfvxYB5UXeWUzCxEeAEZGbEN4QMgCsJLZUKhWThj/yPqy0iSZhXkZ6Pg2A2NV
# DgFigOMYzB2OKhdqfWGVoYW3haT29PSTahYkwmMv0b/83nbeECbiMXhSOtbam+/3
# 6F09fy1tsB8je/RV0mIk8XL/tfCK6cPuYHE215wzrK0h1SWHTxPbPuYkRdkP05Zw
# mRmTnAO5/arnY83jeNzhP06ShdnRqtZlV59+8yv+KIhE5ILMqgOZYAENHNX9SJDm
# +qxp4VqpB3MV/h53yl41aHU5pledi9lCBbH9JeIkNFICiVHNkRmq4TpxtwfvjsUe
# dyz8rNyfQJy/aOs5b4s+ac7IH60B+Ja7TVM+EKv1WuTGwcLmoU3FpOFMbmPj8pz4
# 4MPZ1f9+YEQIQty/NQd/2yGgW+ufflcZ/ZE9o1M7a5Jnqf2i2/uMSWymR8r2oQBM
# dlyh2n5HirY4jKnFH/9gRvd+QOfdRrJZb1sCAwEAAaOCAWQwggFgMB8GA1UdIwQY
# MBaAFDLrkpr/NZZILyhAQnAgNpFcF4XmMB0GA1UdDgQWBBQPKssghyi47G9IritU
# pimqF6TNDDAOBgNVHQ8BAf8EBAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIBADATBgNV
# HSUEDDAKBggrBgEFBQcDAzAbBgNVHSAEFDASMAYGBFUdIAAwCAYGZ4EMAQQBMEsG
# A1UdHwREMEIwQKA+oDyGOmh0dHA6Ly9jcmwuc2VjdGlnby5jb20vU2VjdGlnb1B1
# YmxpY0NvZGVTaWduaW5nUm9vdFI0Ni5jcmwwewYIKwYBBQUHAQEEbzBtMEYGCCsG
# AQUFBzAChjpodHRwOi8vY3J0LnNlY3RpZ28uY29tL1NlY3RpZ29QdWJsaWNDb2Rl
# U2lnbmluZ1Jvb3RSNDYucDdjMCMGCCsGAQUFBzABhhdodHRwOi8vb2NzcC5zZWN0
# aWdvLmNvbTANBgkqhkiG9w0BAQwFAAOCAgEABv+C4XdjNm57oRUgmxP/BP6YdURh
# w1aVcdGRP4Wh60BAscjW4HL9hcpkOTz5jUug2oeunbYAowbFC2AKK+cMcXIBD0Zd
# OaWTsyNyBBsMLHqafvIhrCymlaS98+QpoBCyKppP0OcxYEdU0hpsaqBBIZOtBajj
# cw5+w/KeFvPYfLF/ldYpmlG+vd0xqlqd099iChnyIMvY5HexjO2AmtsbpVn0OhNc
# WbWDRF/3sBp6fWXhz7DcML4iTAWS+MVXeNLj1lJziVKEoroGs9Mlizg0bUMbOalO
# hOfCipnx8CaLZeVme5yELg09Jlo8BMe80jO37PU8ejfkP9/uPak7VLwELKxAMcJs
# zkyeiaerlphwoKx1uHRzNyE6bxuSKcutisqmKL5OTunAvtONEoteSiabkPVSZ2z7
# 6mKnzAfZxCl/3dq3dUNw4rg3sTCggkHSRqTqlLMS7gjrhTqBmzu1L90Y1KWN/Y5J
# KdGvspbOrTfOXyXvmPL6E52z1NZJ6ctuMFBQZH3pwWvqURR8AgQdULUvrxjUYbHH
# j95Ejza63zdrEcxWLDX6xWls/GDnVNueKjWUH3fTv1Y8Wdho698YADR7TNx8X8z2
# Bev6SivBBOHY+uqiirZtg0y9ShQoPzmCcn63Syatatvx157YK9hlcPmVoa1oDE5/
# L9Uo2bC5a4CH2RwwggZKMIIEsqADAgECAhAR4aCGZIeugmCCjSjwUXrGMA0GCSqG
# SIb3DQEBDAUAMFQxCzAJBgNVBAYTAkdCMRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0
# ZWQxKzApBgNVBAMTIlNlY3RpZ28gUHVibGljIENvZGUgU2lnbmluZyBDQSBSMzYw
# HhcNMjMwMjE5MDAwMDAwWhcNMjYwNTE4MjM1OTU5WjBhMQswCQYDVQQGEwJESzEU
# MBIGA1UECAwLSG92ZWRzdGFkZW4xHTAbBgNVBAoMFE1pY2hhZWwgTW9ydGVuIFNv
# bm5lMR0wGwYDVQQDDBRNaWNoYWVsIE1vcnRlbiBTb25uZTCCAiIwDQYJKoZIhvcN
# AQEBBQADggIPADCCAgoCggIBALVGIWG57aPiOruK3bg3tlPMHol1pfnEQiCkYom7
# hFXLVxhGve4OcQmx9xtKy7QIHmbHdH3Vc4J4foS0/bv4cnzYRd0g2qcTjo0Q+b5J
# RUSZQ0yUbLyHJf1TkCJOODWORJlsi/xppcQdAbU7QX2KFE4NkQzNUIOTSlKctx99
# ZqFevKIvwhkmIoB+WWnl/qS4ipFMO/d4m7o8IIgi49LPq3tVxZs0aJ6N02X5Xp2F
# oG2fZynudHIf9waYFtYXA3B8msQwaREpQY880Kki/275pSC+T8+mbnbwrKXOZ8Gj
# W2vvEJZe5ySIrA27omMsBnmoZYkiNMmMGYWQiZ5E75ZIiZ4UqWpuahoGpBLoZNX+
# TjKFFuqmo8EqfYdCpLiYgw95q3gHONu6TwTg01WwaeZFtlhx8qSgD8x7L/SRn4qn
# x//ucBg1Q0f3Al6lz++z8t4ty6CxF/Wr9ZKOoYhHft6SAE7Td9VGdWJLkp6cY1qf
# rq+QA+xR7rjFi7dagxvP1RzZqeh5glAQ74g3/lZJdgDTv/yB/zjxj6dHjzwii501
# VW4ecSX9RQpwWbleDDriDbVNJxwz37mBcSQykGXVfVV8AcdXn1zvEDkdshtLUGAL
# 6q61CugAE4LoOWohBEtk7dV2X0rvEY3Wce47ATLY14VM5gQCEsRxkEqt1HwdK4R+
# v/LtAgMBAAGjggGJMIIBhTAfBgNVHSMEGDAWgBQPKssghyi47G9IritUpimqF6TN
# DDAdBgNVHQ4EFgQUdfN+UjqPPYYWLqh4zXaTNj8AfJswDgYDVR0PAQH/BAQDAgeA
# MAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwMwSgYDVR0gBEMwQTA1
# BgwrBgEEAbIxAQIBAwIwJTAjBggrBgEFBQcCARYXaHR0cHM6Ly9zZWN0aWdvLmNv
# bS9DUFMwCAYGZ4EMAQQBMEkGA1UdHwRCMEAwPqA8oDqGOGh0dHA6Ly9jcmwuc2Vj
# dGlnby5jb20vU2VjdGlnb1B1YmxpY0NvZGVTaWduaW5nQ0FSMzYuY3JsMHkGCCsG
# AQUFBwEBBG0wazBEBggrBgEFBQcwAoY4aHR0cDovL2NydC5zZWN0aWdvLmNvbS9T
# ZWN0aWdvUHVibGljQ29kZVNpZ25pbmdDQVIzNi5jcnQwIwYIKwYBBQUHMAGGF2h0
# dHA6Ly9vY3NwLnNlY3RpZ28uY29tMA0GCSqGSIb3DQEBDAUAA4IBgQBF8qhaDXok
# 5R784NqfjMsNfS97H+ItE+Sxm/QMcIhTiiIBhIYd/lLfdTwpz5aqTl5M4+FDBDeN
# m0mjY8k2Cdg+DOf4JfvZAv4tQVybhEd42E5NTfG5sWN6ruMjBLpSsjwVzvonmeUL
# SwnXY+AtVSag0MU/UnyFOTS69gTjOq3EC+H/OJa/DfI8T/sDICzTy55c5aCDHRXb
# 6Dsr+Hm7PiGCQ6c0AhYOt/etXK1+YjQo9T+FcIF0Ze34CKirIRa1FFe26gNjHdpr
# MA62TOXQJrK+x9DtVY8QCb+IUZNYj6lNiXno3t69JN6FvIU2EtPrKs8SBV2uDZQM
# ecNJ+3w77/EHod82uB73vGiOvX8Q2CkdMunz+VfXyY4Oh10AEnCqzl0UV2HHH66H
# sa8Zti+kXWH9HTUkDJCd2VHdDEOJ0o2kA1/SfETMPAO/yeFz1xXy6CIJ50dkfzuY
# gf9SsIAod1Dx9THs2qkXIwyf5lTJBvPHLRqxs/k+Mn70AUiyj50/JYMwggbsMIIE
# 1KADAgECAhAwD2+s3WaYdHypRjaneC25MA0GCSqGSIb3DQEBDAUAMIGIMQswCQYD
# VQQGEwJVUzETMBEGA1UECBMKTmV3IEplcnNleTEUMBIGA1UEBxMLSmVyc2V5IENp
# dHkxHjAcBgNVBAoTFVRoZSBVU0VSVFJVU1QgTmV0d29yazEuMCwGA1UEAxMlVVNF
# UlRydXN0IFJTQSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTAeFw0xOTA1MDIwMDAw
# MDBaFw0zODAxMTgyMzU5NTlaMH0xCzAJBgNVBAYTAkdCMRswGQYDVQQIExJHcmVh
# dGVyIE1hbmNoZXN0ZXIxEDAOBgNVBAcTB1NhbGZvcmQxGDAWBgNVBAoTD1NlY3Rp
# Z28gTGltaXRlZDElMCMGA1UEAxMcU2VjdGlnbyBSU0EgVGltZSBTdGFtcGluZyBD
# QTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMgbAa/ZLH6ImX0BmD8g
# kL2cgCFUk7nPoD5T77NawHbWGgSlzkeDtevEzEk0y/NFZbn5p2QWJgn71TJSeS7J
# Y8ITm7aGPwEFkmZvIavVcRB5h/RGKs3EWsnb111JTXJWD9zJ41OYOioe/M5YSdO/
# 8zm7uaQjQqzQFcN/nqJc1zjxFrJw06PE37PFcqwuCnf8DZRSt/wflXMkPQEovA8N
# T7ORAY5unSd1VdEXOzQhe5cBlK9/gM/REQpXhMl/VuC9RpyCvpSdv7QgsGB+uE31
# DT/b0OqFjIpWcdEtlEzIjDzTFKKcvSb/01Mgx2Bpm1gKVPQF5/0xrPnIhRfHuCkZ
# pCkvRuPd25Ffnz82Pg4wZytGtzWvlr7aTGDMqLufDRTUGMQwmHSCIc9iVrUhcxIe
# /arKCFiHd6QV6xlV/9A5VC0m7kUaOm/N14Tw1/AoxU9kgwLU++Le8bwCKPRt2ieK
# BtKWh97oaw7wW33pdmmTIBxKlyx3GSuTlZicl57rjsF4VsZEJd8GEpoGLZ8DXv2D
# olNnyrH6jaFkyYiSWcuoRsDJ8qb/fVfbEnb6ikEk1Bv8cqUUotStQxykSYtBORQD
# Hin6G6UirqXDTYLQjdprt9v3GEBXc/Bxo/tKfUU2wfeNgvq5yQ1TgH36tjlYMu9v
# GFCJ10+dM70atZ2h3pVBeqeDAgMBAAGjggFaMIIBVjAfBgNVHSMEGDAWgBRTeb9a
# qitKz1SA4dibwJ3ysgNmyzAdBgNVHQ4EFgQUGqH4YRkgD8NBd0UojtE1XwYSBFUw
# DgYDVR0PAQH/BAQDAgGGMBIGA1UdEwEB/wQIMAYBAf8CAQAwEwYDVR0lBAwwCgYI
# KwYBBQUHAwgwEQYDVR0gBAowCDAGBgRVHSAAMFAGA1UdHwRJMEcwRaBDoEGGP2h0
# dHA6Ly9jcmwudXNlcnRydXN0LmNvbS9VU0VSVHJ1c3RSU0FDZXJ0aWZpY2F0aW9u
# QXV0aG9yaXR5LmNybDB2BggrBgEFBQcBAQRqMGgwPwYIKwYBBQUHMAKGM2h0dHA6
# Ly9jcnQudXNlcnRydXN0LmNvbS9VU0VSVHJ1c3RSU0FBZGRUcnVzdENBLmNydDAl
# BggrBgEFBQcwAYYZaHR0cDovL29jc3AudXNlcnRydXN0LmNvbTANBgkqhkiG9w0B
# AQwFAAOCAgEAbVSBpTNdFuG1U4GRdd8DejILLSWEEbKw2yp9KgX1vDsn9FqguUlZ
# kClsYcu1UNviffmfAO9Aw63T4uRW+VhBz/FC5RB9/7B0H4/GXAn5M17qoBwmWFzz
# tBEP1dXD4rzVWHi/SHbhRGdtj7BDEA+N5Pk4Yr8TAcWFo0zFzLJTMJWk1vSWVgi4
# zVx/AZa+clJqO0I3fBZ4OZOTlJux3LJtQW1nzclvkD1/RXLBGyPWwlWEZuSzxWYG
# 9vPWS16toytCiiGS/qhvWiVwYoFzY16gu9jc10rTPa+DBjgSHSSHLeT8AtY+dwS8
# BDa153fLnC6NIxi5o8JHHfBd1qFzVwVomqfJN2Udvuq82EKDQwWli6YJ/9GhlKZO
# qj0J9QVst9JkWtgqIsJLnfE5XkzeSD2bNJaaCV+O/fexUpHOP4n2HKG1qXUfcb9b
# Q11lPVCBbqvw0NP8srMftpmWJvQ8eYtcZMzN7iea5aDADHKHwW5NWtMe6vBE5jJv
# HOsXTpTDeGUgOw9Bqh/poUGd/rG4oGUqNODeqPk85sEwu8CgYyz8XBYAqNDEf+oR
# nR4GxqZtMl20OAkrSQeq/eww2vGnL8+3/frQo4TZJ577AWZ3uVYQ4SBuxq6x+ba6
# yDVdM3aO8XwgDCp3rrWiAoa6Ke60WgCxjKvj+QrJVF3UuWp0nr1Irpgwggb1MIIE
# 3aADAgECAhA5TCXhfKBtJ6hl4jvZHSLUMA0GCSqGSIb3DQEBDAUAMH0xCzAJBgNV
# BAYTAkdCMRswGQYDVQQIExJHcmVhdGVyIE1hbmNoZXN0ZXIxEDAOBgNVBAcTB1Nh
# bGZvcmQxGDAWBgNVBAoTD1NlY3RpZ28gTGltaXRlZDElMCMGA1UEAxMcU2VjdGln
# byBSU0EgVGltZSBTdGFtcGluZyBDQTAeFw0yMzA1MDMwMDAwMDBaFw0zNDA4MDIy
# MzU5NTlaMGoxCzAJBgNVBAYTAkdCMRMwEQYDVQQIEwpNYW5jaGVzdGVyMRgwFgYD
# VQQKEw9TZWN0aWdvIExpbWl0ZWQxLDAqBgNVBAMMI1NlY3RpZ28gUlNBIFRpbWUg
# U3RhbXBpbmcgU2lnbmVyICM0MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKC
# AgEApJMoUkvPJ4d2pCkcmTjA5w7U0RzsaMsBZOSKzXewcWWCvJ/8i7u7lZj7JRGO
# WogJZhEUWLK6Ilvm9jLxXS3AeqIO4OBWZO2h5YEgciBkQWzHwwj6831d7yGawn7X
# LMO6EZge/NMgCEKzX79/iFgyqzCz2Ix6lkoZE1ys/Oer6RwWLrCwOJVKz4VQq2cD
# JaG7OOkPb6lampEoEzW5H/M94STIa7GZ6A3vu03lPYxUA5HQ/C3PVTM4egkcB9Ei
# 4GOGp7790oNzEhSbmkwJRr00vOFLUHty4Fv9GbsfPGoZe267LUQqvjxMzKyKBJPG
# V4agczYrgZf6G5t+iIfYUnmJ/m53N9e7UJ/6GCVPE/JefKmxIFopq6NCh3fg9EwC
# SN1YpVOmo6DtGZZlFSnF7TMwJeaWg4Ga9mBmkFgHgM1Cdaz7tJHQxd0BQGq2qBDu
# 9o16t551r9OlSxihDJ9XsF4lR5F0zXUS0Zxv5F4Nm+x1Ju7+0/WSL1KF6NpEUSqi
# zADKh2ZDoxsA76K1lp1irScL8htKycOUQjeIIISoh67DuiNye/hU7/hrJ7CF9adD
# hdgrOXTbWncC0aT69c2cPcwfrlHQe2zYHS0RQlNxdMLlNaotUhLZJc/w09CRQxLX
# Mn2YbON3Qcj/HyRU726txj5Ve/Fchzpk8WBLBU/vuS/sCRMCAwEAAaOCAYIwggF+
# MB8GA1UdIwQYMBaAFBqh+GEZIA/DQXdFKI7RNV8GEgRVMB0GA1UdDgQWBBQDDzHI
# kSqTvWPz0V1NpDQP0pUBGDAOBgNVHQ8BAf8EBAMCBsAwDAYDVR0TAQH/BAIwADAW
# BgNVHSUBAf8EDDAKBggrBgEFBQcDCDBKBgNVHSAEQzBBMDUGDCsGAQQBsjEBAgED
# CDAlMCMGCCsGAQUFBwIBFhdodHRwczovL3NlY3RpZ28uY29tL0NQUzAIBgZngQwB
# BAIwRAYDVR0fBD0wOzA5oDegNYYzaHR0cDovL2NybC5zZWN0aWdvLmNvbS9TZWN0
# aWdvUlNBVGltZVN0YW1waW5nQ0EuY3JsMHQGCCsGAQUFBwEBBGgwZjA/BggrBgEF
# BQcwAoYzaHR0cDovL2NydC5zZWN0aWdvLmNvbS9TZWN0aWdvUlNBVGltZVN0YW1w
# aW5nQ0EuY3J0MCMGCCsGAQUFBzABhhdodHRwOi8vb2NzcC5zZWN0aWdvLmNvbTAN
# BgkqhkiG9w0BAQwFAAOCAgEATJtlWPrgec/vFcMybd4zket3WOLrvctKPHXefpRt
# wyLHBJXfZWlhEwz2DJ71iSBewYfHAyTKx6XwJt/4+DFlDeDrbVFXpoyEUghGHCrC
# 3vLaikXzvvf2LsR+7fjtaL96VkjpYeWaOXe8vrqRZIh1/12FFjQn0inL/+0t2v++
# kwzsbaINzMPxbr0hkRojAFKtl9RieCqEeajXPawhj3DDJHk6l/ENo6NbU9irALpY
# +zWAT18ocWwZXsKDcpCu4MbY8pn76rSSZXwHfDVEHa1YGGti+95sxAqpbNMhRnDc
# L411TCPCQdB6ljvDS93NkiZ0dlw3oJoknk5fTtOPD+UTT1lEZUtDZM9I+GdnuU2/
# zA2xOjDQoT1IrXpl5Ozf4AHwsypKOazBpPmpfTXQMkCgsRkqGCGyyH0FcRpLJzaq
# 4Jgcg3Xnx35LhEPNQ/uQl3YqEqxAwXBbmQpA+oBtlGF7yG65yGdnJFxQjQEg3gf3
# AdT4LhHNnYPl+MolHEQ9J+WwhkcqCxuEdn17aE+Nt/cTtO2gLe5zD9kQup2ZLHzX
# dR+PEMSU5n4k5ZVKiIwn1oVmHfmuZHaR6Ej+yFUK7SnDH944psAU+zI9+KmDYjbI
# w74Ahxyr+kpCHIkD3PVcfHDZXXhO7p9eIOYJanwrCKNI9RX8BE/fzSEceuX1jhrU
# uUAxggZpMIIGZQIBATBoMFQxCzAJBgNVBAYTAkdCMRgwFgYDVQQKEw9TZWN0aWdv
# IExpbWl0ZWQxKzApBgNVBAMTIlNlY3RpZ28gUHVibGljIENvZGUgU2lnbmluZyBD
# QSBSMzYCEBHhoIZkh66CYIKNKPBResYwDQYJYIZIAWUDBAIBBQCggYQwGAYKKwYB
# BAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAc
# BgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQg0vUW
# tvbRqMi/LcOQ5P0uW53YtEl1sQIPcFV5Jc5ZOJ8wDQYJKoZIhvcNAQEBBQAEggIA
# jbFZI0cVZ8goyGDR5eTtuLSoVdi4A909+Tflm2CrSfEaL2utrWE81D9/JBxpHhEi
# 4Un/9osRyoJUR406HFaQkXj9khzZAYHL4D0FdUxgbiK8z24+x19SsGO7JmE+DkxS
# KWyeOtWtGHh4bEjIPmGEI2eDEr+doC+vHTywTclQRy7rbbw8v7GeshRSVctWO9KF
# +U/rzn8/ynWvVv+dfblrdsOosLRqSGGVAbMsYJccoDjh1gFNuJY7K/nDx7nByLuM
# axHDPLP39IVVtRgAcemYCIjXdwPOPifX9RoPedDiedGQ20PWicj6KzWsJrkyta/a
# 749o7g7/qKB24203AuP8tRJ10N+xYEMH3svpg7nQ10bKCQ9gDDl6WGFcgXEeTLQC
# pZ+vkFt9CS6kiSzfA0NgjWh4rjh3yMK32Dgx8ddwKYG8ATzY9b1n0mNDkIZITllL
# /Wd1hVPNSo0/XP2YlQWRFDYeu9/V0/H9OIzrdwi1niAXGt5/i1fDRE24DfcAAqjK
# qKGli5A3Qahb7wD1xvwy/v1VktoCFxT14mNWuo5Hu8ScjSh4fSRvAnoMZTiKbEhC
# RB+YUtj0LY0al6OKkdQ66DJxdWjRwrfchRFhLMe4KSREox/jLEfMhvZ2wDt9Tejp
# Gli3xh6YWSDqkmry+1nwvJk5KXj2uaS4UtBotONNLs6hggNLMIIDRwYJKoZIhvcN
# AQkGMYIDODCCAzQCAQEwgZEwfTELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0
# ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEYMBYGA1UEChMPU2VjdGln
# byBMaW1pdGVkMSUwIwYDVQQDExxTZWN0aWdvIFJTQSBUaW1lIFN0YW1waW5nIENB
# AhA5TCXhfKBtJ6hl4jvZHSLUMA0GCWCGSAFlAwQCAgUAoHkwGAYJKoZIhvcNAQkD
# MQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjMwOTE0MjAyMzEyWjA/Bgkq
# hkiG9w0BCQQxMgQwZXQwmV6LcdB/JX49kqtYo7Rsn9RuIXmz24SpCPcsx4eE6KzR
# G3X9CzZ68PDdWlB0MA0GCSqGSIb3DQEBAQUABIICABXEsxmZE7c6+2rnwPsrx2oi
# Dw22ObDntGT/tG/SvAYry6Iwbes0zyvPz5UQ/kv3Op1RN+GLy7d73lX/KfACgUPW
# 4peqWbsE75/9Gv3DwrQnm9B+dxxpi5mmbEB1RbWV9B/OmjSNY0zSoWW1WSUg04+4
# LNDSOh4/+ot5AooYT/SZjOZngGWKezKrYJfWXp3YPp3Suu8Ax/NckoV9qo6uNJ6O
# WkO03ixV2F3aIBOpdP7g99iJ+vkeIGGETYJiG2nHbG+GwN46nTNDPv7kMWdjJllG
# X3635gBglyGp0fpC2arOeu0daX+Y6iZOEFcnQII2yUE3AqC+4oGy1fRGqKEDtaGx
# IZkysarmOUBBS4qxlYHozWDEsCaHvW1iopqcld2u2LHdM2/EwXDWSgX5szeU71GX
# NHcubmusjyEGrJGFTTwbxPJsvUOt8T/zg5IKPNRO0NdWeB2pb8JpR6ZhPc9BoCDN
# K9A/idw3Qb+HIMTvSQssNOAhLO9RDprdths5+bn2V1PQ+guO2plRbWpKOJXw2wxG
# +NLEiPtKSOLKXZa6pNLmtItE2rxQ96nZ5xqxivLj4xYh1NdO3QolD2pcTUthDquH
# CR8sVomJ4o5XRD8EtV9SNeqiIglP+qyUVH9fJ7pAWnnWJYLJvoeSkppaW+vgEeOL
# /PH76zKkxfYYwxC9D6q+
# SIG # End signature block
