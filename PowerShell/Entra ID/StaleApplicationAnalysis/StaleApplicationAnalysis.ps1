<#	
	.NOTES
	===========================================================================
	 Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2022 v5.8.213
	 Created on:   	14-02-2023 14:12
	 Created by:   	Michael Morten Sonne
	 Organization: 	Sonne´s Cloud
	 Filename:     	
	===========================================================================
	.DESCRIPTION
		If you just blocked users from registering applications, or you are just analyzing your Enterprise applications, you may find that there is a lot of work ahead of you.
		First, you may want to find if there are applications with no user assigned. Then you may wonder if there are applications without sign-ins in the last 30 days.

	.USE
		1. head to https://aad.portal.azure.com/#blade/Microsoft_AAD_IAM/StartboardApplicationsMenuBlade/AppAppsPreview/menuId/ and click "Download (Export)", then download the CSV.
		2. login to Azure: Connect-AzureAD (useing AzureADPreview for log function for lookup works)
		3. launch: .\StaleApplicationAnalysis.ps1 | Export-csv StaleApplicationCleanup.csv

	.OUTPUT
		Output will be: ApplicationName, SignIns and Users for the application(s)
#>

#==========================================================================
#Helper functions
#==========================================================================

#Function to connect to Azure ADS
function connect-aad
{	
	try
	{
		$AADtenant = Get-AzureADTenantDetail -ErrorAction Stop | Out-Null
	}
	catch
	{
		write-output "Not connected to Azure AD. Connecting..." | out-host
		try
		{
			Connect-AzureAD -ErrorAction Stop | Out-Null
		}
		catch
		{
			write-output "Failed to connect to Azure AD" | out-host
			write-output $_.Exception.Message | out-host
			Return 1
		}
	}
	
	$AADtenant = Get-AzureADTenantDetail
	$text = "Tenant ID is: " + $AADtenant.ObjectId
	Write-Output "Connected to Azure AD" | out-host
	Write-Output $text | out-host	
}

#Function to check if AzureADPreview module is installed and up-to-date
function invoke-AzureADPreview
{
	$AADPavailable = (find-module -name AzureADPreview)
	$vertemp = $AADPavailable.version.ToString()
	Write-Output "Latest version of AzureADPreview module is $vertemp" | out-host
	$AADPcurrent = (get-installedmodule -name AzureADPreview -ErrorAction SilentlyContinue)
	
	if ($AADPcurrent -eq $null)
	{
		write-output "AzureADPreview module is not installed. Installing..." | out-host
		try
		{
			Install-Module AzureADPreview -Force -ErrorAction Stop
		}
		catch
		{
			write-output "Failed to install AzureADPreview Module" | out-host
			write-output $_.Exception.Message | out-host
			Return 1
		}
	}
	$AADPcurrent = (get-installedmodule -name AzureADPreview)
	$vertemp = $AADPcurrent.Version.ToString()
	write-output "Current installed version of AzureADPreview module is $vertemp" | out-host
		
	if ($AADPavailable.Version -gt $AADPcurrent.Version) { write-host "There is an update to this module available." }
	else
	{ write-output "The installed AzureADPreview module is up to date." | out-host }
}

#function to detect if AzureAD module is installed
function invoke-azureadcheck
{
	try
	{
		Get-InstalledModule -Name AzureAD -ErrorAction Stop | Out-Null
		Write-Host "AzureAD module is installed" -ForegroundColor Red
		Return 1
	}	
	catch
	{
		Write-Host "AzureAD module is not installed"
		Return 0
	}
}

#==========================================================================
#End Helper functions
#==========================================================================

#==========================================================================
#Checker functions
#==========================================================================

#Command to check if AzureAD module is installed and exit if it is.
if (invoke-azureadcheck -eq 1)
{
	write-host "The AzureAD module is not compatibile with AzureADPreivew" -ForegroundColor Red
	write-host "Please uninstall the AzureAD module, close all PowerShell sessions," -ForegroundColor Red
	Write-Host "and run this script again" -ForegroundColor Red
	Return 1
}

#Commands to load AzureADPreview modules
if (invoke-AzureADPreview -eq 1)
{
	write-output "Invoking AzureADPreview failed. Exiting..." | out-host
	Return 1
}

#Command to connect to AzureAD PowerShell app
if (connect-aad -eq 1)
{
	write-output "Connecting to AzureAD failed. Exiting..." | out-host
	Return 1
}

#==========================================================================
#End Checker functions
#==========================================================================

#==========================================================================
#Main script starts here
#==========================================================================

$numers = 0;
$AADtenantInfo = Get-AzureADTenantDetail
$texttenant = $AADtenantInfo.ObjectId

$AllApplications = Import-Csv .\EnterpriseAppsList.csv
$applications = $allapplications | Where-Object { $_.applicationtype -ne "Microsoft application" }

if ($applications -ne $null)
{
	#Show status
	Write-Host "There is found non Microsoft Enterprise applications in tenant: '$texttenant'..." -ForegroundColor Green
	
	ForEach ($Application in $Applications)
	{
		#Count apps
		$numers++
		
		#Retrieve the objectid and signin logs, format the user assigned to the app 
		$app = Get-AzureADServicePrincipal -all $true | Where-Object { $_.objectid -eq $application.id }
		$Log = Get-AzureADAuditSignInLogs -All $true -filter "appid eq '$($App.AppID)'"
		$userassigned = Get-AzureADServiceAppRoleAssignment -ObjectId $App.ObjectId | Select-Object ResourceDisplayName, PrincipalDisplayName
		
		Write-Host "Processing the service principal found: '$($App.displayName)'..." -ForegroundColor Yellow
		
		if ($userassigned -ne $null)
		{
			$format = $userassigned.gettype()
			if ($format.basetype.name -eq "Object")
			{
				$userassigned = [string]$userassigned
			}
		}
		
		#Create a custom object for output 
		[PSCustomObject]@{
			ApplicationName = $App.DisplayName
			ApplicationID   = $App.AppID
			SignIns		    = $Log.count
			Users		    = $userassigned.count
		}
		Start-Sleep 5
	}
	#Show done
	Write-Host "Processed $numers Enterprise applications found in tenant: '$texttenant'..." -ForegroundColor Green
}
else
{
	#Show done with no apps
	Write-Host "No processed non Microsoft Enterprise applications - none found in tenant: '$texttenant'..." -ForegroundColor Yellow
}

#Show log
Write-Host "Output is saved to file in running folder..." -ForegroundColor Yellow
# SIG # Begin signature block
# MIIpEQYJKoZIhvcNAQcCoIIpAjCCKP4CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBjsgsRF1SBQTrQ
# qtwtvq5qQUH69DToIWaYTyV2NDs0H6CCEgEwggVvMIIEV6ADAgECAhBI/JO0YFWU
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
# L9Uo2bC5a4CH2RwwggZsMIIE1KADAgECAhA4AvOHUKXogkfst8ZZWUnPMA0GCSqG
# SIb3DQEBDAUAMFQxCzAJBgNVBAYTAkdCMRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0
# ZWQxKzApBgNVBAMTIlNlY3RpZ28gUHVibGljIENvZGUgU2lnbmluZyBDQSBSMzYw
# HhcNMjMwMTE5MDAwMDAwWhcNMjYwNDE4MjM1OTU5WjBhMQswCQYDVQQGEwJESzEU
# MBIGA1UECAwLSG92ZWRzdGFkZW4xHTAbBgNVBAoMFE1pY2hhZWwgTW9ydGVuIFNv
# bm5lMR0wGwYDVQQDDBRNaWNoYWVsIE1vcnRlbiBTb25uZTCCAiIwDQYJKoZIhvcN
# AQEBBQADggIPADCCAgoCggIBAM8KoVl7ES9u/nV9ycWpb5au+g0F3x2edCAhRPIO
# wtVHX6XIHFBJkFTYmuktZE1hRtGgsvFMo+xh4HLRANRCc482xgeDtpWQw85LRC8M
# QrU2IZ1VYQv750Nvb9pUbO9OaPzJyTjJcK6I+wJRSIETtJAUCZ6JjTp8By4+y8OF
# TsZNUN4cQBYP/Z806ofBVuLP89YAHTb5SUU4MeIONyO90n1+jdYlmyuWYjUWfMg7
# ikseomOgpaymvwbqa/FPCfeKtGLNpmVl1K9IKUbAw51SCoIrJsNISzTky3o/43RD
# 3Ijg52p783sDZQtiqFAhMjPQuz1Y2lTphVjJCF+VCuw94oRS80g9VDMk9iOkIhyK
# EHdkxgXLWtfNiZ8C6tCjiVWAhAzc/jp9sx8AUPJ2u1C1HXBgqqMTA8IqfEUNMAMV
# booAYfptoVUcrL894L60jM+nVntjsWo0piEeDBC0Iol6ovyqcXlTY9dC1xpfpyaH
# IVJm54w9JKWZJAac8GSuP19ZXNmvhF4W5ubqn3iFtMBKHoLAiOn5EeXMKAg8mSYB
# SPuelmzYAP13eMATpErGCJCUgLod+3YVuIfHgs0eVMoDLkIuIquMa5x8Pjakt+UZ
# 7uqz8Mns56HwhzqxUJHveOAS/w2DHJuSg6TTOgdFgw0+44Yx3AX+3ttqzivEqkbc
# 9L1lAgMBAAGjggGrMIIBpzAfBgNVHSMEGDAWgBQPKssghyi47G9IritUpimqF6TN
# DDAdBgNVHQ4EFgQUqY4K6FWkjxAzloSgujkO8XyjQSgwDgYDVR0PAQH/BAQDAgeA
# MAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwMwSgYDVR0gBEMwQTA1
# BgwrBgEEAbIxAQIBAwIwJTAjBggrBgEFBQcCARYXaHR0cHM6Ly9zZWN0aWdvLmNv
# bS9DUFMwCAYGZ4EMAQQBMEkGA1UdHwRCMEAwPqA8oDqGOGh0dHA6Ly9jcmwuc2Vj
# dGlnby5jb20vU2VjdGlnb1B1YmxpY0NvZGVTaWduaW5nQ0FSMzYuY3JsMHkGCCsG
# AQUFBwEBBG0wazBEBggrBgEFBQcwAoY4aHR0cDovL2NydC5zZWN0aWdvLmNvbS9T
# ZWN0aWdvUHVibGljQ29kZVNpZ25pbmdDQVIzNi5jcnQwIwYIKwYBBQUHMAGGF2h0
# dHA6Ly9vY3NwLnNlY3RpZ28uY29tMCAGA1UdEQQZMBeBFWNvZGVzaWduQHNvbm5l
# cy5jbG91ZDANBgkqhkiG9w0BAQwFAAOCAYEAU2Z0svozIG3l2k3tGUfVQa8j+rae
# oGGGg2Btvbn3kxwSIM84AzjywGy80E/q0aegPpfhoslli1KMB5PvjodyvRIZthhl
# SFyUC4WY8JwxPYydAo4lRfGFp2hiJ3Ri39ITgbnHmV7+MxdEyOVbF84Ku1VwGbi6
# cSBWY3md3gaLaDFguOA1D9CX+nlpBQJO1W000UsUWz6+M2Eg2lP0Cy8rGpyiN9p9
# 8z1Qtk+yCIYf7mgRDp4jjn8Qu+qs3x63ujjKY1aNu4DgOBcWbfDF1m9MjulXXS7s
# CJmoTcTHhpvGbRyYiJzQkEumC9VostL+5UcIBN++mze2Z1ExAnQsE5MaKAqF0N3U
# +2CliNfqoJmmyzqajVpH3v1rUCMEqr8hMHRxBQMTFFKIFIjzI/Yro9UXH32dcmBn
# dl4JyToiqiWM0hKFQJAfUR9p5SO+lctbGuUMtSXY8gZAcZBt+amivuFNA/BoPW7Q
# 7rgtCqtZQ7hwBgAzi2x6GFADhqBL+n4sW4L8MYIWZjCCFmICAQEwaDBUMQswCQYD
# VQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMSswKQYDVQQDEyJTZWN0
# aWdvIFB1YmxpYyBDb2RlIFNpZ25pbmcgQ0EgUjM2AhA4AvOHUKXogkfst8ZZWUnP
# MA0GCWCGSAFlAwQCAQUAoHwwEAYKKwYBBAGCNwIBDDECMAAwGQYJKoZIhvcNAQkD
# MQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJ
# KoZIhvcNAQkEMSIEIIczm5Js9L0G5mktjheXV+n5vgELDD+17+4qlpxfqqsWMA0G
# CSqGSIb3DQEBAQUABIICAM0Hdg4tv9uy4DTQZRNH2x3b/U4VF+O7pFQ1h9XauNCu
# dcCP0u/M4fBriI9bUMO3iSdl88K12PMi0wvRNryv1XFb6wEUWv4xeSBRy0yHZZpQ
# 8emN0P5/mA4zdL9PBsB++GDLHoCBJfHFsyWMnTN626nZczL7zC+iUTZkgaRI+rAN
# CnF2KvreAKc2b6oYH85D+TD+na90JVIJS6xFknfXF8J33GYkBSBIZy6EbOL3vTrR
# 6PnEvLFhP/jR3jZPpeLVQpdkWocXODZuiWpGysNTkLGPx6T55spUnpWA3B6k0CRG
# r9kTy66Ui7Ml3U0KAfXSPMnjt4JWve2BUEHfNIXGKXL+mwSaEmiFu2n4xiNROSqu
# Pi2YTZdUZn60wSj4qgSTb+76qLzDeN6qr1UyHP98wA6ggWuCt+oihNAqDV039ZE+
# oD2CfRpawo5ecQF0khCwTlUosYW1lrwEl5KLUuSajAuuRJMgZ6UwJNv4Ddz1yM0/
# 8tt05Ut7qCxkTq93FGCooevFtitm6NeokqfBKRBhV3ce+JHeP/u1IRjMfMy4vOVV
# TSQFVvJVBEGaLlay57BlhjoxtVJK4ZVr2P2eOB1hcUkukKhpmHHOC2OodJLeI18q
# erF+WKNc2O0FAp+9uYzakTZ2cjSjzDndcCsx/M3t+dHalgLTp2JPkssG6yFXMQ2F
# oYITUTCCE00GCisGAQQBgjcDAwExghM9MIITOQYJKoZIhvcNAQcCoIITKjCCEyYC
# AQMxDzANBglghkgBZQMEAgIFADCB8AYLKoZIhvcNAQkQAQSggeAEgd0wgdoCAQEG
# CisGAQQBsjECAQEwMTANBglghkgBZQMEAgEFAAQgsWiS87clFuVWmq4wWlm0b81i
# uXt137RqeY6VRwLidN8CFQD2wlnmtOlfXaqOPjYGPVWS56+hHRgPMjAyMzAyMTQy
# MTA4MDRaoG6kbDBqMQswCQYDVQQGEwJHQjETMBEGA1UECBMKTWFuY2hlc3RlcjEY
# MBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMSwwKgYDVQQDDCNTZWN0aWdvIFJTQSBU
# aW1lIFN0YW1waW5nIFNpZ25lciAjM6CCDeowggb2MIIE3qADAgECAhEAkDl/mtJK
# OhPyvZFfCDipQzANBgkqhkiG9w0BAQwFADB9MQswCQYDVQQGEwJHQjEbMBkGA1UE
# CBMSR3JlYXRlciBNYW5jaGVzdGVyMRAwDgYDVQQHEwdTYWxmb3JkMRgwFgYDVQQK
# Ew9TZWN0aWdvIExpbWl0ZWQxJTAjBgNVBAMTHFNlY3RpZ28gUlNBIFRpbWUgU3Rh
# bXBpbmcgQ0EwHhcNMjIwNTExMDAwMDAwWhcNMzMwODEwMjM1OTU5WjBqMQswCQYD
# VQQGEwJHQjETMBEGA1UECBMKTWFuY2hlc3RlcjEYMBYGA1UEChMPU2VjdGlnbyBM
# aW1pdGVkMSwwKgYDVQQDDCNTZWN0aWdvIFJTQSBUaW1lIFN0YW1waW5nIFNpZ25l
# ciAjMzCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAJCycT954dS5ihfM
# w5fCkJRy7Vo6bwFDf3NaKJ8kfKA1QAb6lK8KoYO2E+RLFQZeaoogNHF7uyWtP1sK
# pB8vbH0uYVHQjFk3PqZd8R5dgLbYH2DjzRJqiB/G/hjLk0NWesfOA9YAZChWIrFL
# GdLwlslEHzldnLCW7VpJjX5y5ENrf8mgP2xKrdUAT70KuIPFvZgsB3YBcEXew/BC
# aer/JswDRB8WKOFqdLacRfq2Os6U0R+9jGWq/fzDPOgNnDhm1fx9HptZjJFaQldV
# UBYNS3Ry7qAqMfwmAjT5ZBtZ/eM61Oi4QSl0AT8N4BN3KxE8+z3N0Ofhl1tV9yoD
# bdXNYtrOnB786nB95n1LaM5aKWHToFwls6UnaKNY/fUta8pfZMdrKAzarHhB3pLv
# D8Xsq98tbxpUUWwzs41ZYOff6Bcio3lBYs/8e/OS2q7gPE8PWsxu3x+8Iq+3OBCa
# NKcL//4dXqTz7hY4Kz+sdpRBnWQd+oD9AOH++DrUw167aU1ymeXxMi1R+mGtTeom
# jm38qUiYPvJGDWmxt270BdtBBcYYwFDk+K3+rGNhR5G8RrVGU2zF9OGGJ5OEOWx1
# 4B0MelmLLsv0ZCxCR/RUWIU35cdpp9Ili5a/xq3gvbE39x/fQnuq6xzp6z1a3fjS
# kNVJmjodgxpXfxwBws4cfcz7lhXFAgMBAAGjggGCMIIBfjAfBgNVHSMEGDAWgBQa
# ofhhGSAPw0F3RSiO0TVfBhIEVTAdBgNVHQ4EFgQUJS5oPGuaKyQUqR+i3yY6zxSm
# 8eAwDgYDVR0PAQH/BAQDAgbAMAwGA1UdEwEB/wQCMAAwFgYDVR0lAQH/BAwwCgYI
# KwYBBQUHAwgwSgYDVR0gBEMwQTA1BgwrBgEEAbIxAQIBAwgwJTAjBggrBgEFBQcC
# ARYXaHR0cHM6Ly9zZWN0aWdvLmNvbS9DUFMwCAYGZ4EMAQQCMEQGA1UdHwQ9MDsw
# OaA3oDWGM2h0dHA6Ly9jcmwuc2VjdGlnby5jb20vU2VjdGlnb1JTQVRpbWVTdGFt
# cGluZ0NBLmNybDB0BggrBgEFBQcBAQRoMGYwPwYIKwYBBQUHMAKGM2h0dHA6Ly9j
# cnQuc2VjdGlnby5jb20vU2VjdGlnb1JTQVRpbWVTdGFtcGluZ0NBLmNydDAjBggr
# BgEFBQcwAYYXaHR0cDovL29jc3Auc2VjdGlnby5jb20wDQYJKoZIhvcNAQEMBQAD
# ggIBAHPa7Whyy8K5QKExu7QDoy0UeyTntFsVfajp/a3Rkg18PTagadnzmjDarGnW
# dFckP34PPNn1w3klbCbojWiTzvF3iTl/qAQF2jTDFOqfCFSr/8R+lmwr05TrtGzg
# RU0ssvc7O1q1wfvXiXVtmHJy9vcHKPPTstDrGb4VLHjvzUWgAOT4BHa7V8WQvndU
# kHSeC09NxKoTj5evATUry5sReOny+YkEPE7jghJi67REDHVBwg80uIidyCLxE2rb
# GC9ueK3EBbTohAiTB/l9g/5omDTkd+WxzoyUbNsDbSgFR36bLvBk+9ukAzEQfBr7
# PBmA0QtwuVVfR745ZM632iNUMuNGsjLY0imGyRVdgJWvAvu00S6dOHw14A8c7RtH
# SJwialWC2fK6CGUD5fEp80iKCQFMpnnyorYamZTrlyjhvn0boXztVoCm9CIzkOSE
# U/wq+sCnl6jqtY16zuTgS6Ezqwt2oNVpFreOZr9f+h/EqH+noUgUkQ2C/L1Nme3J
# 5mw2/ndDmbhpLXxhL+2jsEn+W75pJJH/k/xXaZJL2QU/bYZy06LQwGTSOkLBGgP7
# 0O2aIbg/r6ayUVTVTMXKHxKNV8Y57Vz/7J8mdq1kZmfoqjDg0q23fbFqQSduA4qj
# dOCKCYJuv+P2t7yeCykYaIGhnD9uFllLFAkJmuauv2AV3Yb1MIIG7DCCBNSgAwIB
# AgIQMA9vrN1mmHR8qUY2p3gtuTANBgkqhkiG9w0BAQwFADCBiDELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCk5ldyBKZXJzZXkxFDASBgNVBAcTC0plcnNleSBDaXR5MR4w
# HAYDVQQKExVUaGUgVVNFUlRSVVNUIE5ldHdvcmsxLjAsBgNVBAMTJVVTRVJUcnVz
# dCBSU0EgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMTkwNTAyMDAwMDAwWhcN
# MzgwMTE4MjM1OTU5WjB9MQswCQYDVQQGEwJHQjEbMBkGA1UECBMSR3JlYXRlciBN
# YW5jaGVzdGVyMRAwDgYDVQQHEwdTYWxmb3JkMRgwFgYDVQQKEw9TZWN0aWdvIExp
# bWl0ZWQxJTAjBgNVBAMTHFNlY3RpZ28gUlNBIFRpbWUgU3RhbXBpbmcgQ0EwggIi
# MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDIGwGv2Sx+iJl9AZg/IJC9nIAh
# VJO5z6A+U++zWsB21hoEpc5Hg7XrxMxJNMvzRWW5+adkFiYJ+9UyUnkuyWPCE5u2
# hj8BBZJmbyGr1XEQeYf0RirNxFrJ29ddSU1yVg/cyeNTmDoqHvzOWEnTv/M5u7mk
# I0Ks0BXDf56iXNc48RaycNOjxN+zxXKsLgp3/A2UUrf8H5VzJD0BKLwPDU+zkQGO
# bp0ndVXRFzs0IXuXAZSvf4DP0REKV4TJf1bgvUacgr6Unb+0ILBgfrhN9Q0/29Dq
# hYyKVnHRLZRMyIw80xSinL0m/9NTIMdgaZtYClT0Bef9Maz5yIUXx7gpGaQpL0bj
# 3duRX58/Nj4OMGcrRrc1r5a+2kxgzKi7nw0U1BjEMJh0giHPYla1IXMSHv2qyghY
# h3ekFesZVf/QOVQtJu5FGjpvzdeE8NfwKMVPZIMC1Pvi3vG8Aij0bdonigbSlofe
# 6GsO8Ft96XZpkyAcSpcsdxkrk5WYnJee647BeFbGRCXfBhKaBi2fA179g6JTZ8qx
# +o2hZMmIklnLqEbAyfKm/31X2xJ2+opBJNQb/HKlFKLUrUMcpEmLQTkUAx4p+hul
# Iq6lw02C0I3aa7fb9xhAV3PwcaP7Sn1FNsH3jYL6uckNU4B9+rY5WDLvbxhQiddP
# nTO9GrWdod6VQXqngwIDAQABo4IBWjCCAVYwHwYDVR0jBBgwFoAUU3m/WqorSs9U
# gOHYm8Cd8rIDZsswHQYDVR0OBBYEFBqh+GEZIA/DQXdFKI7RNV8GEgRVMA4GA1Ud
# DwEB/wQEAwIBhjASBgNVHRMBAf8ECDAGAQH/AgEAMBMGA1UdJQQMMAoGCCsGAQUF
# BwMIMBEGA1UdIAQKMAgwBgYEVR0gADBQBgNVHR8ESTBHMEWgQ6BBhj9odHRwOi8v
# Y3JsLnVzZXJ0cnVzdC5jb20vVVNFUlRydXN0UlNBQ2VydGlmaWNhdGlvbkF1dGhv
# cml0eS5jcmwwdgYIKwYBBQUHAQEEajBoMD8GCCsGAQUFBzAChjNodHRwOi8vY3J0
# LnVzZXJ0cnVzdC5jb20vVVNFUlRydXN0UlNBQWRkVHJ1c3RDQS5jcnQwJQYIKwYB
# BQUHMAGGGWh0dHA6Ly9vY3NwLnVzZXJ0cnVzdC5jb20wDQYJKoZIhvcNAQEMBQAD
# ggIBAG1UgaUzXRbhtVOBkXXfA3oyCy0lhBGysNsqfSoF9bw7J/RaoLlJWZApbGHL
# tVDb4n35nwDvQMOt0+LkVvlYQc/xQuUQff+wdB+PxlwJ+TNe6qAcJlhc87QRD9XV
# w+K81Vh4v0h24URnbY+wQxAPjeT5OGK/EwHFhaNMxcyyUzCVpNb0llYIuM1cfwGW
# vnJSajtCN3wWeDmTk5SbsdyybUFtZ83Jb5A9f0VywRsj1sJVhGbks8VmBvbz1kte
# raMrQoohkv6ob1olcGKBc2NeoLvY3NdK0z2vgwY4Eh0khy3k/ALWPncEvAQ2ted3
# y5wujSMYuaPCRx3wXdahc1cFaJqnyTdlHb7qvNhCg0MFpYumCf/RoZSmTqo9CfUF
# bLfSZFrYKiLCS53xOV5M3kg9mzSWmglfjv33sVKRzj+J9hyhtal1H3G/W0NdZT1Q
# gW6r8NDT/LKzH7aZlib0PHmLXGTMze4nmuWgwAxyh8FuTVrTHurwROYybxzrF06U
# w3hlIDsPQaof6aFBnf6xuKBlKjTg3qj5PObBMLvAoGMs/FwWAKjQxH/qEZ0eBsam
# bTJdtDgJK0kHqv3sMNrxpy/Pt/360KOE2See+wFmd7lWEOEgbsausfm2usg1XTN2
# jvF8IAwqd661ogKGuinutFoAsYyr4/kKyVRd1LlqdJ69SK6YMYIELTCCBCkCAQEw
# gZIwfTELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQ
# MA4GA1UEBxMHU2FsZm9yZDEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMSUwIwYD
# VQQDExxTZWN0aWdvIFJTQSBUaW1lIFN0YW1waW5nIENBAhEAkDl/mtJKOhPyvZFf
# CDipQzANBglghkgBZQMEAgIFAKCCAWswGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJ
# EAEEMBwGCSqGSIb3DQEJBTEPFw0yMzAyMTQyMTA4MDRaMD8GCSqGSIb3DQEJBDEy
# BDDJEbaK/24pD0DmF5sf6bIm5/NMA83osMhydnuKaatGq+EbEk2nC8aE27m/wwAP
# Nhkwge0GCyqGSIb3DQEJEAIMMYHdMIHaMIHXMBYEFKs0ATqsQJcxnwga8LMY4YP4
# D3iBMIG8BBQC1luV4oNwwVcAlfqI+SPdk3+tjzCBozCBjqSBizCBiDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCk5ldyBKZXJzZXkxFDASBgNVBAcTC0plcnNleSBDaXR5
# MR4wHAYDVQQKExVUaGUgVVNFUlRSVVNUIE5ldHdvcmsxLjAsBgNVBAMTJVVTRVJU
# cnVzdCBSU0EgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkCEDAPb6zdZph0fKlGNqd4
# LbkwDQYJKoZIhvcNAQEBBQAEggIAMq5ToOkSOWaWpdrWVtYiGgguPtjdyxDxlrzo
# HWpyJUvmtYybt4zMr38eV00ZLv/Gm89BohSxVAhTRzGO/7+zqyvh07y63yAy9cPA
# RzCKz8D+ao2DAE4KZ2+cBWWUAovJJQk4cRezTikhE6PByaV3nNi4zs4sPt1ULKNR
# 2PSnK/cKbQwkEGhsDVP64Fw6a4iYYwgtHaZ/e4GwLtjqmjCMNaGXK45r1BDarOj7
# 1u1oQZMKJDP7iYvySKQmQUL00AZwDnhNj6/i6gEt812U0wgyyycaU3rQS+xNzX9d
# 049DbEcvgYoab8DVaJcf4HVoN1fiEXopreoKmduZDupIVjWbKoR5ljPFOYuS0sd6
# o6v0xrMQa6pJQFPM2nC4slu75Jnenhs7x6YR38EhGD2nJg7AEWreta5UccazpAZr
# 0Q5QcIKxNIbg/rncSbbDp+HB7z3uyOBISRi/N+ZF46JjI8CkGCLd4IcR6g6SvZ5m
# 0A8zs2Ppmsm7mY5K+ABuDe00gLaHA1hocnVKu9Mcx0Kdj0JS1ONCXzQD6jUZj7MG
# CsOH5WeeVOGTYi4Ux9loE7wWEI69TTt0kd0BW5f3QFlz3aSuvZOXdYdLgLzcPfrY
# jYRHCqCSYXxs5xpK9tJS5vBZE/2jkwAdgtFbmuCd8CQgMH705FzQzdhatFfs4dof
# 8Tnuyn4=
# SIG # End signature block
