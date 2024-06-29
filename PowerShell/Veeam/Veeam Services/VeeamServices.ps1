<#	
	.NOTES
	===========================================================================
	 Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2022 v5.8.213
	 Created on:   	19-02-2023 11:29
	 Created by:   	Michael Morten Sonne
	 Organization: 	Sonne´s Cloud
	 Filename:     	VeeamServices.ps1
	 Version:		1.1
	===========================================================================
	.DESCRIPTION
		Start, stop, status and find functions for all Veeam Services

		Output for a Backup and Replication installation:
		Get-Service | Where-Object { $_.DisplayName -like "*Veeam*" -and $_.Name -notlike "*SQL*" } | Format-Table Name, DisplayName -AutoSize

		Name                      DisplayName
		----                      -----------
		VeeamBackupCdpSvc         Veeam CDP Coordinator Service
		VeeamBackupRESTSvc        Veeam Backup Server RESTful API Service
		VeeamBackupSvc            Veeam Backup Service
		VeeamBrokerSvc            Veeam Broker Service
		VeeamCatalogSvc           Veeam Guest Catalog Service
		VeeamCloudSvc             Veeam Cloud Connect Service
		VeeamCRS                  Veeam ONE Error Reporting Service
		VeeamDCS                  Veeam ONE Monitoring Service
		VeeamDeploySvc            Veeam Installer Service
		VeeamDistributionSvc      Veeam Distribution Service
		VeeamExplorersRecoverySvc Veeam Explorers Recovery Service
		VeeamFilesysVssSvc        Veeam Backup VSS Integration Service
		VeeamGCPSvc               Veeam GCP Service
		VeeamKastenSvc            Veeam Kubernetes Service
		VeeamMountSvc             Veeam Mount Service
		VeeamNFSSvc               Veeam vPower NFS Service
		VeeamOneAgentSvc          Veeam ONE Agent
		VeeamRSS                  Veeam ONE Reporting Service
		VeeamTransportSvc         Veeam Data Mover Service
		VeeamVssProviderSvc       Veeam VSS Hardware Provider Service

	.USE
		.\VeeamServices.ps1 -start : Start Veeam Services
		.\VeeamServices.ps1 -stop : Stop Veeam Services
		.\VeeamServices.ps1 -status : Status for Veeam Services
		.\VeeamServices.ps1 -getservices : Get current Veeam Services in this host

	.HISTORY
		19-02-2023 - v. 1.0
			Created

		20-02-2022 - v 1.1:
			Fix to exclude SQL services
#>

# Array of service names to retrieve the status
#$servicesToCheck = Get-Service | Where-Object { $_.DisplayName -like "*Veeam*" -and $_.Name -notlike "*SQL*" } | Select-Object -ExpandProperty Name
$servicesToCheck = Get-Service | Where-Object { $_.DisplayName -like "*Veeam*" -and $_.StartType -notlike "Disabled" -and $_.Name -notlike "*SQL*" } | Select-Object -ExpandProperty Name

# Array to store service name and display name
$serviceNames = @()

# Retrieve all Veeam services and store their name and display name in an array
$veeamServices = Get-Service | Where-Object { $_.DisplayName -like "Veeam*" }
foreach ($service in $veeamServices)
{
	$serviceNames += @{
		Name	    = $service.Name
		DisplayName = $service.DisplayName
	}
}

#Start Veeam Services
function Start-VeeamService
{
	#Loop $servicesToCheck for services
	foreach ($serviceName in $servicesToCheck)
	{
		#Get the service name
		$service = $serviceNames | Where-Object { $_.Name -eq $serviceName }
		
		#If service exists
		if ($service)
		{
			#Get current status on selected service
			$status = Get-Service $serviceName | Select-Object Status
			
			# Select status to write out
			if ($status.Status -eq "Stopped")
			{
				# Start the service
				Start-Service $serviceName
				
				# Wait for the service to start
				while ((Get-Service $serviceName).Status -ne "Running")
				{
					Start-Sleep -Milliseconds 100
				}
				#Service is started
				Write-Host "$($service.DisplayName) ($($service.Name)) is: Started" -ForegroundColor Green
			}
			else
			{
				#Service running in advance - skip
				Write-Host "$($service.DisplayName) ($($service.Name)) is: running in advance, skipping..." -ForegroundColor Yellow
			}
		}
		#If service does not exists
		else
		{
			Write-Host "$($serviceName) service not found"
		}
	}
}

#Stop Veeam Services
function Stop-VeeamService
{
	#Loop $servicesToCheck for services
	foreach ($serviceName in $servicesToCheck)
	{
		#Get the service name
		$service = $serviceNames | Where-Object { $_.Name -eq $serviceName }
		
		#If service exists
		if ($service)
		{
			#Get current status on selected service
			$status = Get-Service $serviceName | Select-Object Status
			
			# Select status to write out
			if ($status.Status -eq "Running")
			{
				# Start the service
				Stop-Service $serviceName -Force
				
				# Wait for the service to start
				while ((Get-Service $serviceName).Status -ne "Stopped")
				{
					Start-Sleep -Milliseconds 100
				}
				
				#Service is stopped
				Write-Host "$($service.DisplayName) ($($service.Name)) is: Stopped" -ForegroundColor Green
			}
			else
			{
				#Service stopped in advance - skip
				Write-Host "$($service.DisplayName) ($($service.Name)) is: stopped in advance, skipping..." -ForegroundColor Yellow
			}
		}
		#If service does not exists
		else
		{
			Write-Host "$($serviceName) service not found"
		}
	}
}

function Get-VeeamServiceStatus
{
	#Loop $servicesToCheck for services
	foreach ($serviceName in $servicesToCheck)
	{
		#Get the service name
		$service = $serviceNames | Where-Object { $_.Name -eq $serviceName }
		
		#If service exists
		if ($service)
		{
			#Get current status on selected service
			$status = Get-Service $serviceName | Select-Object Status
			
			# Write out service name
			Write-Host -NoNewline "$($service.DisplayName) ($($service.Name)) status is: " -ForegroundColor Yellow
			
			# Select status to write out
			if ($status.Status -eq "Running")
			{
				Write-Host -ForegroundColor Green $($status.Status)
			}
			else
			{
				Write-Host -ForegroundColor Red $($status.Status)
			}
		}
		#If service does not exists
		else
		{
			Write-Host "$($serviceName) service not found"
		}
	}
}

function Get-VeeamServiceInfo
{
	#Show service name, status etc.
	Get-Service | Where-Object { $_.DisplayName -like "*Veeam*" } | Format-Table -AutoSize
}

# Parse command line arguments
if ($args[0] -eq "-start")
{
	Start-VeeamService
}
elseif ($args[0] -eq "-stop")
{
	Stop-VeeamService
}
elseif ($args[0] -eq "-status")
{
	Get-VeeamServiceStatus
}
elseif ($args[0] -eq "-getservices")
{
	Get-VeeamServiceInfo
}
else
{
	Write-Error "Invalid argument. Usage: VeeamServices.ps1 -start | -stop | -status | -getservices"
}
# SIG # Begin signature block
# MIIq2gYJKoZIhvcNAQcCoIIqyzCCKscCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDh44epQiP6vSlz
# EjdFMoIZCiYPLDDu1SEdH1b2UkdZgKCCI/8wggQyMIIDGqADAgECAgEBMA0GCSqG
# SIb3DQEBBQUAMHsxCzAJBgNVBAYTAkdCMRswGQYDVQQIDBJHcmVhdGVyIE1hbmNo
# ZXN0ZXIxEDAOBgNVBAcMB1NhbGZvcmQxGjAYBgNVBAoMEUNvbW9kbyBDQSBMaW1p
# dGVkMSEwHwYDVQQDDBhBQUEgQ2VydGlmaWNhdGUgU2VydmljZXMwHhcNMDQwMTAx
# MDAwMDAwWhcNMjgxMjMxMjM1OTU5WjB7MQswCQYDVQQGEwJHQjEbMBkGA1UECAwS
# R3JlYXRlciBNYW5jaGVzdGVyMRAwDgYDVQQHDAdTYWxmb3JkMRowGAYDVQQKDBFD
# b21vZG8gQ0EgTGltaXRlZDEhMB8GA1UEAwwYQUFBIENlcnRpZmljYXRlIFNlcnZp
# Y2VzMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvkCd9G7h6naHHE1F
# RI6+RsiDBp3BKv4YH47kAvrzq11QihYxC5oG0MVwIs1JLVRjzLZuaEYLU+rLTCTA
# vHJO6vEVrvRUmhIKw3qyM2Di2olV8yJY897cz++DhqKMlE+faPKYkEaEJ8d2v+PM
# NSyLXgdkZYLASLCokflhn3YgUKiRx2a163hiA1bwihoT6jGjHqCZ/Tj29icyWG8H
# 9Wu4+xQrr7eqzNZjX3OM2gWZqDioyxd4NlGs6Z70eDqNzw/ZQuKYDKsvnw4B3u+f
# mUnxLd+sdE0bmLVHxeUp0fmQGMdinL6DxyZ7Poolx8DdneY1aBAgnY/Y3tLDhJwN
# XugvyQIDAQABo4HAMIG9MB0GA1UdDgQWBBSgEQojPpbxB+zirynvgqV/0DCktDAO
# BgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zB7BgNVHR8EdDByMDigNqA0
# hjJodHRwOi8vY3JsLmNvbW9kb2NhLmNvbS9BQUFDZXJ0aWZpY2F0ZVNlcnZpY2Vz
# LmNybDA2oDSgMoYwaHR0cDovL2NybC5jb21vZG8ubmV0L0FBQUNlcnRpZmljYXRl
# U2VydmljZXMuY3JsMA0GCSqGSIb3DQEBBQUAA4IBAQAIVvwC8Jvo/6T61nvGRIDO
# T8TF9gBYzKa2vBRJaAR26ObuXewCD2DWjVAYTyZOAePmsKXuv7x0VEG//fwSuMdP
# WvSJYAV/YLcFSvP28cK/xLl0hrYtfWvM0vNG3S/G4GrDwzQDLH2W3VrCDqcKmcEF
# i6sML/NcOs9sN1UJh95TQGxY7/y2q2VuBPYb3DzgWhXGntnxWUgwIWUDbOzpIXPs
# mwOh4DetoBUYj/q6As6nLKkQEyzU5QgmqyKXYPiQXnTUoppTvfKpaOCibsLXbLGj
# D56/62jnVvKu8uMrODoJgbVrhde+Le0/GreyY+L1YiyC1GoAQVDxOYOflek2lphu
# MIIFbzCCBFegAwIBAgIQSPyTtGBVlI02p8mKidaUFjANBgkqhkiG9w0BAQwFADB7
# MQswCQYDVQQGEwJHQjEbMBkGA1UECAwSR3JlYXRlciBNYW5jaGVzdGVyMRAwDgYD
# VQQHDAdTYWxmb3JkMRowGAYDVQQKDBFDb21vZG8gQ0EgTGltaXRlZDEhMB8GA1UE
# AwwYQUFBIENlcnRpZmljYXRlIFNlcnZpY2VzMB4XDTIxMDUyNTAwMDAwMFoXDTI4
# MTIzMTIzNTk1OVowVjELMAkGA1UEBhMCR0IxGDAWBgNVBAoTD1NlY3RpZ28gTGlt
# aXRlZDEtMCsGA1UEAxMkU2VjdGlnbyBQdWJsaWMgQ29kZSBTaWduaW5nIFJvb3Qg
# UjQ2MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAjeeUEiIEJHQu/xYj
# ApKKtq42haxH1CORKz7cfeIxoFFvrISR41KKteKW3tCHYySJiv/vEpM7fbu2ir29
# BX8nm2tl06UMabG8STma8W1uquSggyfamg0rUOlLW7O4ZDakfko9qXGrYbNzszwL
# DO/bM1flvjQ345cbXf0fEj2CA3bm+z9m0pQxafptszSswXp43JJQ8mTHqi0Eq8Nq
# 6uAvp6fcbtfo/9ohq0C/ue4NnsbZnpnvxt4fqQx2sycgoda6/YDnAdLv64IplXCN
# /7sVz/7RDzaiLk8ykHRGa0c1E3cFM09jLrgt4b9lpwRrGNhx+swI8m2JmRCxrds+
# LOSqGLDGBwF1Z95t6WNjHjZ/aYm+qkU+blpfj6Fby50whjDoA7NAxg0POM1nqFOI
# +rgwZfpvx+cdsYN0aT6sxGg7seZnM5q2COCABUhA7vaCZEao9XOwBpXybGWfv1Vb
# HJxXGsd4RnxwqpQbghesh+m2yQ6BHEDWFhcp/FycGCvqRfXvvdVnTyheBe6QTHrn
# xvTQ/PrNPjJGEyA2igTqt6oHRpwNkzoJZplYXCmjuQymMDg80EY2NXycuu7D1fkK
# dvp+BRtAypI16dV60bV/AK6pkKrFfwGcELEW/MxuGNxvYv6mUKe4e7idFT/+IAx1
# yCJaE5UZkADpGtXChvHjjuxf9OUCAwEAAaOCARIwggEOMB8GA1UdIwQYMBaAFKAR
# CiM+lvEH7OKvKe+CpX/QMKS0MB0GA1UdDgQWBBQy65Ka/zWWSC8oQEJwIDaRXBeF
# 5jAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zATBgNVHSUEDDAKBggr
# BgEFBQcDAzAbBgNVHSAEFDASMAYGBFUdIAAwCAYGZ4EMAQQBMEMGA1UdHwQ8MDow
# OKA2oDSGMmh0dHA6Ly9jcmwuY29tb2RvY2EuY29tL0FBQUNlcnRpZmljYXRlU2Vy
# dmljZXMuY3JsMDQGCCsGAQUFBwEBBCgwJjAkBggrBgEFBQcwAYYYaHR0cDovL29j
# c3AuY29tb2RvY2EuY29tMA0GCSqGSIb3DQEBDAUAA4IBAQASv6Hvi3SamES4aUa1
# qyQKDKSKZ7g6gb9Fin1SB6iNH04hhTmja14tIIa/ELiueTtTzbT72ES+BtlcY2fU
# QBaHRIZyKtYyFfUSg8L54V0RQGf2QidyxSPiAjgaTCDi2wH3zUZPJqJ8ZsBRNraJ
# AlTH/Fj7bADu/pimLpWhDFMpH2/YGaZPnvesCepdgsaLr4CnvYFIUoQx2jLsFeSm
# TD1sOXPUC4U5IOCFGmjhp0g4qdE2JXfBjRkWxYhMZn0vY86Y6GnfrDyoXZ3JHFuu
# 2PMvdM+4fvbXg50RlmKarkUT2n/cR/vfw1Kf5gZV6Z2M8jpiUbzsJA8p1FiAhORF
# e1rYMIIGGjCCBAKgAwIBAgIQYh1tDFIBnjuQeRUgiSEcCjANBgkqhkiG9w0BAQwF
# ADBWMQswCQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMS0wKwYD
# VQQDEyRTZWN0aWdvIFB1YmxpYyBDb2RlIFNpZ25pbmcgUm9vdCBSNDYwHhcNMjEw
# MzIyMDAwMDAwWhcNMzYwMzIxMjM1OTU5WjBUMQswCQYDVQQGEwJHQjEYMBYGA1UE
# ChMPU2VjdGlnbyBMaW1pdGVkMSswKQYDVQQDEyJTZWN0aWdvIFB1YmxpYyBDb2Rl
# IFNpZ25pbmcgQ0EgUjM2MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA
# myudU/o1P45gBkNqwM/1f/bIU1MYyM7TbH78WAeVF3llMwsRHgBGRmxDeEDIArCS
# 2VCoVk4Y/8j6stIkmYV5Gej4NgNjVQ4BYoDjGMwdjioXan1hlaGFt4Wk9vT0k2oW
# JMJjL9G//N523hAm4jF4UjrW2pvv9+hdPX8tbbAfI3v0VdJiJPFy/7XwiunD7mBx
# NtecM6ytIdUlh08T2z7mJEXZD9OWcJkZk5wDuf2q52PN43jc4T9OkoXZ0arWZVef
# fvMr/iiIROSCzKoDmWABDRzV/UiQ5vqsaeFaqQdzFf4ed8peNWh1OaZXnYvZQgWx
# /SXiJDRSAolRzZEZquE6cbcH747FHncs/Kzcn0Ccv2jrOW+LPmnOyB+tAfiWu01T
# PhCr9VrkxsHC5qFNxaThTG5j4/Kc+ODD2dX/fmBECELcvzUHf9shoFvrn35XGf2R
# PaNTO2uSZ6n9otv7jElspkfK9qEATHZcodp+R4q2OIypxR//YEb3fkDn3UayWW9b
# AgMBAAGjggFkMIIBYDAfBgNVHSMEGDAWgBQy65Ka/zWWSC8oQEJwIDaRXBeF5jAd
# BgNVHQ4EFgQUDyrLIIcouOxvSK4rVKYpqhekzQwwDgYDVR0PAQH/BAQDAgGGMBIG
# A1UdEwEB/wQIMAYBAf8CAQAwEwYDVR0lBAwwCgYIKwYBBQUHAwMwGwYDVR0gBBQw
# EjAGBgRVHSAAMAgGBmeBDAEEATBLBgNVHR8ERDBCMECgPqA8hjpodHRwOi8vY3Js
# LnNlY3RpZ28uY29tL1NlY3RpZ29QdWJsaWNDb2RlU2lnbmluZ1Jvb3RSNDYuY3Js
# MHsGCCsGAQUFBwEBBG8wbTBGBggrBgEFBQcwAoY6aHR0cDovL2NydC5zZWN0aWdv
# LmNvbS9TZWN0aWdvUHVibGljQ29kZVNpZ25pbmdSb290UjQ2LnA3YzAjBggrBgEF
# BQcwAYYXaHR0cDovL29jc3Auc2VjdGlnby5jb20wDQYJKoZIhvcNAQEMBQADggIB
# AAb/guF3YzZue6EVIJsT/wT+mHVEYcNWlXHRkT+FoetAQLHI1uBy/YXKZDk8+Y1L
# oNqHrp22AKMGxQtgCivnDHFyAQ9GXTmlk7MjcgQbDCx6mn7yIawsppWkvfPkKaAQ
# siqaT9DnMWBHVNIabGqgQSGTrQWo43MOfsPynhbz2Hyxf5XWKZpRvr3dMapandPf
# YgoZ8iDL2OR3sYztgJrbG6VZ9DoTXFm1g0Rf97Aaen1l4c+w3DC+IkwFkvjFV3jS
# 49ZSc4lShKK6BrPTJYs4NG1DGzmpToTnwoqZ8fAmi2XlZnuchC4NPSZaPATHvNIz
# t+z1PHo35D/f7j2pO1S8BCysQDHCbM5Mnomnq5aYcKCsdbh0czchOm8bkinLrYrK
# pii+Tk7pwL7TjRKLXkomm5D1Umds++pip8wH2cQpf93at3VDcOK4N7EwoIJB0kak
# 6pSzEu4I64U6gZs7tS/dGNSljf2OSSnRr7KWzq03zl8l75jy+hOds9TWSenLbjBQ
# UGR96cFr6lEUfAIEHVC1L68Y1GGxx4/eRI82ut83axHMViw1+sVpbPxg51Tbnio1
# lB93079WPFnYaOvfGAA0e0zcfF/M9gXr+korwQTh2Prqooq2bYNMvUoUKD85gnJ+
# t0smrWrb8dee2CvYZXD5laGtaAxOfy/VKNmwuWuAh9kcMIIGSjCCBLKgAwIBAgIQ
# EeGghmSHroJggo0o8FF6xjANBgkqhkiG9w0BAQwFADBUMQswCQYDVQQGEwJHQjEY
# MBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMSswKQYDVQQDEyJTZWN0aWdvIFB1Ymxp
# YyBDb2RlIFNpZ25pbmcgQ0EgUjM2MB4XDTIzMDIxOTAwMDAwMFoXDTI2MDUxODIz
# NTk1OVowYTELMAkGA1UEBhMCREsxFDASBgNVBAgMC0hvdmVkc3RhZGVuMR0wGwYD
# VQQKDBRNaWNoYWVsIE1vcnRlbiBTb25uZTEdMBsGA1UEAwwUTWljaGFlbCBNb3J0
# ZW4gU29ubmUwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC1RiFhue2j
# 4jq7it24N7ZTzB6JdaX5xEIgpGKJu4RVy1cYRr3uDnEJsfcbSsu0CB5mx3R91XOC
# eH6EtP27+HJ82EXdINqnE46NEPm+SUVEmUNMlGy8hyX9U5AiTjg1jkSZbIv8aaXE
# HQG1O0F9ihRODZEMzVCDk0pSnLcffWahXryiL8IZJiKAfllp5f6kuIqRTDv3eJu6
# PCCIIuPSz6t7VcWbNGiejdNl+V6dhaBtn2cp7nRyH/cGmBbWFwNwfJrEMGkRKUGP
# PNCpIv9u+aUgvk/Ppm528KylzmfBo1tr7xCWXuckiKwNu6JjLAZ5qGWJIjTJjBmF
# kImeRO+WSImeFKlqbmoaBqQS6GTV/k4yhRbqpqPBKn2HQqS4mIMPeat4Bzjbuk8E
# 4NNVsGnmRbZYcfKkoA/Mey/0kZ+Kp8f/7nAYNUNH9wJepc/vs/LeLcugsRf1q/WS
# jqGIR37ekgBO03fVRnViS5KenGNan66vkAPsUe64xYu3WoMbz9Uc2anoeYJQEO+I
# N/5WSXYA07/8gf848Y+nR488IoudNVVuHnEl/UUKcFm5Xgw64g21TSccM9+5gXEk
# MpBl1X1VfAHHV59c7xA5HbIbS1BgC+qutQroABOC6DlqIQRLZO3Vdl9K7xGN1nHu
# OwEy2NeFTOYEAhLEcZBKrdR8HSuEfr/y7QIDAQABo4IBiTCCAYUwHwYDVR0jBBgw
# FoAUDyrLIIcouOxvSK4rVKYpqhekzQwwHQYDVR0OBBYEFHXzflI6jz2GFi6oeM12
# kzY/AHybMA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoG
# CCsGAQUFBwMDMEoGA1UdIARDMEEwNQYMKwYBBAGyMQECAQMCMCUwIwYIKwYBBQUH
# AgEWF2h0dHBzOi8vc2VjdGlnby5jb20vQ1BTMAgGBmeBDAEEATBJBgNVHR8EQjBA
# MD6gPKA6hjhodHRwOi8vY3JsLnNlY3RpZ28uY29tL1NlY3RpZ29QdWJsaWNDb2Rl
# U2lnbmluZ0NBUjM2LmNybDB5BggrBgEFBQcBAQRtMGswRAYIKwYBBQUHMAKGOGh0
# dHA6Ly9jcnQuc2VjdGlnby5jb20vU2VjdGlnb1B1YmxpY0NvZGVTaWduaW5nQ0FS
# MzYuY3J0MCMGCCsGAQUFBzABhhdodHRwOi8vb2NzcC5zZWN0aWdvLmNvbTANBgkq
# hkiG9w0BAQwFAAOCAYEARfKoWg16JOUe/ODan4zLDX0vex/iLRPksZv0DHCIU4oi
# AYSGHf5S33U8Kc+Wqk5eTOPhQwQ3jZtJo2PJNgnYPgzn+CX72QL+LUFcm4RHeNhO
# TU3xubFjeq7jIwS6UrI8Fc76J5nlC0sJ12PgLVUmoNDFP1J8hTk0uvYE4zqtxAvh
# /ziWvw3yPE/7AyAs08ueXOWggx0V2+g7K/h5uz4hgkOnNAIWDrf3rVytfmI0KPU/
# hXCBdGXt+AioqyEWtRRXtuoDYx3aazAOtkzl0CayvsfQ7VWPEAm/iFGTWI+pTYl5
# 6N7evSTehbyFNhLT6yrPEgVdrg2UDHnDSft8O+/xB6HfNrge97xojr1/ENgpHTLp
# 8/lX18mODoddABJwqs5dFFdhxx+uh7GvGbYvpF1h/R01JAyQndlR3QxDidKNpANf
# 0nxEzDwDv8nhc9cV8ugiCedHZH87mIH/UrCAKHdQ8fUx7NqpFyMMn+ZUyQbzxy0a
# sbP5PjJ+9AFIso+dPyWDMIIG7DCCBNSgAwIBAgIQMA9vrN1mmHR8qUY2p3gtuTAN
# BgkqhkiG9w0BAQwFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCk5ldyBKZXJz
# ZXkxFDASBgNVBAcTC0plcnNleSBDaXR5MR4wHAYDVQQKExVUaGUgVVNFUlRSVVNU
# IE5ldHdvcmsxLjAsBgNVBAMTJVVTRVJUcnVzdCBSU0EgQ2VydGlmaWNhdGlvbiBB
# dXRob3JpdHkwHhcNMTkwNTAyMDAwMDAwWhcNMzgwMTE4MjM1OTU5WjB9MQswCQYD
# VQQGEwJHQjEbMBkGA1UECBMSR3JlYXRlciBNYW5jaGVzdGVyMRAwDgYDVQQHEwdT
# YWxmb3JkMRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQxJTAjBgNVBAMTHFNlY3Rp
# Z28gUlNBIFRpbWUgU3RhbXBpbmcgQ0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAw
# ggIKAoICAQDIGwGv2Sx+iJl9AZg/IJC9nIAhVJO5z6A+U++zWsB21hoEpc5Hg7Xr
# xMxJNMvzRWW5+adkFiYJ+9UyUnkuyWPCE5u2hj8BBZJmbyGr1XEQeYf0RirNxFrJ
# 29ddSU1yVg/cyeNTmDoqHvzOWEnTv/M5u7mkI0Ks0BXDf56iXNc48RaycNOjxN+z
# xXKsLgp3/A2UUrf8H5VzJD0BKLwPDU+zkQGObp0ndVXRFzs0IXuXAZSvf4DP0REK
# V4TJf1bgvUacgr6Unb+0ILBgfrhN9Q0/29DqhYyKVnHRLZRMyIw80xSinL0m/9NT
# IMdgaZtYClT0Bef9Maz5yIUXx7gpGaQpL0bj3duRX58/Nj4OMGcrRrc1r5a+2kxg
# zKi7nw0U1BjEMJh0giHPYla1IXMSHv2qyghYh3ekFesZVf/QOVQtJu5FGjpvzdeE
# 8NfwKMVPZIMC1Pvi3vG8Aij0bdonigbSlofe6GsO8Ft96XZpkyAcSpcsdxkrk5WY
# nJee647BeFbGRCXfBhKaBi2fA179g6JTZ8qx+o2hZMmIklnLqEbAyfKm/31X2xJ2
# +opBJNQb/HKlFKLUrUMcpEmLQTkUAx4p+hulIq6lw02C0I3aa7fb9xhAV3PwcaP7
# Sn1FNsH3jYL6uckNU4B9+rY5WDLvbxhQiddPnTO9GrWdod6VQXqngwIDAQABo4IB
# WjCCAVYwHwYDVR0jBBgwFoAUU3m/WqorSs9UgOHYm8Cd8rIDZsswHQYDVR0OBBYE
# FBqh+GEZIA/DQXdFKI7RNV8GEgRVMA4GA1UdDwEB/wQEAwIBhjASBgNVHRMBAf8E
# CDAGAQH/AgEAMBMGA1UdJQQMMAoGCCsGAQUFBwMIMBEGA1UdIAQKMAgwBgYEVR0g
# ADBQBgNVHR8ESTBHMEWgQ6BBhj9odHRwOi8vY3JsLnVzZXJ0cnVzdC5jb20vVVNF
# UlRydXN0UlNBQ2VydGlmaWNhdGlvbkF1dGhvcml0eS5jcmwwdgYIKwYBBQUHAQEE
# ajBoMD8GCCsGAQUFBzAChjNodHRwOi8vY3J0LnVzZXJ0cnVzdC5jb20vVVNFUlRy
# dXN0UlNBQWRkVHJ1c3RDQS5jcnQwJQYIKwYBBQUHMAGGGWh0dHA6Ly9vY3NwLnVz
# ZXJ0cnVzdC5jb20wDQYJKoZIhvcNAQEMBQADggIBAG1UgaUzXRbhtVOBkXXfA3oy
# Cy0lhBGysNsqfSoF9bw7J/RaoLlJWZApbGHLtVDb4n35nwDvQMOt0+LkVvlYQc/x
# QuUQff+wdB+PxlwJ+TNe6qAcJlhc87QRD9XVw+K81Vh4v0h24URnbY+wQxAPjeT5
# OGK/EwHFhaNMxcyyUzCVpNb0llYIuM1cfwGWvnJSajtCN3wWeDmTk5SbsdyybUFt
# Z83Jb5A9f0VywRsj1sJVhGbks8VmBvbz1kteraMrQoohkv6ob1olcGKBc2NeoLvY
# 3NdK0z2vgwY4Eh0khy3k/ALWPncEvAQ2ted3y5wujSMYuaPCRx3wXdahc1cFaJqn
# yTdlHb7qvNhCg0MFpYumCf/RoZSmTqo9CfUFbLfSZFrYKiLCS53xOV5M3kg9mzSW
# mglfjv33sVKRzj+J9hyhtal1H3G/W0NdZT1QgW6r8NDT/LKzH7aZlib0PHmLXGTM
# ze4nmuWgwAxyh8FuTVrTHurwROYybxzrF06Uw3hlIDsPQaof6aFBnf6xuKBlKjTg
# 3qj5PObBMLvAoGMs/FwWAKjQxH/qEZ0eBsambTJdtDgJK0kHqv3sMNrxpy/Pt/36
# 0KOE2See+wFmd7lWEOEgbsausfm2usg1XTN2jvF8IAwqd661ogKGuinutFoAsYyr
# 4/kKyVRd1LlqdJ69SK6YMIIG9jCCBN6gAwIBAgIRAJA5f5rSSjoT8r2RXwg4qUMw
# DQYJKoZIhvcNAQEMBQAwfTELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIg
# TWFuY2hlc3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEYMBYGA1UEChMPU2VjdGlnbyBM
# aW1pdGVkMSUwIwYDVQQDExxTZWN0aWdvIFJTQSBUaW1lIFN0YW1waW5nIENBMB4X
# DTIyMDUxMTAwMDAwMFoXDTMzMDgxMDIzNTk1OVowajELMAkGA1UEBhMCR0IxEzAR
# BgNVBAgTCk1hbmNoZXN0ZXIxGDAWBgNVBAoTD1NlY3RpZ28gTGltaXRlZDEsMCoG
# A1UEAwwjU2VjdGlnbyBSU0EgVGltZSBTdGFtcGluZyBTaWduZXIgIzMwggIiMA0G
# CSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCQsnE/eeHUuYoXzMOXwpCUcu1aOm8B
# Q39zWiifJHygNUAG+pSvCqGDthPkSxUGXmqKIDRxe7slrT9bCqQfL2x9LmFR0IxZ
# Nz6mXfEeXYC22B9g480Saogfxv4Yy5NDVnrHzgPWAGQoViKxSxnS8JbJRB85XZyw
# lu1aSY1+cuRDa3/JoD9sSq3VAE+9CriDxb2YLAd2AXBF3sPwQmnq/ybMA0QfFijh
# anS2nEX6tjrOlNEfvYxlqv38wzzoDZw4ZtX8fR6bWYyRWkJXVVAWDUt0cu6gKjH8
# JgI0+WQbWf3jOtTouEEpdAE/DeATdysRPPs9zdDn4ZdbVfcqA23VzWLazpwe/Opw
# feZ9S2jOWilh06BcJbOlJ2ijWP31LWvKX2THaygM2qx4Qd6S7w/F7KvfLW8aVFFs
# M7ONWWDn3+gXIqN5QWLP/Hvzktqu4DxPD1rMbt8fvCKvtzgQmjSnC//+HV6k8+4W
# OCs/rHaUQZ1kHfqA/QDh/vg61MNeu2lNcpnl8TItUfphrU3qJo5t/KlImD7yRg1p
# sbdu9AXbQQXGGMBQ5Pit/qxjYUeRvEa1RlNsxfThhieThDlsdeAdDHpZiy7L9GQs
# Qkf0VFiFN+XHaafSJYuWv8at4L2xN/cf30J7qusc6es9Wt340pDVSZo6HYMaV38c
# AcLOHH3M+5YVxQIDAQABo4IBgjCCAX4wHwYDVR0jBBgwFoAUGqH4YRkgD8NBd0Uo
# jtE1XwYSBFUwHQYDVR0OBBYEFCUuaDxrmiskFKkfot8mOs8UpvHgMA4GA1UdDwEB
# /wQEAwIGwDAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMEoG
# A1UdIARDMEEwNQYMKwYBBAGyMQECAQMIMCUwIwYIKwYBBQUHAgEWF2h0dHBzOi8v
# c2VjdGlnby5jb20vQ1BTMAgGBmeBDAEEAjBEBgNVHR8EPTA7MDmgN6A1hjNodHRw
# Oi8vY3JsLnNlY3RpZ28uY29tL1NlY3RpZ29SU0FUaW1lU3RhbXBpbmdDQS5jcmww
# dAYIKwYBBQUHAQEEaDBmMD8GCCsGAQUFBzAChjNodHRwOi8vY3J0LnNlY3RpZ28u
# Y29tL1NlY3RpZ29SU0FUaW1lU3RhbXBpbmdDQS5jcnQwIwYIKwYBBQUHMAGGF2h0
# dHA6Ly9vY3NwLnNlY3RpZ28uY29tMA0GCSqGSIb3DQEBDAUAA4ICAQBz2u1ocsvC
# uUChMbu0A6MtFHsk57RbFX2o6f2t0ZINfD02oGnZ85ow2qxp1nRXJD9+DzzZ9cN5
# JWwm6I1ok87xd4k5f6gEBdo0wxTqnwhUq//EfpZsK9OU67Rs4EVNLLL3OztatcH7
# 14l1bZhycvb3Byjz07LQ6xm+FSx4781FoADk+AR2u1fFkL53VJB0ngtPTcSqE4+X
# rwE1K8ubEXjp8vmJBDxO44ISYuu0RAx1QcIPNLiIncgi8RNq2xgvbnitxAW06IQI
# kwf5fYP+aJg05Hflsc6MlGzbA20oBUd+my7wZPvbpAMxEHwa+zwZgNELcLlVX0e+
# OWTOt9ojVDLjRrIy2NIphskVXYCVrwL7tNEunTh8NeAPHO0bR0icImpVgtnyughl
# A+XxKfNIigkBTKZ58qK2GpmU65co4b59G6F87VaApvQiM5DkhFP8KvrAp5eo6rWN
# es7k4EuhM6sLdqDVaRa3jma/X/ofxKh/p6FIFJENgvy9TZntyeZsNv53Q5m4aS18
# YS/to7BJ/lu+aSSR/5P8V2mSS9kFP22GctOi0MBk0jpCwRoD+9DtmiG4P6+mslFU
# 1UzFyh8SjVfGOe1c/+yfJnatZGZn6Kow4NKtt32xakEnbgOKo3TgigmCbr/j9re8
# ngspGGiBoZw/bhZZSxQJCZrmrr9gFd2G9TGCBjEwggYtAgEBMGgwVDELMAkGA1UE
# BhMCR0IxGDAWBgNVBAoTD1NlY3RpZ28gTGltaXRlZDErMCkGA1UEAxMiU2VjdGln
# byBQdWJsaWMgQ29kZSBTaWduaW5nIENBIFIzNgIQEeGghmSHroJggo0o8FF6xjAN
# BglghkgBZQMEAgEFAKBMMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMC8GCSqG
# SIb3DQEJBDEiBCB4Qth3UpKBax4tMR/c4HogdnfdFHtHd/XgwwCr62r97DANBgkq
# hkiG9w0BAQEFAASCAgBrONcZDkWueLPoTcvWS57zFFa1KymLn+NiJ6V9uRceOzPW
# VipBeMxOl6Y35Fa75xrA192EcMHX+xsiU6GTYzE1c11d4i3RZgkCBC9s8fWgsu1m
# H3Wce9fjOV6UXp+wOgwdP89U8qyuheHYTVbW5GW7+Uf7V4lcL7oq9FqcV8zGcUt6
# 6GqHu5A/Dd5EKRCgKKFiwZ6ll9556GA5jeVnCzTwQ6FnurlhbEp9iaf8VY0ul0l3
# iJh8FJ2DO3ARB2vnSlzUF7tZpoNYbEG3rY1KmYtREXsQtLqEXV1BGkkLutdjMf5x
# MSO9VeCUXL7kdP72TcFQ0FAmlzRer1N4SxVJjkX7Hq8gz9tH/W22aI25nEaNQq2H
# w2w9r4zNGHf+poHeGg413wT/naS4ZMPqe5IjtLzH4OyH76XI9qzvwepsieGj/rfV
# g53ZevhlFKpOu+8xNCI+3Fw6PPZQ/V0g20bqCtOEOyh3hoTDiLYdXXJVSIPDbWRy
# F7dMjOBEfEdT6T5htV1rzPxx0n3XQSKFXYzqGx6sBBzpEx0AwkJrDxNLn7CBWOLL
# 92tNxWN70KljVPD4/v0xkAUI+QcAnPEBo8xdX1bMfhKX5bySiJnjmHzHfF4ZMhi8
# Tcuo21tumBMTISdaPsn/hLer3m6hmFaPqIyZu36vIE4OUKx26yCLrVmzaOIBnKGC
# A0wwggNIBgkqhkiG9w0BCQYxggM5MIIDNQIBATCBkjB9MQswCQYDVQQGEwJHQjEb
# MBkGA1UECBMSR3JlYXRlciBNYW5jaGVzdGVyMRAwDgYDVQQHEwdTYWxmb3JkMRgw
# FgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQxJTAjBgNVBAMTHFNlY3RpZ28gUlNBIFRp
# bWUgU3RhbXBpbmcgQ0ECEQCQOX+a0ko6E/K9kV8IOKlDMA0GCWCGSAFlAwQCAgUA
# oHkwGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjMw
# MzA5MjAwMzI2WjA/BgkqhkiG9w0BCQQxMgQwXy719z+qtpFRaXYHrh7EY3Udj1ye
# Au8MhFoTFPAkbpSJLGlAaYvSN+f6ehHH6BCfMA0GCSqGSIb3DQEBAQUABIICAGvb
# 8DZ0IcyG6f/ydLf6aYFluvRrN7ucdM0M4kLZYiLe2wQBzcgWGGdlOqBPOEqtQjqI
# Ny7FmaCy8bgao1KBh5t8X1b6OUMqNegBBsvE23W4BIA9ivC6PIKXi07ku4ChYBuq
# Iq32RDm8FHUTQyK7vko6MMBSXq/XhQYj7b5dsL4I5lo0ySOLV0MerrV/utespxjl
# 3QKqmPTkLk8B4cUgE40jGdLMpBMsZR4EEbJaAB/etvV8kz1Zd562O0DSFeOU/bgy
# WcBeUMpRLklYykQ0PU+hkVTgOIj1rJ3X7O40oo9rz1vvY+EIGmjbnnb4avqVbGbs
# JQwIxPD81Qz2oqXjkAJm4viqCGtkEJxSn2XvANQLZ/0Y1RBXHc4Z2C5tYH2RgVbi
# zQedlseqIN7nemTG+LRToGu4f/QQFGgJiUZsWEOkbv3oPrlqaRSIQvTW85rrE4a8
# 5T+yrCPoGbjavMFLChVNEBrc+YMuQwvw30JN1//Ay8tGRdlBl3qNHPDKdVuGWw9g
# vtNxj6rKk9K5Ea69UaA4ZRo+cVxoxZko6ZqdZNvQIqWU2ExtYlVoJlqx61s3Tz36
# jVwwz/fLG/vrwNP1aMsE5BXP7L9/vCd4kO7UWPolW9uCRQZ1wzn3K6JUE+12wSFh
# stbk8Cobue18UTmAu9IMvLvOSG2azT/hphNf8dSa
# SIG # End signature block
