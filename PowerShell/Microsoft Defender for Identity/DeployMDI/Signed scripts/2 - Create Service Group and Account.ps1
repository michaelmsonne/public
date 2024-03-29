﻿<#	
	.NOTES
	===========================================================================
	 Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2022 v5.8.213
	 Created on:   	18-01-2024 21:29
	 Created by:   	Michael Morten Sonne
	 Organization: 	Sonne´s Cloud
	 Filename:     	"2 - Create Service Group and Account.ps1"
	 Version:		1.0
	===========================================================================
	.DESCRIPTION
        This script will create a gMSA account and a group for the gMSA account to be a member of.

    .EXAMPLE
        .\"2 - Create Service Group and Account.ps1"
#>

# Please set the variables below to match your environment:
$gMSA_AccountName = 'gMSAMDI'
$gMSA_HostsGroupName = 'gMSAMDIGroup'
$gMSA_HostNames = 'ADDC01', 'ADDC02', 'ADCS', 'ADFS01', 'ADFS02'

# Alternatively, you may opt to utilize the built-in 'Domain Controllers' group if the environment consists of a single forest and exclusively features domain controller sensors (although this is not recommended)

# Import the required PowerShell module for Active Directory
Import-Module ActiveDirectory

# Create the group for the gMSA account to be a member of (if it does not already exist):
try {
    # Create the group
    New-ADGroup -Name $gMSA_HostsGroupName -GroupScope Global -PassThru -ErrorAction Stop

    # Show a confirmation that the group has been created
    Write-Host "Group '$gMSA_HostsGroupName' created." -ForegroundColor Green
} catch {
    # Show an error if the group could not be created
    Write-Host "Error creating group: $_" -ForegroundColor Red
}

# Add the members to it:
try {
    $gMSA_HostNames | ForEach-Object {
        $computer = Get-ADComputer -Identity $_ -ErrorAction Stop
        try {
            Add-ADGroupMember -Identity $gMSA_HostsGroupName -Members $computer -ErrorAction Stop
        } catch {
            Write-Host "Error adding member to group: $_" -ForegroundColor Red
        }
    }
    # Show a confirmation that the members have been added to the group
    Write-Host "Member(s) added to group '$gMSA_HostsGroupName'." -ForegroundColor Green
} catch {
    # Show an error if the members could not be added to the group
    Write-Host "Error when add member(s) to the group: $_" -ForegroundColor Red
}

# if ad kds key not exists in AD, create it
if (-not (Get-ADObject -Filter {objectclass -eq 'msDS-KeyCredentialLink'} -SearchBase (Get-ADRootDSE).configurationNamingContext -ErrorAction SilentlyContinue)) {
    # Create the KDS root key
    Add-KdsRootKey -EffectiveTime ((get-date).addhours(-10))
}
  
# Create the gMSA account for MDI:
Write-Host "Creating gMSA account '$gMSA_AccountName'..." -ForegroundColor Yellow
try {
    # Create the gMSA account
    New-ADServiceAccount -Name $gMSA_AccountName -DNSHostName "$gMSA_AccountName.$env:USERDNSDOMAIN" -Description "Microsoft Defender for Identity service account" -KerberosEncryptionType AES256 -ManagedPasswordIntervalInDays 30 -PrincipalsAllowedToRetrieveManagedPassword $gMSA_HostsGroupName -ErrorAction Stop

    # Show a confirmation that the gMSA account has been created
    Write-Host "gMSA account '$gMSA_AccountName' created." -ForegroundColor Green
} catch {
    Write-Host "Error creating gMSA service account: $_" -ForegroundColor Red
}

# Show a warning that the gMSA account password needs to be changed
Write-Host "gMSA account password needs to be changed. Changing it now..." -ForegroundColor Yellow

# Change the gMSA account password
try {
    Set-ADServiceAccount -Identity $gMSA_AccountName -Reset -Credential (Get-Credential) -ErrorAction Stop

    # Show a confirmation that the gMSA account password has been changed
    Write-Host "gMSA account password changed." -ForegroundColor Green
} catch {
    # Show an error if the gMSA account password could not be changed
    Write-Host "Error changing service account password: $_" -ForegroundColor Red
}

# Show a warning that the gMSA account needs to be validated
Write-Host "gMSA account needs to be validated. Validating it now..." -ForegroundColor Yellow

# Validate the gMSA account
try {
    Test-ADServiceAccount -Identity $gMSA_AccountName -ErrorAction Stop

    # Show a confirmation that the gMSA account has been validated
    Write-Host "gMSA account validated." -ForegroundColor Green
} catch {
    # Show an error if the gMSA account could not be validated
    Write-Host "Error validating service account: $_" -ForegroundColor Red
}

# Show a warning that the gMSA account needs to be installed on the hosts
Write-Host "gMSA account needs to be installed on the hosts. Installing it now..." -ForegroundColor Yellow

# Install the gMSA account on the hosts
try {
    Install-ADServiceAccount -Identity $gMSA_AccountName -ErrorAction Stop

    # Show a confirmation that the gMSA account has been installed on the host
    Write-Host "gMSA account installed on the host." -ForegroundColor Green
} catch {
    # Show an error if the gMSA account could not be installed on the host
    Write-Host "Error installing service account on the host: $_" -ForegroundColor Red
}

# Script completed
Write-host "Script completed."
# SIG # Begin signature block
# MIIo7AYJKoZIhvcNAQcCoIIo3TCCKNkCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCD0fYSS1/F3u189
# 3RBp4LCEiDj6cOyvXS5lQ6ZKhZt9baCCEd8wggVvMIIEV6ADAgECAhBI/JO0YFWU
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
# gf9SsIAod1Dx9THs2qkXIwyf5lTJBvPHLRqxs/k+Mn70AUiyj50/JYMxghZjMIIW
# XwIBATBoMFQxCzAJBgNVBAYTAkdCMRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQx
# KzApBgNVBAMTIlNlY3RpZ28gUHVibGljIENvZGUgU2lnbmluZyBDQSBSMzYCEBHh
# oIZkh66CYIKNKPBResYwDQYJYIZIAWUDBAIBBQCgfDAQBgorBgEEAYI3AgEMMQIw
# ADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYK
# KwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgQhHL7SPCu9wKEJMKugWScOSWMssl
# DhXfqJQenGnss4EwDQYJKoZIhvcNAQEBBQAEggIAHsj2dPFekZU9kF43J17j7Ajl
# 87DPOt7z+EIkfQr5p5ZFx6vQpVEFQZOaVJ2xsIHNNShEdX13XbnKU6HJJjzSwZjC
# dNsUZeNmslY58EhBsBqPPSop+oZzjFYd7RFSeqGyYPxj5Vcr6n0RvcviZ2plrSDM
# Rxb+C71lkLKLi3rv+KaBchw17aqWw0ybvBiTjUevenvDlxbheA6r38FAhr9wFL6/
# CZY1kC/Kpw2Ega9plEgu5TCzYGfz5ExzeyHo3+/ZupN7/vP8Nf4Kq4uRUjo6c2pB
# EQYKeNGuol7krKIjfrif+MQ6qeHjcMfAjr9AmEpkiRNfsb6l250Db/NPBEpD9aZb
# peAVpMCxdmNFNZ4HnH/UZKtUrtlHpNI0j88pAi7NySt7cpEai9SLdT2l7ZGgqlqN
# 2XvykIYa0CWBxUsawcSMJ/0HohOvAL9+o8FFCVImdp3X3BRsHyY9MkaKfBsHMtnt
# DPPUke0xfgGX444bBYnhO1mJ5cUG93IboIptIJMMEZDba/DxRKirybcAbi75FA9j
# NaRLQfrwK4qN8FngqdQxOdkFQFQilhBplTMegXafQHXdzNMUUdi+viUkD0nJETWd
# w39U2qNLBz2xHlToWsVg/ZpnOXveEwcEi1+iFqD1rulMHYkSEihkwS+U1JgMWxBL
# x44SNRjuoF3Q3STo7TehghNOMIITSgYKKwYBBAGCNwMDATGCEzowghM2BgkqhkiG
# 9w0BBwKgghMnMIITIwIBAzEPMA0GCWCGSAFlAwQCAgUAMIHvBgsqhkiG9w0BCRAB
# BKCB3wSB3DCB2QIBAQYKKwYBBAGyMQIBATAxMA0GCWCGSAFlAwQCAQUABCDBkEOc
# XxXWhhOkSkSxk0glnYF6+2NQntgg+xd997oB4wIUOxWh2z24rs0LQdW+SmEZipaK
# iL0YDzIwMjQwMTIwMTExMDE5WqBupGwwajELMAkGA1UEBhMCR0IxEzARBgNVBAgT
# Ck1hbmNoZXN0ZXIxGDAWBgNVBAoTD1NlY3RpZ28gTGltaXRlZDEsMCoGA1UEAwwj
# U2VjdGlnbyBSU0EgVGltZSBTdGFtcGluZyBTaWduZXIgIzSggg3pMIIG9TCCBN2g
# AwIBAgIQOUwl4XygbSeoZeI72R0i1DANBgkqhkiG9w0BAQwFADB9MQswCQYDVQQG
# EwJHQjEbMBkGA1UECBMSR3JlYXRlciBNYW5jaGVzdGVyMRAwDgYDVQQHEwdTYWxm
# b3JkMRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQxJTAjBgNVBAMTHFNlY3RpZ28g
# UlNBIFRpbWUgU3RhbXBpbmcgQ0EwHhcNMjMwNTAzMDAwMDAwWhcNMzQwODAyMjM1
# OTU5WjBqMQswCQYDVQQGEwJHQjETMBEGA1UECBMKTWFuY2hlc3RlcjEYMBYGA1UE
# ChMPU2VjdGlnbyBMaW1pdGVkMSwwKgYDVQQDDCNTZWN0aWdvIFJTQSBUaW1lIFN0
# YW1waW5nIFNpZ25lciAjNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB
# AKSTKFJLzyeHdqQpHJk4wOcO1NEc7GjLAWTkis13sHFlgryf/Iu7u5WY+yURjlqI
# CWYRFFiyuiJb5vYy8V0twHqiDuDgVmTtoeWBIHIgZEFsx8MI+vN9Xe8hmsJ+1yzD
# uhGYHvzTIAhCs1+/f4hYMqsws9iMepZKGRNcrPznq+kcFi6wsDiVSs+FUKtnAyWh
# uzjpD2+pWpqRKBM1uR/zPeEkyGuxmegN77tN5T2MVAOR0Pwtz1UzOHoJHAfRIuBj
# hqe+/dKDcxIUm5pMCUa9NLzhS1B7cuBb/Rm7HzxqGXtuuy1EKr48TMysigSTxleG
# oHM2K4GX+hubfoiH2FJ5if5udzfXu1Cf+hglTxPyXnypsSBaKaujQod34PRMAkjd
# WKVTpqOg7RmWZRUpxe0zMCXmloOBmvZgZpBYB4DNQnWs+7SR0MXdAUBqtqgQ7vaN
# ereeda/TpUsYoQyfV7BeJUeRdM11EtGcb+ReDZvsdSbu/tP1ki9ShejaRFEqoswA
# yodmQ6MbAO+itZadYq0nC/IbSsnDlEI3iCCEqIeuw7ojcnv4VO/4ayewhfWnQ4XY
# Kzl021p3AtGk+vXNnD3MH65R0Hts2B0tEUJTcXTC5TWqLVIS2SXP8NPQkUMS1zJ9
# mGzjd0HI/x8kVO9urcY+VXvxXIc6ZPFgSwVP77kv7AkTAgMBAAGjggGCMIIBfjAf
# BgNVHSMEGDAWgBQaofhhGSAPw0F3RSiO0TVfBhIEVTAdBgNVHQ4EFgQUAw8xyJEq
# k71j89FdTaQ0D9KVARgwDgYDVR0PAQH/BAQDAgbAMAwGA1UdEwEB/wQCMAAwFgYD
# VR0lAQH/BAwwCgYIKwYBBQUHAwgwSgYDVR0gBEMwQTA1BgwrBgEEAbIxAQIBAwgw
# JTAjBggrBgEFBQcCARYXaHR0cHM6Ly9zZWN0aWdvLmNvbS9DUFMwCAYGZ4EMAQQC
# MEQGA1UdHwQ9MDswOaA3oDWGM2h0dHA6Ly9jcmwuc2VjdGlnby5jb20vU2VjdGln
# b1JTQVRpbWVTdGFtcGluZ0NBLmNybDB0BggrBgEFBQcBAQRoMGYwPwYIKwYBBQUH
# MAKGM2h0dHA6Ly9jcnQuc2VjdGlnby5jb20vU2VjdGlnb1JTQVRpbWVTdGFtcGlu
# Z0NBLmNydDAjBggrBgEFBQcwAYYXaHR0cDovL29jc3Auc2VjdGlnby5jb20wDQYJ
# KoZIhvcNAQEMBQADggIBAEybZVj64HnP7xXDMm3eM5Hrd1ji673LSjx13n6UbcMi
# xwSV32VpYRMM9gye9YkgXsGHxwMkysel8Cbf+PgxZQ3g621RV6aMhFIIRhwqwt7y
# 2opF87739i7Efu347Wi/elZI6WHlmjl3vL66kWSIdf9dhRY0J9Ipy//tLdr/vpMM
# 7G2iDczD8W69IZEaIwBSrZfUYngqhHmo1z2sIY9wwyR5OpfxDaOjW1PYqwC6WPs1
# gE9fKHFsGV7Cg3KQruDG2PKZ++q0kmV8B3w1RB2tWBhrYvvebMQKqWzTIUZw3C+N
# dUwjwkHQepY7w0vdzZImdHZcN6CaJJ5OX07Tjw/lE09ZRGVLQ2TPSPhnZ7lNv8wN
# sTow0KE9SK16ZeTs3+AB8LMqSjmswaT5qX010DJAoLEZKhghssh9BXEaSyc2quCY
# HIN158d+S4RDzUP7kJd2KhKsQMFwW5kKQPqAbZRhe8huuchnZyRcUI0BIN4H9wHU
# +C4RzZ2D5fjKJRxEPSflsIZHKgsbhHZ9e2hPjbf3E7TtoC3ucw/ZELqdmSx813Uf
# jxDElOZ+JOWVSoiMJ9aFZh35rmR2kehI/shVCu0pwx/eOKbAFPsyPfipg2I2yMO+
# AIccq/pKQhyJA9z1XHxw2V14Tu6fXiDmCWp8KwijSPUV/ARP380hHHrl9Y4a1LlA
# MIIG7DCCBNSgAwIBAgIQMA9vrN1mmHR8qUY2p3gtuTANBgkqhkiG9w0BAQwFADCB
# iDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCk5ldyBKZXJzZXkxFDASBgNVBAcTC0pl
# cnNleSBDaXR5MR4wHAYDVQQKExVUaGUgVVNFUlRSVVNUIE5ldHdvcmsxLjAsBgNV
# BAMTJVVTRVJUcnVzdCBSU0EgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMTkw
# NTAyMDAwMDAwWhcNMzgwMTE4MjM1OTU5WjB9MQswCQYDVQQGEwJHQjEbMBkGA1UE
# CBMSR3JlYXRlciBNYW5jaGVzdGVyMRAwDgYDVQQHEwdTYWxmb3JkMRgwFgYDVQQK
# Ew9TZWN0aWdvIExpbWl0ZWQxJTAjBgNVBAMTHFNlY3RpZ28gUlNBIFRpbWUgU3Rh
# bXBpbmcgQ0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDIGwGv2Sx+
# iJl9AZg/IJC9nIAhVJO5z6A+U++zWsB21hoEpc5Hg7XrxMxJNMvzRWW5+adkFiYJ
# +9UyUnkuyWPCE5u2hj8BBZJmbyGr1XEQeYf0RirNxFrJ29ddSU1yVg/cyeNTmDoq
# HvzOWEnTv/M5u7mkI0Ks0BXDf56iXNc48RaycNOjxN+zxXKsLgp3/A2UUrf8H5Vz
# JD0BKLwPDU+zkQGObp0ndVXRFzs0IXuXAZSvf4DP0REKV4TJf1bgvUacgr6Unb+0
# ILBgfrhN9Q0/29DqhYyKVnHRLZRMyIw80xSinL0m/9NTIMdgaZtYClT0Bef9Maz5
# yIUXx7gpGaQpL0bj3duRX58/Nj4OMGcrRrc1r5a+2kxgzKi7nw0U1BjEMJh0giHP
# Yla1IXMSHv2qyghYh3ekFesZVf/QOVQtJu5FGjpvzdeE8NfwKMVPZIMC1Pvi3vG8
# Aij0bdonigbSlofe6GsO8Ft96XZpkyAcSpcsdxkrk5WYnJee647BeFbGRCXfBhKa
# Bi2fA179g6JTZ8qx+o2hZMmIklnLqEbAyfKm/31X2xJ2+opBJNQb/HKlFKLUrUMc
# pEmLQTkUAx4p+hulIq6lw02C0I3aa7fb9xhAV3PwcaP7Sn1FNsH3jYL6uckNU4B9
# +rY5WDLvbxhQiddPnTO9GrWdod6VQXqngwIDAQABo4IBWjCCAVYwHwYDVR0jBBgw
# FoAUU3m/WqorSs9UgOHYm8Cd8rIDZsswHQYDVR0OBBYEFBqh+GEZIA/DQXdFKI7R
# NV8GEgRVMA4GA1UdDwEB/wQEAwIBhjASBgNVHRMBAf8ECDAGAQH/AgEAMBMGA1Ud
# JQQMMAoGCCsGAQUFBwMIMBEGA1UdIAQKMAgwBgYEVR0gADBQBgNVHR8ESTBHMEWg
# Q6BBhj9odHRwOi8vY3JsLnVzZXJ0cnVzdC5jb20vVVNFUlRydXN0UlNBQ2VydGlm
# aWNhdGlvbkF1dGhvcml0eS5jcmwwdgYIKwYBBQUHAQEEajBoMD8GCCsGAQUFBzAC
# hjNodHRwOi8vY3J0LnVzZXJ0cnVzdC5jb20vVVNFUlRydXN0UlNBQWRkVHJ1c3RD
# QS5jcnQwJQYIKwYBBQUHMAGGGWh0dHA6Ly9vY3NwLnVzZXJ0cnVzdC5jb20wDQYJ
# KoZIhvcNAQEMBQADggIBAG1UgaUzXRbhtVOBkXXfA3oyCy0lhBGysNsqfSoF9bw7
# J/RaoLlJWZApbGHLtVDb4n35nwDvQMOt0+LkVvlYQc/xQuUQff+wdB+PxlwJ+TNe
# 6qAcJlhc87QRD9XVw+K81Vh4v0h24URnbY+wQxAPjeT5OGK/EwHFhaNMxcyyUzCV
# pNb0llYIuM1cfwGWvnJSajtCN3wWeDmTk5SbsdyybUFtZ83Jb5A9f0VywRsj1sJV
# hGbks8VmBvbz1kteraMrQoohkv6ob1olcGKBc2NeoLvY3NdK0z2vgwY4Eh0khy3k
# /ALWPncEvAQ2ted3y5wujSMYuaPCRx3wXdahc1cFaJqnyTdlHb7qvNhCg0MFpYum
# Cf/RoZSmTqo9CfUFbLfSZFrYKiLCS53xOV5M3kg9mzSWmglfjv33sVKRzj+J9hyh
# tal1H3G/W0NdZT1QgW6r8NDT/LKzH7aZlib0PHmLXGTMze4nmuWgwAxyh8FuTVrT
# HurwROYybxzrF06Uw3hlIDsPQaof6aFBnf6xuKBlKjTg3qj5PObBMLvAoGMs/FwW
# AKjQxH/qEZ0eBsambTJdtDgJK0kHqv3sMNrxpy/Pt/360KOE2See+wFmd7lWEOEg
# bsausfm2usg1XTN2jvF8IAwqd661ogKGuinutFoAsYyr4/kKyVRd1LlqdJ69SK6Y
# MYIELDCCBCgCAQEwgZEwfTELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIg
# TWFuY2hlc3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEYMBYGA1UEChMPU2VjdGlnbyBM
# aW1pdGVkMSUwIwYDVQQDExxTZWN0aWdvIFJTQSBUaW1lIFN0YW1waW5nIENBAhA5
# TCXhfKBtJ6hl4jvZHSLUMA0GCWCGSAFlAwQCAgUAoIIBazAaBgkqhkiG9w0BCQMx
# DQYLKoZIhvcNAQkQAQQwHAYJKoZIhvcNAQkFMQ8XDTI0MDEyMDExMTAxOVowPwYJ
# KoZIhvcNAQkEMTIEMGIIJgyX8GvO9mFiM31LenD7lav04KTyBdyJ7Tfe5fXnVStz
# ko3nl+vwXqnxhL9SKDCB7QYLKoZIhvcNAQkQAgwxgd0wgdowgdcwFgQUrmKvdQoM
# vUfWRh91aOK8jOfKT5QwgbwEFALWW5Xig3DBVwCV+oj5I92Tf62PMIGjMIGOpIGL
# MIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMKTmV3IEplcnNleTEUMBIGA1UEBxML
# SmVyc2V5IENpdHkxHjAcBgNVBAoTFVRoZSBVU0VSVFJVU1QgTmV0d29yazEuMCwG
# A1UEAxMlVVNFUlRydXN0IFJTQSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eQIQMA9v
# rN1mmHR8qUY2p3gtuTANBgkqhkiG9w0BAQEFAASCAgAML714EJjMiLZ3/U5vhNM1
# FjDED5+LzTlotpM596i2UW9yKb4DhtDwvx/TPhkU7APj4b2NozBiaE1CL/dLWCtO
# p+QAmu24Pfel2bxKQv6S4smMrekzRIRYTtugsDDIXpiKgggdAAndLHJU9cj6fHMs
# XJx08XLClbYKDypBOLLZRLQUczgiK5RDIpdXpMZS3P2/+MRIAXrotgYxAJ6qoltz
# hy+8Z6Tn4F6b9/D9paznkDK+W5NXb+62Clg/Ku/lX5gA3ooavAZYoAsXPMYl0/l6
# aNustC0o82Ch7ie4viWhdeqZgN2xx+A7VBsPSIR3GkgUZIhblca9o3R6KoBXrkp5
# +AAucgIM4P8UVLV7rpL3XPvIRQcW8aKEHOeDGJkrll6LwGuTXzCts22zmEsswbti
# Bq/N3l8cvgK+OKHlHccWHSe2E7J+cymwanjs2w3wl389bbCQchuRElJmk0p6jFbY
# rAV9+FTgyUWtcIwxjfpaBgA9wMB8oqS/4sBUO3D1x82wX1M8CDVk2D79otDW4yz9
# l1/oBgBfA0yS93rOUcsFKF2kCII3hSJ0nygpnqK0d5lWROrjYmBPEPHe6/vQxZRd
# 36GaMQdO9fdIOxv7ntJjKdSxSmB8NztE30D1sEmadXKxm4CgB6Nv42BpoBVRb+mq
# NfVXGfCLSOQbgdo2Iljpeg==
# SIG # End signature block
