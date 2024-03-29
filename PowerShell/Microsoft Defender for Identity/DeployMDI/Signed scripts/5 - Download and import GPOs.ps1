﻿<#	
	.NOTES
	===========================================================================
	 Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2022 v5.8.213
	 Created on:   	19-01-2024 19:04
	 Created by:   	Michael Morten Sonne
	 Organization: 	Sonne´s Cloud
	 Filename:     	"5 - Download and import GPOs.ps1"
	 Version:		1.0
	===========================================================================
	.DESCRIPTION
        This script will download and extract the MDI GPOs.

    .EXAMPLE
        .\"5 - Download and import GPOs.ps1"
#>

# Function to create and import GPOs
function CreateAndImportGPO {
    param (
        [string]$GPOName,
        [string]$BackupId
    )

    try {
        $GPO = New-GPO -Name $GPOName

        try {
            Import-GPO -Path C:\Temp\MDI-GPOs -BackupId $BackupId -TargetGuid $GPO.Id -Domain $localdomain.Forest

            # Uncomment the following line to automatically link GPO to the Domain Controllers OU
            # New-GPLink -Name $GPO.DisplayName -Target "OU=Domain Controllers,DC=lab,DC=sonnes,DC=cloud"
            Write-Host "GPO '$GPOName' created and imported successfully." -ForegroundColor Green
        } catch {
            Write-Host "Error importing GPO '$GPOName': $_" -ForegroundColor Red
            # Handle the import error as needed
        }
    } catch {
        Write-Host "Error creating GPO '$GPOName': $_" -ForegroundColor Red
        # Handle the creation error as needed
    }
}

# Set the source URL and destination paths
$SourceUrl = "https://raw.githubusercontent.com/michaelmsonne/public/main/PowerShell/Microsoft%20Defender%20for%20Identity/DeployMDI/MDI-GPO-Import.zip"
$DestinationFolder = "C:\Temp"

# Download the file using BITS
try {
	Write-Host "Downloading the GPO file from $SourceUrl to $DestinationFolder..."
    Start-BitsTransfer -Source $SourceUrl -Destination $DestinationFolder -DisplayName "Downloading MDI-GPO-Import.zip"
    Write-Host "Download completed successfully." -ForegroundColor Green
} catch {
    Write-Host "Error downloading the file: $_" -ForegroundColor Red
    exit
}

# Extract MDI GPOs
try {
    $ZipFilePath = Join-Path -Path $DestinationFolder -ChildPath "MDI-GPO-Import.zip"
    $DestinationPath = Join-Path -Path $DestinationFolder -ChildPath "MDI-GPO"

	Write-Host "Extracting the contents of $ZipFilePath to $DestinationPath..." -ForegroundColor Yellow
    Expand-Archive -Path $ZipFilePath -DestinationPath $DestinationPath
    Write-Host "Extraction completed successfully." -ForegroundColor Green
} catch {
    Write-Host "Error extracting the contents: $_" -ForegroundColor Red
    exit
}

# Import the GPOs
Write-Host "Importing the GPOs..." -ForegroundColor Yellow

# Create GPOs for domain controllers
CreateAndImportGPO -GPOName "Microsoft Defender for Identity - Advanced Audit Policy for CAs" -BackupId "10C96B19-99E5-47FB-8D91-7A08255553B2"
CreateAndImportGPO -GPOName "Microsoft Defender for Identity - Advanced Audit Policy for DCs" -BackupId "E445CE28-CF1E-4FEB-945C-1AF76E2DF490"

# Create other GPOs (Modify as needed)
CreateAndImportGPO -GPOName "Microsoft Defender for Identity - Auditing for CAs" -BackupId "BD4C8B67-86A9-4AE1-8A56-DC7170E3A530"
CreateAndImportGPO -GPOName "Microsoft Defender for Identity - NTLM Auditing for DCs" -BackupId "E633D0F2-7726-4707-84E6-992BC2E1426F"
CreateAndImportGPO -GPOName "Microsoft Defender for Identity - Processor Performance" -BackupId "FEF8FAFF-A207-45FD-BB90-7530365A0062"

# Ask the user if they want to delete the file
$DeleteFile = Read-Host "Do you want to delete the file $ZipFilePath (downloaded GPO files)? (Enter 'Y' for Yes, 'N' for No)"

try {
    # Process user input
    if ($DeleteFile -eq 'Y' -or $DeleteFile -eq 'y') {
        # Delete the file
        Remove-Item -Path $ZipFilePath -Force

        # Show a confirmation that the file has been deleted
        Write-Host "File $ZipFilePath deleted successfully." -ForegroundColor Green
    } else {
        # Show a warning that the file was not deleted
        Write-Host "File deletion canceled. The file $ZipFilePath was not deleted." -ForegroundColor Red
    }
}
catch {
    # Show an error if the file could not be deleted
    Write-Host "An error occurred: $_" -ForegroundColor Red
}

# Script completed
Write-host "Script completed."
# SIG # Begin signature block
# MIIo7QYJKoZIhvcNAQcCoIIo3jCCKNoCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA2PFH9RMeKM7i9
# aPB/FTWYnbG2K59ivE1NeYIBCoH2mqCCEd8wggVvMIIEV6ADAgECAhBI/JO0YFWU
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
# gf9SsIAod1Dx9THs2qkXIwyf5lTJBvPHLRqxs/k+Mn70AUiyj50/JYMxghZkMIIW
# YAIBATBoMFQxCzAJBgNVBAYTAkdCMRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQx
# KzApBgNVBAMTIlNlY3RpZ28gUHVibGljIENvZGUgU2lnbmluZyBDQSBSMzYCEBHh
# oIZkh66CYIKNKPBResYwDQYJYIZIAWUDBAIBBQCgfDAQBgorBgEEAYI3AgEMMQIw
# ADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYK
# KwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgTk5zdt1XeBaDgQ+yjMsTqNh7CmQx
# Xxax9BQIwMJkvEowDQYJKoZIhvcNAQEBBQAEggIAtCfo56ps/UGZijQRxf4s571p
# aUB/LyiB+7QAsmzpwyHmKvs8Jj74r7Cgo36dubHeJVHJy4FxZjLBJaoGrqxqwZSl
# Y6N8oO/A3oii4fc/wiXMKVgjY5yq2+SSd3tyCkLtLIjKjKjGIfGG/akVLeCaE58v
# wWygbMGMQXqjy6X3zLQ2fMFjZYu6lU0ytMfro4CboWJ1FAqUzrBGfq+0PjpmcOku
# hCGTM8dfI/1xBgLcdX10BesNy4I8klNsaU159vMmbjUgNWWcy/1tGRMz8QnJLrHZ
# qYo3ZYNQClyoUa0GoSBjY4GzrfBsEBa7RRL9z0Y2FMunDbQtjZOVElCYZt+ocw5q
# TjzyZbuTEdunHL0RYKLQPTZc5NPj2ewmQFStANVex/zjOsP2YAdX+sLbPJfldaZg
# sD+uGC23yWDhFVOeJZ+TL+tnXWqqhm04vtB6wooO4H8M/13kE+QQFGP0wCynK2d3
# +FdpuMaARDfufLTzf+vFsF5BWR+8YPFhY2G5mGefdLtJTb1O/Pigs68m6grueWP9
# kcL/jd9PQJBQpJfnD/iPpXjL6xbWRhGHC1nWB1KAAc/kDaT7e7RRYeQcYrb3PfjD
# OgtxzSmuI8bqwrFUml/3c/RizEBLqSjI1OcErCDIlmgOA662mku8nQ6ihMX98QEH
# TlFWizQ4JWXJFbrpfS6hghNPMIITSwYKKwYBBAGCNwMDATGCEzswghM3BgkqhkiG
# 9w0BBwKgghMoMIITJAIBAzEPMA0GCWCGSAFlAwQCAgUAMIHwBgsqhkiG9w0BCRAB
# BKCB4ASB3TCB2gIBAQYKKwYBBAGyMQIBATAxMA0GCWCGSAFlAwQCAQUABCDzH/7f
# DbV7QzK0Q3y8Zp4SgCBeDnUYHY/+JKJUH0UHawIVAISuMt9vZFGXyZe9pBoeWbFq
# In0gGA8yMDI0MDEyMDExMTAxNlqgbqRsMGoxCzAJBgNVBAYTAkdCMRMwEQYDVQQI
# EwpNYW5jaGVzdGVyMRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQxLDAqBgNVBAMM
# I1NlY3RpZ28gUlNBIFRpbWUgU3RhbXBpbmcgU2lnbmVyICM0oIIN6TCCBvUwggTd
# oAMCAQICEDlMJeF8oG0nqGXiO9kdItQwDQYJKoZIhvcNAQEMBQAwfTELMAkGA1UE
# BhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBxMHU2Fs
# Zm9yZDEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMSUwIwYDVQQDExxTZWN0aWdv
# IFJTQSBUaW1lIFN0YW1waW5nIENBMB4XDTIzMDUwMzAwMDAwMFoXDTM0MDgwMjIz
# NTk1OVowajELMAkGA1UEBhMCR0IxEzARBgNVBAgTCk1hbmNoZXN0ZXIxGDAWBgNV
# BAoTD1NlY3RpZ28gTGltaXRlZDEsMCoGA1UEAwwjU2VjdGlnbyBSU0EgVGltZSBT
# dGFtcGluZyBTaWduZXIgIzQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoIC
# AQCkkyhSS88nh3akKRyZOMDnDtTRHOxoywFk5IrNd7BxZYK8n/yLu7uVmPslEY5a
# iAlmERRYsroiW+b2MvFdLcB6og7g4FZk7aHlgSByIGRBbMfDCPrzfV3vIZrCftcs
# w7oRmB780yAIQrNfv3+IWDKrMLPYjHqWShkTXKz856vpHBYusLA4lUrPhVCrZwMl
# obs46Q9vqVqakSgTNbkf8z3hJMhrsZnoDe+7TeU9jFQDkdD8Lc9VMzh6CRwH0SLg
# Y4anvv3Sg3MSFJuaTAlGvTS84UtQe3LgW/0Zux88ahl7brstRCq+PEzMrIoEk8ZX
# hqBzNiuBl/obm36Ih9hSeYn+bnc317tQn/oYJU8T8l58qbEgWimro0KHd+D0TAJI
# 3VilU6ajoO0ZlmUVKcXtMzAl5paDgZr2YGaQWAeAzUJ1rPu0kdDF3QFAaraoEO72
# jXq3nnWv06VLGKEMn1ewXiVHkXTNdRLRnG/kXg2b7HUm7v7T9ZIvUoXo2kRRKqLM
# AMqHZkOjGwDvorWWnWKtJwvyG0rJw5RCN4gghKiHrsO6I3J7+FTv+GsnsIX1p0OF
# 2Cs5dNtadwLRpPr1zZw9zB+uUdB7bNgdLRFCU3F0wuU1qi1SEtklz/DT0JFDEtcy
# fZhs43dByP8fJFTvbq3GPlV78VyHOmTxYEsFT++5L+wJEwIDAQABo4IBgjCCAX4w
# HwYDVR0jBBgwFoAUGqH4YRkgD8NBd0UojtE1XwYSBFUwHQYDVR0OBBYEFAMPMciR
# KpO9Y/PRXU2kNA/SlQEYMA4GA1UdDwEB/wQEAwIGwDAMBgNVHRMBAf8EAjAAMBYG
# A1UdJQEB/wQMMAoGCCsGAQUFBwMIMEoGA1UdIARDMEEwNQYMKwYBBAGyMQECAQMI
# MCUwIwYIKwYBBQUHAgEWF2h0dHBzOi8vc2VjdGlnby5jb20vQ1BTMAgGBmeBDAEE
# AjBEBgNVHR8EPTA7MDmgN6A1hjNodHRwOi8vY3JsLnNlY3RpZ28uY29tL1NlY3Rp
# Z29SU0FUaW1lU3RhbXBpbmdDQS5jcmwwdAYIKwYBBQUHAQEEaDBmMD8GCCsGAQUF
# BzAChjNodHRwOi8vY3J0LnNlY3RpZ28uY29tL1NlY3RpZ29SU0FUaW1lU3RhbXBp
# bmdDQS5jcnQwIwYIKwYBBQUHMAGGF2h0dHA6Ly9vY3NwLnNlY3RpZ28uY29tMA0G
# CSqGSIb3DQEBDAUAA4ICAQBMm2VY+uB5z+8VwzJt3jOR63dY4uu9y0o8dd5+lG3D
# IscEld9laWETDPYMnvWJIF7Bh8cDJMrHpfAm3/j4MWUN4OttUVemjIRSCEYcKsLe
# 8tqKRfO+9/YuxH7t+O1ov3pWSOlh5Zo5d7y+upFkiHX/XYUWNCfSKcv/7S3a/76T
# DOxtog3Mw/FuvSGRGiMAUq2X1GJ4KoR5qNc9rCGPcMMkeTqX8Q2jo1tT2KsAulj7
# NYBPXyhxbBlewoNykK7gxtjymfvqtJJlfAd8NUQdrVgYa2L73mzECqls0yFGcNwv
# jXVMI8JB0HqWO8NL3c2SJnR2XDegmiSeTl9O048P5RNPWURlS0Nkz0j4Z2e5Tb/M
# DbE6MNChPUitemXk7N/gAfCzKko5rMGk+al9NdAyQKCxGSoYIbLIfQVxGksnNqrg
# mByDdefHfkuEQ81D+5CXdioSrEDBcFuZCkD6gG2UYXvIbrnIZ2ckXFCNASDeB/cB
# 1PguEc2dg+X4yiUcRD0n5bCGRyoLG4R2fXtoT4239xO07aAt7nMP2RC6nZksfNd1
# H48QxJTmfiTllUqIjCfWhWYd+a5kdpHoSP7IVQrtKcMf3jimwBT7Mj34qYNiNsjD
# vgCHHKv6SkIciQPc9Vx8cNldeE7un14g5glqfCsIo0j1FfwET9/NIRx65fWOGtS5
# QDCCBuwwggTUoAMCAQICEDAPb6zdZph0fKlGNqd4LbkwDQYJKoZIhvcNAQEMBQAw
# gYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpOZXcgSmVyc2V5MRQwEgYDVQQHEwtK
# ZXJzZXkgQ2l0eTEeMBwGA1UEChMVVGhlIFVTRVJUUlVTVCBOZXR3b3JrMS4wLAYD
# VQQDEyVVU0VSVHJ1c3QgUlNBIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MB4XDTE5
# MDUwMjAwMDAwMFoXDTM4MDExODIzNTk1OVowfTELMAkGA1UEBhMCR0IxGzAZBgNV
# BAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEYMBYGA1UE
# ChMPU2VjdGlnbyBMaW1pdGVkMSUwIwYDVQQDExxTZWN0aWdvIFJTQSBUaW1lIFN0
# YW1waW5nIENBMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAyBsBr9ks
# foiZfQGYPyCQvZyAIVSTuc+gPlPvs1rAdtYaBKXOR4O168TMSTTL80VlufmnZBYm
# CfvVMlJ5LsljwhObtoY/AQWSZm8hq9VxEHmH9EYqzcRaydvXXUlNclYP3MnjU5g6
# Kh78zlhJ07/zObu5pCNCrNAVw3+eolzXOPEWsnDTo8Tfs8VyrC4Kd/wNlFK3/B+V
# cyQ9ASi8Dw1Ps5EBjm6dJ3VV0Rc7NCF7lwGUr3+Az9ERCleEyX9W4L1GnIK+lJ2/
# tCCwYH64TfUNP9vQ6oWMilZx0S2UTMiMPNMUopy9Jv/TUyDHYGmbWApU9AXn/TGs
# +ciFF8e4KRmkKS9G493bkV+fPzY+DjBnK0a3Na+WvtpMYMyou58NFNQYxDCYdIIh
# z2JWtSFzEh79qsoIWId3pBXrGVX/0DlULSbuRRo6b83XhPDX8CjFT2SDAtT74t7x
# vAIo9G3aJ4oG0paH3uhrDvBbfel2aZMgHEqXLHcZK5OVmJyXnuuOwXhWxkQl3wYS
# mgYtnwNe/YOiU2fKsfqNoWTJiJJZy6hGwMnypv99V9sSdvqKQSTUG/xypRSi1K1D
# HKRJi0E5FAMeKfobpSKupcNNgtCN2mu32/cYQFdz8HGj+0p9RTbB942C+rnJDVOA
# ffq2OVgy728YUInXT50zvRq1naHelUF6p4MCAwEAAaOCAVowggFWMB8GA1UdIwQY
# MBaAFFN5v1qqK0rPVIDh2JvAnfKyA2bLMB0GA1UdDgQWBBQaofhhGSAPw0F3RSiO
# 0TVfBhIEVTAOBgNVHQ8BAf8EBAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIBADATBgNV
# HSUEDDAKBggrBgEFBQcDCDARBgNVHSAECjAIMAYGBFUdIAAwUAYDVR0fBEkwRzBF
# oEOgQYY/aHR0cDovL2NybC51c2VydHJ1c3QuY29tL1VTRVJUcnVzdFJTQUNlcnRp
# ZmljYXRpb25BdXRob3JpdHkuY3JsMHYGCCsGAQUFBwEBBGowaDA/BggrBgEFBQcw
# AoYzaHR0cDovL2NydC51c2VydHJ1c3QuY29tL1VTRVJUcnVzdFJTQUFkZFRydXN0
# Q0EuY3J0MCUGCCsGAQUFBzABhhlodHRwOi8vb2NzcC51c2VydHJ1c3QuY29tMA0G
# CSqGSIb3DQEBDAUAA4ICAQBtVIGlM10W4bVTgZF13wN6MgstJYQRsrDbKn0qBfW8
# Oyf0WqC5SVmQKWxhy7VQ2+J9+Z8A70DDrdPi5Fb5WEHP8ULlEH3/sHQfj8ZcCfkz
# XuqgHCZYXPO0EQ/V1cPivNVYeL9IduFEZ22PsEMQD43k+ThivxMBxYWjTMXMslMw
# laTW9JZWCLjNXH8Blr5yUmo7Qjd8Fng5k5OUm7Hcsm1BbWfNyW+QPX9FcsEbI9bC
# VYRm5LPFZgb289ZLXq2jK0KKIZL+qG9aJXBigXNjXqC72NzXStM9r4MGOBIdJIct
# 5PwC1j53BLwENrXnd8ucLo0jGLmjwkcd8F3WoXNXBWiap8k3ZR2+6rzYQoNDBaWL
# pgn/0aGUpk6qPQn1BWy30mRa2Coiwkud8TleTN5IPZs0lpoJX47997FSkc4/ifYc
# obWpdR9xv1tDXWU9UIFuq/DQ0/yysx+2mZYm9Dx5i1xkzM3uJ5rloMAMcofBbk1a
# 0x7q8ETmMm8c6xdOlMN4ZSA7D0GqH+mhQZ3+sbigZSo04N6o+TzmwTC7wKBjLPxc
# FgCo0MR/6hGdHgbGpm0yXbQ4CStJB6r97DDa8acvz7f9+tCjhNknnvsBZne5VhDh
# IG7GrrH5trrINV0zdo7xfCAMKneutaIChrop7rRaALGMq+P5CslUXdS5anSevUiu
# mDGCBCwwggQoAgEBMIGRMH0xCzAJBgNVBAYTAkdCMRswGQYDVQQIExJHcmVhdGVy
# IE1hbmNoZXN0ZXIxEDAOBgNVBAcTB1NhbGZvcmQxGDAWBgNVBAoTD1NlY3RpZ28g
# TGltaXRlZDElMCMGA1UEAxMcU2VjdGlnbyBSU0EgVGltZSBTdGFtcGluZyBDQQIQ
# OUwl4XygbSeoZeI72R0i1DANBglghkgBZQMEAgIFAKCCAWswGgYJKoZIhvcNAQkD
# MQ0GCyqGSIb3DQEJEAEEMBwGCSqGSIb3DQEJBTEPFw0yNDAxMjAxMTEwMTZaMD8G
# CSqGSIb3DQEJBDEyBDAkSxM0pDNub3TTdp2xf8DMtpEwOpPbqJ+GMyKrqyDwSLsm
# r2R8c85cufo30b78N8wwge0GCyqGSIb3DQEJEAIMMYHdMIHaMIHXMBYEFK5ir3UK
# DL1H1kYfdWjivIznyk+UMIG8BBQC1luV4oNwwVcAlfqI+SPdk3+tjzCBozCBjqSB
# izCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCk5ldyBKZXJzZXkxFDASBgNVBAcT
# C0plcnNleSBDaXR5MR4wHAYDVQQKExVUaGUgVVNFUlRSVVNUIE5ldHdvcmsxLjAs
# BgNVBAMTJVVTRVJUcnVzdCBSU0EgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkCEDAP
# b6zdZph0fKlGNqd4LbkwDQYJKoZIhvcNAQEBBQAEggIAcWUFN5I0Hcey1wz3veGv
# jYULQdFwviGxgnGzvYDaDprpVXd3UFZsI7iojcQWsva4c4dQcPf1ugxFYe3b5itw
# 2gDF0jYO07bQDFI0NQiJHJE0pfmFXx0gi3BNasdNbdnsbUlFpMT1Zmf93NXtbTu4
# RRE7UcNFKkqSG3mOVCosbzsrIgADWk+o5NZjWIDSlSeJy9Gf8ip6ft/uSZQiD86u
# XYyvs5xnef1LP9+Xe+7YL7KBjM0KbB4vGVbHds03Oxv0IeooB1AytakqSVJi5DgY
# WSHEMhSR81UD4DlG4DaiFlFmPCWaijMtfocmlFpQrML9wKsKs4ZoY8xPKpmaGuGy
# WAhs+NuhWC33TOwLTuefNBNXCHF1D4m5xV03dRdtNdgCoA2I5HFxcwzSutmkNGXs
# KZQhgkRoFljKM+r7H27t1WDBgVU/Uey6jDRiw6X4/hZPdnvHhBozSizFEb2C5vzg
# 0Kzu+KFs18h6QA1ik+KKwIfstAqCBBG0Dah5gEDHniGGcPCGH3CCVXKBT8aYSoA/
# 8gePHNRqsKR34fiPD7H2Zt/Jw/+t0HmGjtXU3xcicXMBWWb8AHrF4oZIWpDaYtT0
# 6qfCMLzd4vKEiURxjgabOYFoL9Fb0Cn38sM7v53mKQMI9vRSlVdjq1p7oWiKfg48
# 5YmwNLeiTm3D0N2plhDzwvw=
# SIG # End signature block
