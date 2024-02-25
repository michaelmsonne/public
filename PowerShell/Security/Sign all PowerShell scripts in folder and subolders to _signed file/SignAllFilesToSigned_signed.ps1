<#
    .NOTES
    ===========================================================================
     Created on:    17-04-2022 22:34
	 Updated on:    25-02-2024 14:39
     Created by:    Michael Morten Sonne
     Blog:          https://blog.sonnes.cloud
     Organization:  Sonne´s Cloud
	 Name:          SignAllFilesToSigned
     Filename:      SignAllFilesToSigned.ps1
    ===========================================================================
    .SYNOPSIS
        Sign all scripts of the folder and create an _signed.ps1 copy there is signed. We import the complete chain.
        This is to ensure that the original file is not changed and that the signed file is created in the same folder/place as the original file.

    .DESCRIPTION
        This script is used to sign all scripts of the folder and create an _signed.ps1 copy there is signed. We import the complete certificate chain.

    .PARAMETER Path
        The path to the folder where The scripts are located.

    .PARAMETER Hash
        The hash algorithm to use for signing The scripts. The default value is SHA256.

    .PARAMETER Thumbprint
        The thumbprint of the certificate to use for signing The scripts. The certificate must be located in the current user store.

    .PARAMETER TimestampServer
        The URL of the timestamp server to use for timestamping The scripts. The default value is http://timestamp.sectigo.com.

    .PARAMETER WhatIf
        Show what would happen if The script were to run. The default value is $false.

    .PARAMETER Force
        Remove all _signed.ps1 files in the specified directory and its subdirectories. The default value is $false.

    .EXAMPLE
        This example signs all scripts in the C:\Test directory and its subdirectories with a certificate with the specified thumbprint and hash algorithm.
        PS C:\> .\SignAllFilesToSigned.ps1 -Path "C:\Test" -Hash "SHA256" -Thumbprint "d6a630b8f65c473c19f8b694491130073fccdb32" -TimestampServer "http://timestamp.sectigo.com"

    .EXAMPLE
        This shows what would happen if The script were to run. The -WhatIf parameter is used to show what would happen if The script were to run (see command above)
        PS C:\> .\SignAllFilesToSigned.ps1 -Path "C:\Test" -Hash "SHA256" -Thumbprint "d6a630b8f65c473c19f8b694491130073fccdb32" -TimestampServer "http://timestamp.sectigo.com" -Whatif

    .NOTES
        We import the complete certificate chain and use a Timestamp Server
#>

Param (
    [Parameter(Mandatory=$true)]
    [string]$Path,
    [Parameter(Mandatory=$true)]
    [string]$Hash = "SHA256", # Default value set to SHA256
    [Parameter(Mandatory=$true)]
    [string]$Thumbprint,
    [string]$TimestampServer = "http://timestamp.sectigo.com",
    [switch]$WhatIf,
    [switch]$Force # TODO: Implement the Force parameter to overwrite existing signed files
)

# Initialize error count
$errorCount = 0
$successCount = 0
$skippedCount = 0

function Show-CertificateInformation {
    $separator = "=" * 80
    $header = @"
$separator
                            Certificate Information
$separator
"@
    Write-Host $header -ForegroundColor Green
    Write-Host "Certificate with thumbprint " -NoNewline
    Write-Host -ForegroundColor Yellow "'$Thumbprint'" -NoNewline
    Write-Host " is found in the current user store."
    Write-Host "Subject: " -NoNewline
    Write-Host -ForegroundColor Yellow "'$($certificate.Subject)'" -NoNewline
    Write-Host ", Issuer: " -NoNewline
    Write-Host -ForegroundColor Yellow "'$($certificate.Issuer)'" -NoNewline
    Write-Host ", Expiration Date: " -NoNewline
    Write-Host -ForegroundColor Yellow "'$($certificate.NotAfter)'"
    Write-Host $separator -ForegroundColor Green
    Write-Host ""
}

function Show-SigningOverview {
    $separator = "=" * 80
    $header = @"
$separator
                           Script Signing Overview
$separator
"@
    Write-Host $header -ForegroundColor Green
    Write-Host "Signing all scripts in the directory and its subdirectories with certificate " -NoNewline
    Write-Host -ForegroundColor Yellow "'$($certificate.Subject)'" -NoNewline
    Write-Host ", issued by: " -NoNewline
    Write-Host -ForegroundColor Yellow "'$($certificate.Issuer)'" -NoNewline
    Write-Host ", hash type: " -NoNewline
    Write-Host -ForegroundColor Yellow "'$Hash'" -NoNewline
    Write-Host ", and timestamp server: '$TimestampServer'."
    Write-Host $separator -ForegroundColor Green
    Write-Host ""
}

function Show-EndRedLine {
    $separator = "=" * 80
    $header = @"
$separator
"@
    Write-Host $header -ForegroundColor Red
    Write-Host ""
}

function Show-RemovedFileOverview {
    param (
        [string]$FilePath
    )

    if ($WhatIf) {
        Write-Host -ForegroundColor Red "WhatIf: " -NoNewline
        Write-Host "The file '" -NoNewline
        Write-Host -ForegroundColor Green $FilePath -NoNewline
        Write-Host "' would be removed." -NoNewline
    } else {
        Write-Host "Removed file: " -NoNewline  -ForegroundColor Red
        Write-Host "'$FilePath'" -ForegroundColor Yellow
    }
}

function Show-RemoveFileOverview {
    param (
        [string]$FilePath
    )

    $separator = "=" * 80
    $header = @"
$separator
                               File(s) removal
$separator
"@
    Write-Host $header -ForegroundColor Red
    Write-Host ""
}

# Main script logic starts here

try {
    # Get the code signing certificate from the current user store using the thumbprint
    $certificate = Get-ChildItem -Path Cert:\CurrentUser\My\$Thumbprint -CodeSigningCert -ErrorAction Stop | Select-Object -First 1
}
catch {
    # Handle the error when the certificate is not found
    Write-Host "Certificate with thumbprint $Thumbprint not found in the current user store."
    Exit
}

if ($certificate) {
    # Show output to console
    Show-CertificateInformation
}

# Check if the Path parameter is set
if (-not $Path) {
    Write-Host "Please provide a valid path using the -Path parameter."
    Exit
}

# Ensure that the provided path is a valid directory
if (-not (Test-Path -Path $Path -PathType Container)) {
    Write-Host "The specified path '$Path' is not a valid directory."
    Exit
}

# If -Force is set, delete all _signed.ps1 files in the specified directory and its subdirectories
# Check if -Force argument is set
if ($Force) {
    # Get all .ps1 files in the specified directory and its subdirectories
    $scriptFiles = Get-ChildItem -Path $Path -Recurse -Filter *.ps1

    # Filter out files with "_signed.ps1" and remove them
    $signedFiles = $scriptFiles | Where-Object { $_.Name -like '*_signed.ps1' }

    if ($signedFiles.Count -gt 0) {
        # Show removed file overview
        Show-RemoveFileOverview

        if ($WhatIf) {
            # If -WhatIf is set, simulate the removal
            $signedFiles | ForEach-Object {
                Show-RemovedFileOverview -FilePath $_.FullName
                Write-Host ""
            }
            Write-Host ""
            Write-Host "The scripts are not deleted yet, because the -WhatIf parameter is used." -ForegroundColor Red
        } else {
            # Remove the files
            $signedFiles | ForEach-Object {
                # Remove the file
                Remove-Item $_.FullName -Force

                # Show removed file overview to console
                Show-RemovedFileOverview -FilePath $_.FullName
            }
            Write-Host ""
            Write-Host "The scripts are being deleted because the -Force argument is specified." -ForegroundColor Red
        }

        Write-Host ""
        Show-EndRedLine

    } else {
        Write-Host "The -Force argument is specified, but no '_signed.ps1' files were found for removal." -ForegroundColor Yellow
        Write-Host ""
    }
} else {
    Write-Host "The -Force argument is required to remove '_signed.ps1' files. No files were removed." -ForegroundColor Yellow
    Write-Host ""
}

# If path exists, certificate exists, and hash is valid, then run The script
if ($Path -and $certificate -and $Hash -match "^(MD5|SHA1|SHA256)$") {
    # Show output to console
    Show-SigningOverview

    # Get all .ps1 files in the specified directory and its subdirectories
    $scriptFiles = Get-ChildItem -Path $Path -Recurse -Filter *.ps1

    # Loop through each script file and sign it
    foreach ($scriptFile in $scriptFiles) {
        $scriptPath = $scriptFile.FullName
        $signedPath = $scriptPath.Replace(".ps1", "_signed.ps1")

        $signature = Get-AuthenticodeSignature $scriptPath -ErrorAction SilentlyContinue

        if (!$signature -or $signature.Status -ne "Valid" -or $signature.SignerCertificate.Thumbprint -ne $certificate.Thumbprint) {
            if ($WhatIf) {
                # Show WhatIf output with original file name
                Write-Host -ForegroundColor Red "WhatIf: " -NoNewline
                Write-Host "The script '" -NoNewline
                Write-Host -ForegroundColor Green $scriptPath -NoNewline
                Write-Host "' would be signed with certificate: '" -NoNewline
                Write-Host -ForegroundColor Yellow "$($certificate.Subject)'" -NoNewline
                Write-Host ", issued by: " -NoNewline
                Write-Host -ForegroundColor Yellow "$($certificate.Issuer)'" -NoNewline
                Write-Host ", hash type: " -NoNewline
                Write-Host -ForegroundColor Yellow "'$Hash'" -NoNewline
                Write-Host ", and timestamp server: '$TimestampServer'. "
                Write-Host "A " -NoNewline
                Write-Host -ForegroundColor Green "'_signed'" -NoNewline
                Write-Host " file will be created for that in the same folder/place as the original file, so the original file is kept unsigned."
                Write-Host ""
            }
            else {
                # Do work
                if (Test-Path $signedPath) {
                    # Check the signature status
                    $signature = Get-AuthenticodeSignature -FilePath $signedPath
                    if ($signature -and $signature.Status -eq "Valid" -and $signature.SignerCertificate.Thumbprint -eq $certificate.Thumbprint) {
                        # Show output to console - valid and signed
                        Write-Host "The script '" -NoNewline
                        Write-Host -ForegroundColor Yellow $signedPath -NoNewline
                        Write-Host "' is already " -NoNewline
                        Write-Host -ForegroundColor Green "signed " -NoNewline
                        Write-Host "with a " -NoNewline
                        Write-Host -ForegroundColor Green "valid certificate and hash '$Hash'" -NoNewline
                        Write-Host ", so it is '" -NoNewline
                        Write-Host -ForegroundColor Green "skipped" -NoNewline
                        Write-Host "' for process!"
                        Write-Host -ForegroundColor Cyan "Original script: $scriptPath"
                        Write-Host ""

                        $skippedCount++
                    }
                    else {
                        # Show output to console - invalid signed
                        Write-Host "The script '" -NoNewline
                        Write-Host -ForegroundColor Yellow $signedPath -NoNewline
                        Write-Host "' has an " -NoNewline
                        Write-Host -ForegroundColor Red "invalid certificate or hash" -NoNewline
                        Write-Host ", signing it again with certificate " -NoNewline
                        Write-Host -ForegroundColor Yellow "'$($certificate.Subject)'" -NoNewline
                        Write-Host ", issued by: " -NoNewline
                        Write-Host -ForegroundColor Yellow "'$($certificate.Issuer)'" -NoNewline
                        Write-Host ", hash type: '$Hash', and timestamp server: '$TimestampServer'!"
                        Write-Host ""

                        # Sign The script again
                        Set-AuthenticodeSignature -FilePath $signedPath -Certificate $certificate -HashAlgorithm $Hash -TimestampServer http://timestamp.digicert.com  | Out-Null

                        # Check the signature status after signing
                        $newSignature = Get-AuthenticodeSignature -FilePath $signedPath
                        if ($newSignature.Status -eq "Valid") {
                            # Show output to console
                            Write-Host "The script '" -NoNewline
                            Write-Host -ForegroundColor Yellow $signedPath -NoNewline
                            Write-Host "' has been successfully " -NoNewline
                            Write-Host -ForegroundColor Green "re-signed" -NoNewline
                            Write-Host " with certificate " -NoNewline
                            Write-Host -ForegroundColor Yellow "'$($certificate.Subject)'" -NoNewline
                            Write-Host ", issued by: " -NoNewline
                            Write-Host -ForegroundColor Yellow "'$($certificate.Issuer)'" -NoNewline
                            Write-Host ", hash type: '$Hash', and timestamp server: '$TimestampServer'!."
                            Write-Host -ForegroundColor Cyan "Original script: $scriptPath"
                            Write-Host ""

                            $successCount++
                        }
                        else {
                            # Show output to console
                            Write-Host -ForegroundColor Red "Script $scriptPath could not be signed with a valid certificate and hash $Hash."
                            $errorCount++
                        }
                    }
                }
                else {
                    # Show output to console - copy to _signed file
                    Write-Host "Copying script '" -NoNewline
                    Write-Host -ForegroundColor Yellow $scriptPath -NoNewline
                    Write-Host "' to '" -NoNewline
                    Write-Host -ForegroundColor Yellow $signedPath -NoNewline
                    Write-Host "' and signing it with certificate " -NoNewline
                    Write-Host -ForegroundColor Yellow "'$($certificate.Subject)'" -NoNewline
                    Write-Host ", issued by: " -NoNewline
                    Write-Host -ForegroundColor Yellow "'$($certificate.Issuer)'" -NoNewline
                    Write-Host ", hash type: '$Hash', and timestamp server: '$TimestampServer'!"
                    Write-Host ""

                    # Copy to _signed file
                    Copy-Item $scriptPath $signedPath

                    # Sign The script
                    try {
                        Set-AuthenticodeSignature -FilePath $signedPath -Certificate $certificate -HashAlgorithm $Hash -TimestampServer $TimestampServer -WhatIf:$false | Out-Null
                    }
                    catch {
                        # Show output to console
                        Write-Error "The script $scriptPath could not be signed with a valid certificate and hash $Hash."
                        $errorCount++
                    }             

                    # Check the signature status
                    $newSignature = Get-AuthenticodeSignature -FilePath $signedPath
                    if ($newSignature.Status -eq "Valid") {
                        # Show output to console
                        Write-Host "The script '" -NoNewline
                        Write-Host -ForegroundColor Yellow $signedPath -NoNewline
                        Write-Host "' has been " -NoNewline
                        Write-Host -ForegroundColor Green "signed" -NoNewline
                        Write-Host " with certificate " -NoNewline
                        Write-Host -ForegroundColor Yellow "'$($certificate.Subject)'" -NoNewline
                        Write-Host ", issued by: " -NoNewline
                        Write-Host -ForegroundColor Yellow "'$($certificate.Issuer)'" -NoNewline
                        Write-Host ", hash type: '$Hash', and timestamp server: '$TimestampServer'!"
                        Write-Host -ForegroundColor Cyan "Original script: $scriptPath"
                        Write-Host ""

                        $successCount++
                    }
                    else {
                        # Show output to console
                        Write-Host -ForegroundColor Red "Script $scriptPath could not be signed with a valid certificate and hash $Hash."
                        $errorCount++
                    }
                }
            }
        }
    }
    if ($WhatIf)
    {
        Write-Host -ForegroundColor Red "The scripts are not signed yet, because the -WhatIf parameter is used."
        Write-Host ""
    }
    else {
        if ($errorCount -eq 0)
        {
            # Show output to console
            Write-Host "All scripts in the directory and its subdirectories have been signed using the specified certificate." -ForegroundColor Green
            Write-Host "Total scripts signed: $successCount" -ForegroundColor Yellow
            Write-Host "Total scripts skipped: $skippedCount" -ForegroundColor Yellow
            Write-Host ""
        }
        else {
            Write-Host "Some scripts in the directory and its subdirectories have been signed using the specified certificate." -ForegroundColor Yellow
            Write-Host "Total scripts signed: $successCount" -ForegroundColor Yellow
            Write-Host "Total scripts skipped: $skippedCount" -ForegroundColor Yellow
            Write-Host ""
        }        
    }
}
else
{
    # Show output to console
    Write-Error "Please provide a valid path, certificate, and hash using the -Path, -Thumbprint, and -Hash parameters."
    Exit
}
# SIG # Begin signature block
# MIIm2wYJKoZIhvcNAQcCoIImzDCCJsgCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA/30MBoYb2YYTF
# cqE6HoJqfSKIvPX+wNvnAoa/3Fo5PKCCH8gwggVvMIIEV6ADAgECAhBI/JO0YFWU
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
# BgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgKuA2
# G68+9aMtPl8jo/imHl92+De2nvlVlSD3DpvlTI4wDQYJKoZIhvcNAQEBBQAEggIA
# E+EWkL5zEHs+fYx9T0cAYxqND4+sqJ1hyMeo9A3yxmjYFZJqqm6WdMvQnnqKbeYG
# zi6AtdRLfr0n2BETJj7DBhpghwV9mDVMzA9q+cgrA6k+lQnoTKP5ugk4C110sk6r
# 2gAzh23PIT+RFtHQn2Bk6mr3wuTrjw/06H7WOtlRJ5fTpYfb1Gc1ceccYTf4epeX
# BEG5hsaJadTcBwOpJq+RXmCL2MGY5TGwKXnD/jW/bIkVguW3D5vodtSc45JG679O
# 6N9uXKq5siVpocCwsFxgj0SksVxeYoro/BgakFKqK7QHSw6L9Ae35Iig5Yw1X9W0
# 0UkNxBhqj7z0fN/4oniAmOhJj//6xdAkxfVl7rxbi8XOiEk7KXPXMUcSGoDPXshq
# zNpbhJs2rwYy9eTDRSrANlpOSgbWt5iCKp7rrKrnzy0XA6K8aWRIBEesHiIWAXJG
# ZqxLZYAXAuBjrswWRoLJKtIYeF72HW+qRuufqThA3E9E/6x6g9FuMjmWhUE34r6u
# id4QBMi6ithX0YH99CwqY3ODAEKUNoBfbDRrbrLWDje+h3Ce/6eLRMkCGdgnYTtE
# ar/+mC7aXQpoXY579B+D7Kj0J6yvWHXzC2r6GR58SfxWdMAd/EEpONTJO9aeyYiJ
# iBWSmjFSMf3pok2oho4vAGNTYH7wXmALXzuis67mqfqhggNLMIIDRwYJKoZIhvcN
# AQkGMYIDODCCAzQCAQEwgZEwfTELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0
# ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEYMBYGA1UEChMPU2VjdGln
# byBMaW1pdGVkMSUwIwYDVQQDExxTZWN0aWdvIFJTQSBUaW1lIFN0YW1waW5nIENB
# AhA5TCXhfKBtJ6hl4jvZHSLUMA0GCWCGSAFlAwQCAgUAoHkwGAYJKoZIhvcNAQkD
# MQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjQwMjI1MTcwMDEwWjA/Bgkq
# hkiG9w0BCQQxMgQwSIua9aARPb2/OBmycCqpYyOnw+kFO3UH7dlNQ7QfSx3vl9qW
# i0k2cLcadwh/ebIyMA0GCSqGSIb3DQEBAQUABIICADQADThYzjVKABZq5ka8keFD
# 5w8ZtLvos2ktL97/IbcH+1CX9TCBL0DGY0hC/9E07Rfi8oW8WeveoCCA80olXX9U
# Q1nkILZ+qjqlWghKGmHCTYyMPzJ2ISw3oiOw3egWe5obeTLb4QNZJYl6Cupq/Xmh
# xmXTE+EWYpZsWBv2sTHRuZZA5OtvTcq7PvXGoZTbX/g1HMF9x3FCr+lRCflV0Qz4
# MrMoa0ZovlFzXuT40xYbeedk/ro/Arr45pMs6zadHHjdSg18gEM2vjZ4GfVTFTJM
# yGAJ8pW2rXCBZyMgd5oBQJ+x5lDoDiQFNvyzhwx8TyW7oCbiBir+Ok5bGJCdzRZe
# 6+LaTlXRynXW9oYXkZlgOBpQb/u9h7DGD0JLvJvD5CtISjNTybj9+JzLOF3Eq8Gi
# Gelh6ngp/CenK8VyQIfgkbvCbRmyFsyimxY979BEtSKzSkSxReFCoq07LP+sQDfa
# QfiDm7l9HDOhcHNikayi1HER7WegTedHWgqHYhoyyufx+Pr0JcShIG8AU5WKdO34
# 3xturg8hChmbw+oTwigesSfkYCwsFt06y3r54f2vcMYLEUny8EdavNCiOSNNea0d
# LTKBuRM+nAq+C7PbE+fEWxUXed6mQoqphPhbXYtE19jI/AzjiTYXFvCintVOM0Bj
# FCmAJIjbpgKj/dBq5l/Y
# SIG # End signature block
