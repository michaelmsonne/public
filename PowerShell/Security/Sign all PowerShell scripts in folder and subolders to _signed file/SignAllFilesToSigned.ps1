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
    [string]$Hash,
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