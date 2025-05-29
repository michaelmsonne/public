<#	
	.NOTES
	===========================================================================
	 Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2022 v5.8.213
	 Created on:   	26-04-2025 20:37
	 Created by:   	Michael Morten Sonne
	 Organization: 	Sonne´s Cloud
	 Blog:          https://blog.sonnes.cloud
	 Filename:     	EntraIDConnectCertManagement.ps1
	===========================================================================
	.DESCRIPTION
        This script manages certificate-based authentication for Entra ID Connect.
        It allows you to create and assign a certificate to the Entra ID Connect service account,
        register an application with the certificate, assign the certificate to Entra ID Connect,
        verify connector credentials, and rotate (rollover) the certificate.

    .REQUREMENT
        - Administrator rights on the machine

    .CHANGELOG
        28-05-2025 - Michael Morten Sonne - Initial release
        29-05-2025 - Michael Morten Sonne - Added error handling and improved user prompts

	.EXAMPLE
        Get the Value of a Setting: .\EntraIDConnectCertManagement.ps1
#>

function Show-Menu {
    Write-Host ""
    Write-Host "Entra ID Connect - Certificate-based Authentication Management" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "1. Create and assign certificate for service account"
    Write-Host "2. Register application with certificate"
    Write-Host "3. Assign certificate to Entra ID Connect"
    Write-Host "4. Verify connector credential"
    Write-Host "5. Rotate (rollover) certificate"
    Write-Host "6. Exit"
    Write-Host ""
}

function CreateAndAssignCertificate {
    Write-Host "Creating and assigning a certificate for the Entra ID Connect service account..." -ForegroundColor Yellow
    try {
        $dns = ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).Name
        Write-Host "Using current domain name found: $dns"
    } catch {
        Write-Host "Unable to automatically detect the domain name."
        $dns = Read-Host "Please enter the certificate DNS name (e.g., sub.domain.com)"
    }
    Write-Host "Generating a new self-signed certificate for: $dns"
    Write-Host "The certificate will be placed in the LocalMachine\My store and set as non-exportable for security."
    Write-Host "The certificate will be valid for 1 year and use SHA256 with a 2048-bit RSA key." -ForegroundColor Yellow
    
    $params = @{
        DnsName = $dns
        CertStoreLocation = "Cert:\LocalMachine\My"
        KeyAlgorithm = "RSA"
        KeyLength = 2048
        HashAlgorithm = "SHA256"
        NotAfter = (Get-Date).AddYears(1)
        KeyExportPolicy = "NonExportable"
    }
    $cert = New-SelfSignedCertificate @params

    if ($null -eq $cert) {
        Write-Host "Failed to create the certificate." -ForegroundColor Red
        return
    }

    # Display certificate details
    Write-Host "Certificate created successfully." -ForegroundColor Green
    Write-Host "Certificate details:"
    Write-Host "Subject: $($cert.Subject)"
    Write-Host "Thumbprint: $($cert.Thumbprint)"
    Write-Host "Not Before: $($cert.NotBefore)"
    Write-Host "Not After: $($cert.NotAfter)"
    Write-Host "SHA256 Hash: $([BitConverter]::ToString($cert.GetCertHash('SHA256')) -replace '-', '')"
    Write-Host "Certificate will be used for Entra ID Connect service account authentication."


    # Confirm to proceed with assigning permissions
    $confirm = Read-Host "Do you want to assign read permissions to the Entra ID Connect service account for this certificate? (Y/N)"
    if ($confirm -ne 'Y' -and $confirm -ne 'y') {
        Write-Host "Operation cancelled by user." -ForegroundColor Yellow
        return
    }
    # Assign read permissions to the Entra ID Connect service account
    Write-Host "Assigning read permissions to the Entra ID Connect service account so it can access the certificate's private key..."

    try {
        $rsaCert = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
        if ($null -eq $rsaCert) {
            Write-Host "Failed to retrieve the RSA private key from the certificate." -ForegroundColor Red
            return
        }
        $keyName = $rsaCert.key.UniqueName
        if ([string]::IsNullOrWhiteSpace($keyName)) {
            Write-Host "Failed to determine the private key file name." -ForegroundColor Red
            return
        }
        $path = "$env:ALLUSERSPROFILE\Microsoft\Crypto\Keys\$keyName"
        if (-not (Test-Path -Path $path)) {
            Write-Host "Private key file not found at: $path" -ForegroundColor Red
            return
        }
        try {
            $permissions = Get-Acl -Path $path
        } catch {
            Write-Host "Failed to get ACL for private key file: $_" -ForegroundColor Red
            return
        }
        try {
            $serviceAccount = (Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\ADSync -Name ObjectName).ObjectName
        } catch {
            Write-Host "Failed to retrieve the Entra ID Connect service account name: $_" -ForegroundColor Red
            return
        }
        if ([string]::IsNullOrWhiteSpace($serviceAccount)) {
            Write-Host "Service account name is empty or not found." -ForegroundColor Red
            return
        }
        try {
            $rule = New-Object Security.Accesscontrol.FileSystemAccessRule "$serviceAccount", "read", "allow"
            $permissions.AddAccessRule($rule)
            Set-Acl -Path $path -AclObject $permissions
            Write-Host "Certificate created and permissions assigned." -ForegroundColor Green
        } catch {
            Write-Host "Failed to assign permissions to the service account: $_" -ForegroundColor Red
            return
        }
    } catch {
        Write-Host "An unexpected error occurred during certificate permission assignment: $_" -ForegroundColor Red
        return
    }
}

function Get-Certificates {
    try {
        $certs = Get-ChildItem -Path "Cert:\LocalMachine\My" -ErrorAction Stop | Where-Object { $_.HasPrivateKey -and $_.Subject -like "*CN=*" }
    } catch {
        Write-Host "Failed to retrieve certificates: $_" -ForegroundColor Red
        return $null
    }
    if (-not $certs -or $certs.Count -eq 0) {
        Write-Host "No valid certificates found." -ForegroundColor Yellow
        return $null
    }
    Write-Host "Available certificates:" -ForegroundColor Cyan
    $i = 1
    foreach ($cert in $certs) {
        try {
            $sha256 = ([BitConverter]::ToString($cert.GetCertHash("SHA256")) -replace '-', '').ToLower()
        } catch {
            $sha256 = "Error retrieving SHA256"
        }
        Write-Host "$i. Subject: $($cert.Subject)"
        Write-Host "   Thumbprint: $($cert.Thumbprint)"
        Write-Host "   SHA256 Hash: $sha256"
        Write-Host "   Not Before: $($cert.NotBefore)"
        Write-Host "   Not After : $($cert.NotAfter)"
        Write-Host ""
        $i++
    }
    do {
        $selection = Read-Host "Select certificate by number (1-$($certs.Count)), or press Enter to cancel"
        if ([string]::IsNullOrWhiteSpace($selection)) { return $null }
        if ($selection -match '^\d+$' -and $selection -ge 1 -and $selection -le $certs.Count) {
            $selectedCert = $certs[$selection - 1]
            try {
                # Return the SHA256 hash as a lowercase string (no dashes)
                return ([BitConverter]::ToString($selectedCert.GetCertHash("SHA256")) -replace '-', '').ToLower()
            } catch {
                Write-Host "Failed to retrieve SHA256 hash: $_" -ForegroundColor Red
                return $null
            }
        } else {
            Write-Host "Invalid selection. Try again." -ForegroundColor Red
        }
    } while ($true)
}

function Register-Application-With-Certificate {
    try {
        $sha256 = Get-Certificates
        if ($null -eq $sha256) { Write-Host "Operation cancelled."; return }
        Add-EntraApplicationRegistration -CertificateSHA256Hash $sha256
        Write-Host "Application registered with certificate." -ForegroundColor Green
    } catch {
        Write-Host "An error occurred while registering the application: $_" -ForegroundColor Red
    }
}

function Set-CertificateToADConnect {
    try {
        $sha256 = Get-Certificates
        if ($null -eq $sha256) { Write-Host "Operation cancelled."; return }
        Add-ADSyncApplicationRegistration -CertificateSHA256Hash $sha256
        Write-Host "Certificate assigned to Entra ID Connect." -ForegroundColor Green
    } catch {
        Write-Host "An error occurred while assigning the certificate: $_" -ForegroundColor Red
    }
}

function Test-ConnectorCredential {
    try {
        $result = Get-ADSyncEntraConnectorCredential
        if ($null -eq $result) {
            Write-Host "No connector credential found." -ForegroundColor Yellow
            return
        }
        # Only show the summary, not the table
        Write-Host ""
        Write-Host "ConnectorIdentityType: $($result.ConnectorIdentityType)" -ForegroundColor Cyan
        if ($result.CertificateCredential) {
            Write-Host "CertificateCredential type: $($result.CertificateCredential.GetType().Name)" -ForegroundColor Cyan
        } else {
            Write-Host "No CertificateCredential present." -ForegroundColor Yellow
        }
        Write-Host "Connector credential verified successfully." -ForegroundColor Green
    } catch {
        Write-Host "An error occurred while verifying the connector credential: $_" -ForegroundColor Red
    }
}

function RotateCertificate {
    $dns = Read-Host "Enter certificate DNS name"
    Set-ADSyncScheduler -SyncCycleEnabled $false
    $params = @{
        DnsName = $dns
        CertStoreLocation = "Cert:\LocalMachine\My"
        KeyAlgorithm = "RSA"
        KeyLength = 2048
        HashAlgorithm = "SHA256"
        NotAfter = (Get-Date).AddYears(1)
        KeyExportPolicy = "NonExportable"
    }
    $cert = New-SelfSignedCertificate @params
    $rsaCert = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
    $path = "$env:ALLUSERSPROFILE\Microsoft\Crypto\Keys\$($rsaCert.key.UniqueName)"
    $permissions = Get-Acl -Path $path
    $serviceAccount = (Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\ADSync -Name ObjectName).ObjectName
    $rule = New-Object Security.Accesscontrol.FileSystemAccessRule "$serviceAccount", "read", "allow"
    $permissions.AddAccessRule($rule)
    Set-Acl -Path $path -AclObject $permissions

    $errorOccurred = $false
    try {
        Invoke-ADSyncApplicationCredentialRotation -CertificateSHA256Hash $cert.Thumbprint
    } catch {
        $errorOccurred = $true
        Write-Host "An error occurred during certificate rotation:" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
        if ($_.Exception.InnerException) {
            Write-Host $_.Exception.InnerException.Message -ForegroundColor Red
        }
    }
    Set-ADSyncScheduler -SyncCycleEnabled $true

    if (-not $errorOccurred) {
        Write-Host "Certificate rotated and scheduler re-enabled." -ForegroundColor Green
    }
}

do {
    Show-Menu
    $choice = Read-Host "Select an option (1-6)"
    switch ($choice) {
        "1" { CreateAndAssignCertificate }
        "2" { Register-Application-With-Certificate }
        "3" { Set-CertificateToADConnect }
        "4" { Test-ConnectorCredential }
        "5" { RotateCertificate }
        "6" { Write-Host "Exiting..."; exit }
        default { Write-Host "Invalid selection. Try again." -ForegroundColor Red }
    }
} while ($true)