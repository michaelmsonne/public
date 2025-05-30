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
    Write-Host "================================================" -ForegroundColor DarkCyan
    Write-Host " Entra ID Connect - Certificate Management Menu " -ForegroundColor Cyan
    Write-Host "================================================" -ForegroundColor DarkCyan
    Write-Host ""
    Write-Host "1. Create and assign certificate for service account"
    Write-Host "2. Register application with certificate"
    Write-Host "3. Assign certificate to Entra ID Connect"
    Write-Host "4. Verify connector credential"
    Write-Host "5. Rotate (rollover) certificate"
    Write-Host "6. Show current connector config"
    Write-Host ""
    Write-Host "0. Exit"
    Write-Host ""
}

function Add-NewCertAndAssignCertificate {
    Write-Host "Creating and assigning a certificate for the Entra ID Connect service account..." -ForegroundColor Yellow
    $dns = $null
    $domainFound = $false
    try {
        $dns = ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).Name
        $domainFound = $true
        Write-Host "Using current domain name found: $dns"
    } catch {
        Write-Host "Unable to automatically detect the domain name."
    }

    if ($domainFound -and $dns) {
        $useDomain = Read-Host "Use detected domain name '$dns'? (Y to accept, N to enter a custom DNS name)"
        if ($useDomain -ne 'Y' -and $useDomain -ne 'y') {
            $dns = Read-Host "Please enter the certificate DNS name (e.g., sub.domain.com)"
        }
    } else {
        $dns = Read-Host "Please enter the certificate DNS name (e.g., sub.domain.com)"
    }

    if ([string]::IsNullOrWhiteSpace($dns)) {
        Write-Host "No DNS name provided. Skipping certificate creation." -ForegroundColor Yellow
        return
    }

    Write-Host "Generating a new self-signed certificate for: $dns"
    Write-Host "The certificate will be placed in the LocalMachine\My store and set as non-exportable for security."
    Write-Host "The certificate will be valid for 1 year and use SHA256 with a 2048-bit RSA key." -ForegroundColor Yellow
    
    try {
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
    } catch {
        Write-Host "Failed to create self-signed certificate: $_" -ForegroundColor Red
        return
    }

    # Display certificate details
    Write-Host "Certificate created successfully." -ForegroundColor Green
    Write-Host "Certificate details:"
    Write-Host " Subject: $($cert.Subject)"
    Write-Host " Thumbprint: $($cert.Thumbprint)"
    Write-Host " Not Before: $($cert.NotBefore)"
    Write-Host " Not After: $($cert.NotAfter)"
    Write-Host " SHA256 Hash: $([BitConverter]::ToString($cert.GetCertHash('SHA256')) -replace '-', '')"
    Write-Host ""
    Write-Host "Certificate will be used for Entra ID Connect service account authentication."
    Write-Host ""

    # Confirm to proceed with assigning permissions
    $confirm = Read-Host "Do you want to assign read permissions to the Entra ID Connect service account for this certificate? (Y/N)"
    if ($confirm -ne 'Y' -and $confirm -ne 'y') {
        Write-Host "Operation cancelled by user." -ForegroundColor Yellow
        return
    }
    # Assign read permissions to the Entra ID Connect service account
    Write-Host "Assigning read permissions to the Entra ID Connect service account so it can access the certificate's private key..."

    try {
        # Ensure the certificate has a private key
        $rsaCert = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
        if ($null -eq $rsaCert) {
            Write-Host "Failed to retrieve the RSA private key from the certificate." -ForegroundColor Red
            return
        }
        # Get the unique name of the private key file
        $keyName = $rsaCert.key.UniqueName
        if ([string]::IsNullOrWhiteSpace($keyName)) {
            Write-Host "Failed to determine the private key file name." -ForegroundColor Red
            return
        }
        # Construct the path to the private key file
        $path = "$env:ALLUSERSPROFILE\Microsoft\Crypto\Keys\$keyName"
        if (-not (Test-Path -Path $path)) {
            Write-Host "Private key file not found at: $path" -ForegroundColor Red
            return
        }
        # Get the current ACL for the private key file
        try {
            $permissions = Get-Acl -Path $path
        } catch {
            Write-Host "Failed to get ACL for private key file: $_" -ForegroundColor Red
            return
        }
        # Retrieve the Entra ID Connect service account name
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
        # Create a new FileSystemAccessRule to grant read permissions
        Write-Host "Assigning read permissions to the service account: $serviceAccount" -ForegroundColor Yellow
        if (-not $permissions) {
            Write-Host "No permissions found for the private key file. Creating new ACL." -ForegroundColor Yellow
            $permissions = New-Object Security.AccessControl.FileSecurity
        }
        if ($permissions.Access | Where-Object { $_.IdentityReference -eq $serviceAccount -and $_.FileSystemRights -eq "Read" }) {
            Write-Host "Service account already has read permissions." -ForegroundColor Yellow
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
function Register-ApplicationWithCertificate {
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

function Add-NewCertificateAndChange {
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

function Get-ConnectorName {
    # Look for connectors matching the pattern
    $connectors = Get-ADSyncConnector | Where-Object { $_.Name -imatch "onmicrosoft\.com - AAD$" }
    if ($connectors.Count -eq 0) {
        Write-Host "No connectors found matching '*onmicrosoft.com - AAD'" -ForegroundColor Red
        $manual = Read-Host "Do you want to manually enter a connector name? (Y/N)"
        if ($manual -match '^(Y|y)$') {
            return Read-Host "Enter the full connector name"
        } else {
            return $null
        }
    } elseif ($connectors.Count -eq 1) {
        return $connectors[0].Name
    } else {
        Write-Host "Multiple connectors found:" -ForegroundColor Yellow
        $i = 1
        foreach ($c in $connectors) {
            Write-Host "$i : $($c.Name)"
            $i++
        }
        $selection = Read-Host "Select the connector number or type 'M' to manually enter a connector name"
        if ($selection -match "^\d+$" -and $selection -ge 1 -and $selection -le $connectors.Count) {
            return $connectors[$selection - 1].Name
        } elseif ($selection -ieq "M") {
            return Read-Host "Enter the full connector name"
        } else {
            Write-Host "Invalid selection." -ForegroundColor Red
            return $null
        }
    }
}

function Show-ConnectorParameters {
    param(
        [string]$ConnectorName
    )
    
    # If no ConnectorName is provided, automatically find one.
    if ([string]::IsNullOrWhiteSpace($ConnectorName)) {
        Write-Host "No connector name provided. Searching automatically..." -ForegroundColor Yellow
        $ConnectorName = Get-ConnectorName
        if ([string]::IsNullOrWhiteSpace($ConnectorName)) {
            Write-Host "Unable to automatically locate a connector." -ForegroundColor Red
            # Ask user to manually enter
            if ((Read-Host "Would you like to manually enter a connector name? (Y/N)") -match '^(Y|y)$') {
                $ConnectorName = Read-Host "Enter the full connector name"
            } else {
                return
            }
        } else {
            Write-Host "Using connector: $ConnectorName" -ForegroundColor Cyan
        }
    }
    
    $connector = Get-ADSyncConnector | Where-Object { $_.Name -eq $ConnectorName } | Select-Object -First 1
    if (-not $connector) {
        Write-Host "Connector '$ConnectorName' not found." -ForegroundColor Red
        return
    }
    
    Write-Host "Connector: $($connector.Name)" -ForegroundColor Cyan
    $oldLimit = $FormatEnumerationLimit
    $FormatEnumerationLimit = -1
    # Capture table output into a string
    $output = $connector.ConnectivityParameters | Format-Table Name, InputType, Value -Wrap -AutoSize | Out-String
    # Replace multiple newlines with a single newline
    $compressedOutput = $output -replace "(\r?\n\s*){2,}", "`n"
    Write-Host $compressedOutput.TrimEnd()
    $FormatEnumerationLimit = $oldLimit
}

function Show-CurrentConnectorConfig {
    Write-Host "Retrieving current connector configuration..." -ForegroundColor Cyan
    Show-ConnectorParameters -ConnectorName ""
}

do {
    Show-Menu
    $choice = Read-Host "Select an option (1-6) or 0 to exit"    
    switch ($choice) {
        "1" { Add-NewCertAndAssignCertificate }
        "2" { Register-ApplicationWithCertificate }
        "3" { Set-CertificateToADConnect }
        "4" { Test-ConnectorCredential }
        "5" { Add-NewCertificateAndChange }
        "6" { Show-CurrentConnectorConfig }
        "0" { Write-Host "Exiting..."; exit }
        default { Write-Host "Invalid selection. Try again." -ForegroundColor Red }
    }
} while ($true)