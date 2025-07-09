<#	
	.NOTES
	===========================================================================
	 Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2022 v5.8.213
	 Created on:   	14-02-2024 21:37
	 Created by:   	Michael Morten Sonne
	 Organization: 	Sonne´s Cloud
	 Blog:          https://blog.sonnes.cloud
	 Filename:     	UpdateSecureBootCAs.ps1
	===========================================================================
	.DESCRIPTION
		PowerShell script to update Secure Boot DB on Windows for the UEFI CA 2023 certificate update.
		This script addresses the Microsoft Tech Community guidance for the June 2026 certificate expiration.
		Features include:
		- System compatibility checking
		- Current Secure Boot status assessment
		- Prerequisites setup (registry keys, diagnostic data)
		- Detailed reporting and logging
		- Certificate update process automation
		- Verification of successful updates

    .REQUREMENT
        - Administrator rights on the machine
        - UEFI-based system with Secure Boot support
        - Windows 10/11 with necessary Windows Update components

    .CHANGELOG
        14-02-2024 - Michael Morten Sonne - Initial release
        09-07-2025 - Michael Morten Sonne - Enhanced with comprehensive system checking, status reporting, and prerequisites setup per Microsoft guidance

	.EXAMPLE
        .\UpdateSecureBootCAs.ps1
#>

# Check if running as administrator
$adminRights = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $adminRights) {
    Write-Host "Please run this script as an administrator."
    Start-Sleep -Seconds 3
    Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`"" -Verb RunAs
    Exit
}

function Show-Menu {
    Clear-Host
    Write-Host "********** Secure Boot Update Menu for UEFI CA 2023 **********" -ForegroundColor Cyan
    Write-Host "*** Certificate Expiration: June 2026 - Update Required ***" -ForegroundColor Red
    Write-Host ""
    Write-Host "Certificate Analysis:"
    Write-Host "1. Show certificate overview and expiration timeline"
    Write-Host "2. Check system information and compatibility"
    Write-Host "3. Check current Secure Boot status"
    Write-Host ""
    Write-Host "Prerequisites & Setup:"
    Write-Host "4. Set up prerequisites for update"
    Write-Host "5. Export detailed report"
    Write-Host ""
    Write-Host "Update Process:"
    Write-Host "6. Set registry key for certificate update"
    Write-Host "7. Run scheduled task"
    Write-Host "8. Reboot the machine"
    Write-Host "9. Verify Secure Boot DB update"
    Write-Host ""
    Write-Host "10. Exit"
}

function RunScheduledTask {
    $taskName = "\Microsoft\Windows\PI\Secure-Boot-Update"
    
    try {
        # Check if the task exists
        Get-ScheduledTask -TaskName $taskName -ErrorAction Stop | Out-Null
        
        # Start the scheduled task
        Start-ScheduledTask -TaskName $taskName
        Write-Host "Scheduled task started. Waiting for it to complete..." -ForegroundColor Yellow
        
        # Wait for the task to complete
        do {
            Start-Sleep -Seconds 2
            $taskState = (Get-ScheduledTask -TaskName $taskName).State
            Write-Host "Task status: $taskState" -ForegroundColor Cyan
        } while ($taskState -ne 'Ready')
        
        Write-Host "Scheduled task completed." -ForegroundColor Green
        
        # Check the last run result
        $taskInfo = Get-ScheduledTaskInfo -TaskName $taskName
        if ($taskInfo.LastTaskResult -eq 0) {
            Write-Host "Task completed successfully (Result: $($taskInfo.LastTaskResult))" -ForegroundColor Green
        } else {
            Write-Host "Task completed with result code: $($taskInfo.LastTaskResult)" -ForegroundColor Yellow
        }
        
    } catch {
        Write-Host "Error running scheduled task: $_" -ForegroundColor Red
        Write-Host "This may be normal if the task doesn't exist on this system or if Secure Boot updates are not available." -ForegroundColor Yellow
    }
}

function Get-SystemInfo {
    $system = Get-CimInstance -Class Win32_ComputerSystem
    $bios = Get-CimInstance -Class Win32_BIOS
    $os = Get-CimInstance -Class Win32_OperatingSystem

    $info = [PSCustomObject]@{
        ComputerName     = $env:COMPUTERNAME
        Manufacturer     = $system.Manufacturer
        Model            = $system.Model
        BIOS_Version     = $bios.SMBIOSBIOSVersion
        BIOS_ReleaseDate = $bios.ReleaseDate
        OS_Version       = $os.Version
        OS_BuildNumber   = $os.BuildNumber
        Timestamp        = (Get-Date).ToString("s")
    }

    return $info
}

function Get-SecureBootStatus {
    $results = [PSCustomObject]@{
        SecureBoot_Enabled             = $false
        MicrosoftUpdateManagedOptIn   = $false
        DiagnosticDataEnabled         = $false
        OS_Version                    = (Get-CimInstance Win32_OperatingSystem).Version
        UEFI_FirmwareVersion          = $null
        AvailableUpdatesSet           = $false
        CertificateExpirationCheck    = $null
    }

    # Secure Boot status
    try {
        if (Confirm-SecureBootUEFI) {
            $results.SecureBoot_Enabled = $true
        }
    } catch {
        # Could not confirm Secure Boot (likely unsupported system)
        $results.SecureBoot_Enabled = $false
    }

    # Registry opt-in check
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Secureboot"
    try {
        if (Test-Path $regPath) {
            $value = Get-ItemProperty -Path $regPath -Name MicrosoftUpdateManagedOptIn -ErrorAction SilentlyContinue
            if ($value.MicrosoftUpdateManagedOptIn -eq 0x5944) {
                $results.MicrosoftUpdateManagedOptIn = $true
            }
        }
    } catch {
        # Registry key or value not accessible
        $results.MicrosoftUpdateManagedOptIn = $false
    }

    # Check if AvailableUpdates is set for Secure Boot update
    try {
        if (Test-Path $regPath) {
            $availableUpdates = Get-ItemProperty -Path $regPath -Name AvailableUpdates -ErrorAction SilentlyContinue
            if ($availableUpdates.AvailableUpdates -eq 0x40) {
                $results.AvailableUpdatesSet = $true
            }
        }
    } catch {
        $results.AvailableUpdatesSet = $false
    }

    # Diagnostic data level
    try {
        $diag = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name AllowTelemetry -ErrorAction SilentlyContinue
        if ($diag.AllowTelemetry -ge 1) {
            $results.DiagnosticDataEnabled = $true
        }
    } catch {
        $results.DiagnosticDataEnabled = $false
    }

    # Firmware version
    try {
        $bios = Get-CimInstance -ClassName Win32_BIOS
        $results.UEFI_FirmwareVersion = $bios.SMBIOSBIOSVersion
    } catch {
        $results.UEFI_FirmwareVersion = "Unavailable"
    }

    # Check for certificate expiration (June 2026)
    try {
        $secureBootDB = Get-SecureBootUEFI db -ErrorAction SilentlyContinue
        if ($secureBootDB) {
            $dbString = [System.Text.Encoding]::ASCII.GetString($secureBootDB.bytes)
            if ($dbString -match 'Windows UEFI CA 2023') {
                $results.CertificateExpirationCheck = "Updated certificates found"
            } else {
                $results.CertificateExpirationCheck = "Legacy certificates - update required before June 2026"
            }
        }
    } catch {
        $results.CertificateExpirationCheck = "Unable to check certificate status"
    }

    return $results
}

function Set-SecureBootPrerequisites {
    Write-Host "Setting up prerequisites for Secure Boot certificate update..." -ForegroundColor Yellow
    
    # Ensure registry key exists
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Secureboot"
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
        Write-Host "Created Secure Boot registry path" -ForegroundColor Green
    }

    # Set MicrosoftUpdateManagedOptIn
    try {
        Set-ItemProperty -Path $regPath -Name "MicrosoftUpdateManagedOptIn" -Type DWord -Value 0x5944 -Force
        Write-Host "Set MicrosoftUpdateManagedOptIn registry value" -ForegroundColor Green
    } catch {
        Write-Host "Failed to set MicrosoftUpdateManagedOptIn: $_" -ForegroundColor Red
    }

    # Ensure required diagnostic data level (minimum: 1)
    try {
        $diagPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"
        if (-not (Test-Path $diagPath)) {
            New-Item -Path $diagPath -Force | Out-Null
        }
        Set-ItemProperty -Path $diagPath -Name "AllowTelemetry" -Type DWord -Value 1 -Force
        Write-Host "Set diagnostic data level to required minimum" -ForegroundColor Green
    } catch {
        Write-Host "Failed to set diagnostic data level: $_" -ForegroundColor Red
    }

    Write-Host "Prerequisites setup completed" -ForegroundColor Green
}

function Export-SecureBootReport {
    $systemInfo = Get-SystemInfo
    $secureBootStatus = Get-SecureBootStatus
    
    # Create logs directory if it doesn't exist
    $logPath = "C:\Logs"
    if (-not (Test-Path $logPath)) {
        New-Item -Path $logPath -ItemType Directory -Force | Out-Null
    }
    
    # Export system information
    $systemReportPath = Join-Path $logPath "SecureBootSystemInfo_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $systemInfo | Export-Csv -Path $systemReportPath -NoTypeInformation
    
    # Export Secure Boot status
    $statusReportPath = Join-Path $logPath "SecureBootStatus_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $secureBootStatus | Export-Csv -Path $statusReportPath -NoTypeInformation
    
    Write-Host "Reports exported to:" -ForegroundColor Green
    Write-Host "  System Info: $systemReportPath" -ForegroundColor Cyan
    Write-Host "  Secure Boot Status: $statusReportPath" -ForegroundColor Cyan
    
    # Display results on screen
    Write-Host "`nSystem Information:" -ForegroundColor Yellow
    $systemInfo | Format-List
    
    Write-Host "`nSecure Boot Status:" -ForegroundColor Yellow
    $secureBootStatus | Format-List
}

function Get-DetailedCertificateInfo {
    Write-Host "Analyzing Secure Boot certificates..." -ForegroundColor Yellow
    Write-Host ""
    
    $results = [PSCustomObject]@{
        KEK_Status = "Not Checked"
        KEK_Legacy_Found = $false
        KEK_Updated_Found = $false
        DB_UEFI_Status = "Not Checked"
        DB_UEFI_Legacy_Found = $false
        DB_UEFI_Updated_Found = $false
        DB_Windows_Status = "Not Checked"
        DB_Windows_Legacy_Found = $false
        DB_Windows_Updated_Found = $false
        OverallStatus = "Unknown"
        CertificateDetails = @()
    }
    
    try {
        # Check KEK (Key Exchange Key)
        Write-Host "► Checking KEK certificates..." -ForegroundColor Cyan
        try {
            $kekData = Get-SecureBootUEFI -Name kek -ErrorAction Stop
            $kekString = [System.Text.Encoding]::ASCII.GetString($kekData.bytes)
            
            # Check for legacy KEK certificate
            if ($kekString -match 'Microsoft Corporation KEK CA 2011') {
                $results.KEK_Legacy_Found = $true
                Write-Host "  ✓ Found: Microsoft Corporation KEK CA 2011 (expires June 2026)" -ForegroundColor Yellow
            }
            
            # Check for updated KEK certificate
            if ($kekString -match 'Microsoft Corporation KEK 2K CA 2023') {
                $results.KEK_Updated_Found = $true
                Write-Host "  ✓ Found: Microsoft Corporation KEK 2K CA 2023 (updated certificate)" -ForegroundColor Green
            }
            
            $results.KEK_Status = if ($results.KEK_Updated_Found) { "Updated" } elseif ($results.KEK_Legacy_Found) { "Legacy - Update Required" } else { "Unknown" }
        } catch {
            $results.KEK_Status = "Error accessing KEK"
            Write-Host "  ✗ Error accessing KEK certificates: $_" -ForegroundColor Red
        }
        
        Write-Host ""
        
        # Check DB (Signature Database)
        Write-Host "► Checking DB certificates..." -ForegroundColor Cyan
        try {
            $dbData = Get-SecureBootUEFI -Name db -ErrorAction Stop
            $dbString = [System.Text.Encoding]::ASCII.GetString($dbData.bytes)
            
            # Check for legacy UEFI certificates
            if ($dbString -match 'Microsoft Corporation UEFI CA 2011') {
                $results.DB_UEFI_Legacy_Found = $true
                Write-Host "  ✓ Found: Microsoft Corporation UEFI CA 2011 (expires June 2026)" -ForegroundColor Yellow
            }
            
            # Check for updated UEFI certificates
            if ($dbString -match 'Microsoft Corporation UEFI CA 2023') {
                $results.DB_UEFI_Updated_Found = $true
                Write-Host "  ✓ Found: Microsoft Corporation UEFI CA 2023 (updated certificate)" -ForegroundColor Green
            }
            
            if ($dbString -match 'Microsoft Option ROM UEFI CA 2023') {
                Write-Host "  ✓ Found: Microsoft Option ROM UEFI CA 2023 (updated certificate)" -ForegroundColor Green
            }
            
            # Check for legacy Windows certificates
            if ($dbString -match 'Microsoft Windows Production PCA 2011') {
                $results.DB_Windows_Legacy_Found = $true
                Write-Host "  ✓ Found: Microsoft Windows Production PCA 2011 (expires October 2026)" -ForegroundColor Yellow
            }
            
            # Check for updated Windows certificates
            if ($dbString -match 'Windows UEFI CA 2023') {
                $results.DB_Windows_Updated_Found = $true
                Write-Host "  ✓ Found: Windows UEFI CA 2023 (updated certificate)" -ForegroundColor Green
            }
            
            $results.DB_UEFI_Status = if ($results.DB_UEFI_Updated_Found) { "Updated" } elseif ($results.DB_UEFI_Legacy_Found) { "Legacy - Update Required" } else { "Unknown" }
            $results.DB_Windows_Status = if ($results.DB_Windows_Updated_Found) { "Updated" } elseif ($results.DB_Windows_Legacy_Found) { "Legacy - Update Required" } else { "Unknown" }
            
        } catch {
            $results.DB_UEFI_Status = "Error accessing DB"
            $results.DB_Windows_Status = "Error accessing DB"
            Write-Host "  ✗ Error accessing DB certificates: $_" -ForegroundColor Red
        }
        
        # Determine overall status
        if ($results.KEK_Updated_Found -and $results.DB_UEFI_Updated_Found -and $results.DB_Windows_Updated_Found) {
            $results.OverallStatus = "Fully Updated"
        } elseif ($results.KEK_Legacy_Found -or $results.DB_UEFI_Legacy_Found -or $results.DB_Windows_Legacy_Found) {
            $results.OverallStatus = "Partial Update - Action Required"
        } else {
            $results.OverallStatus = "Status Unknown"
        }
        
        # Create detailed certificate information
        $results.CertificateDetails = @(
            [PSCustomObject]@{
                Location = "KEK"
                ExpirationDate = "June 2026"
                ExpiringCertificate = "Microsoft Corporation KEK CA 2011"
                UpdatedCertificate = "Microsoft Corporation KEK 2K CA 2023"
                Purpose = "Signs updates to DB and DBX"
                LegacyFound = $results.KEK_Legacy_Found
                UpdatedFound = $results.KEK_Updated_Found
                Status = $results.KEK_Status
            },
            [PSCustomObject]@{
                Location = "DB"
                ExpirationDate = "June 2026"
                ExpiringCertificate = "Microsoft Corporation UEFI CA 2011"
                UpdatedCertificate = "Microsoft Corporation UEFI CA 2023"
                Purpose = "Signs third-party OS and hardware driver components"
                LegacyFound = $results.DB_UEFI_Legacy_Found
                UpdatedFound = $results.DB_UEFI_Updated_Found
                Status = $results.DB_UEFI_Status
            },
            [PSCustomObject]@{
                Location = "DB"
                ExpirationDate = "June 2026"
                ExpiringCertificate = "Third-party UEFI CA"
                UpdatedCertificate = "Microsoft Option ROM UEFI CA 2023"
                Purpose = "Signs third-party option ROMs"
                LegacyFound = "N/A"
                UpdatedFound = ($dbString -match 'Microsoft Option ROM UEFI CA 2023')
                Status = if ($dbString -match 'Microsoft Option ROM UEFI CA 2023') { "Updated" } else { "Not Found" }
            },
            [PSCustomObject]@{
                Location = "DB"
                ExpirationDate = "October 2026"
                ExpiringCertificate = "Microsoft Windows Production PCA 2011"
                UpdatedCertificate = "Windows UEFI CA 2023"
                Purpose = "Signs the Windows bootloader and boot components"
                LegacyFound = $results.DB_Windows_Legacy_Found
                UpdatedFound = $results.DB_Windows_Updated_Found
                Status = $results.DB_Windows_Status
            }
        )
        
    } catch {
        Write-Host "Error during certificate analysis: $_" -ForegroundColor Red
        $results.OverallStatus = "Error"
    }
    
    Write-Host ""
    
    return $results
}

function Show-CertificateOverview {
    Write-Host "`n============= SECURE BOOT CERTIFICATE OVERVIEW =============" -ForegroundColor Cyan
    Write-Host "Based on Microsoft Tech Community guidance for certificate expiration" -ForegroundColor Gray
    Write-Host ""
    
    # Display the certificate information in a more readable format
    Write-Host "Certificate Expiration Timeline:" -ForegroundColor Yellow
    Write-Host "================================================================" -ForegroundColor Gray
    
    Write-Host ""
    Write-Host "1. KEK Certificate (June 2026):" -ForegroundColor White
    Write-Host "   Expiring:  Microsoft Corporation KEK CA 2011" -ForegroundColor Red
    Write-Host "   Updated:   Microsoft Corporation KEK 2K CA 2023" -ForegroundColor Green
    Write-Host "   Purpose:   Signs updates to DB and DBX" -ForegroundColor Gray
    Write-Host "   Location:  KEK" -ForegroundColor Gray
    
    Write-Host ""
    Write-Host "2. UEFI Certificate (June 2026):" -ForegroundColor White
    Write-Host "   Expiring:  Microsoft Corporation UEFI CA 2011" -ForegroundColor Red
    Write-Host "   Updated:   Microsoft Corporation UEFI CA 2023" -ForegroundColor Green
    Write-Host "   Purpose:   Signs third-party OS and hardware drivers" -ForegroundColor Gray
    Write-Host "   Location:  DB" -ForegroundColor Gray
    
    Write-Host ""
    Write-Host "3. Option ROM Certificate (June 2026):" -ForegroundColor White
    Write-Host "   Expiring:  Third-party UEFI CA" -ForegroundColor Red
    Write-Host "   Updated:   Microsoft Option ROM UEFI CA 2023" -ForegroundColor Green
    Write-Host "   Purpose:   Signs third-party option ROMs" -ForegroundColor Gray
    Write-Host "   Location:  DB" -ForegroundColor Gray
    
    Write-Host ""
    Write-Host "4. Windows Certificate (October 2026):" -ForegroundColor White
    Write-Host "   Expiring:  Microsoft Windows Production PCA 2011" -ForegroundColor Red
    Write-Host "   Updated:   Windows UEFI CA 2023" -ForegroundColor Green
    Write-Host "   Purpose:   Signs Windows bootloader and boot components" -ForegroundColor Gray
    Write-Host "   Location:  DB" -ForegroundColor Gray
    
    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Gray
    
    # Get and display current certificate status
    $certInfo = Get-DetailedCertificateInfo
    
    Write-Host ""
    Write-Host "Current System Status:" -ForegroundColor Yellow
    Write-Host "Overall Status: " -NoNewline
    switch ($certInfo.OverallStatus) {
        "Fully Updated" { Write-Host $certInfo.OverallStatus -ForegroundColor Green }
        "Partial Update - Action Required" { Write-Host $certInfo.OverallStatus -ForegroundColor Yellow }
        "Status Unknown" { Write-Host $certInfo.OverallStatus -ForegroundColor Gray }
        "Error" { Write-Host $certInfo.OverallStatus -ForegroundColor Red }
    }
    
    Write-Host ""
    Write-Host "Certificate Status Summary:" -ForegroundColor Yellow
    Write-Host "================================================================" -ForegroundColor Gray
    
    foreach ($cert in $certInfo.CertificateDetails) {
        $statusColor = switch ($cert.Status) {
            "Updated" { "Green" }
            "Legacy - Update Required" { "Yellow" }
            "Not Found" { "Gray" }
            default { "Red" }
        }
        
        $statusSymbol = switch ($cert.Status) {
            "Updated" { "✓" }
            "Legacy - Update Required" { "⚠" }
            "Not Found" { "?" }
            default { "✗" }
        }
        
        Write-Host "$statusSymbol $($cert.Location) - $($cert.ExpirationDate): " -NoNewline
        Write-Host "$($cert.Status)" -ForegroundColor $statusColor
        Write-Host "   Legacy Found: $($cert.LegacyFound) | Updated Found: $($cert.UpdatedFound)" -ForegroundColor Gray
    }
    
    Write-Host ""
    Write-Host "Recommendations:" -ForegroundColor Yellow
    Write-Host "================================================================" -ForegroundColor Gray
    if ($certInfo.OverallStatus -eq "Fully Updated") {
        Write-Host "✓ All certificates are up to date. No action required." -ForegroundColor Green
    } elseif ($certInfo.OverallStatus -eq "Partial Update - Action Required") {
        Write-Host "⚠ Some certificates need updating. Use the update process (options 6-9) to complete the update." -ForegroundColor Yellow
    } else {
        Write-Host "? Status unclear. Ensure Secure Boot is enabled and run the update process." -ForegroundColor Gray
    }
    
    return $certInfo
}

# Main execution loop
do {
    Show-Menu
    $choice = Read-Host "Select a task (1-10)"

    try {
        switch ($choice) {
            1 {
                # Show certificate overview and expiration timeline
                Show-CertificateOverview
            }
            2 {
                # Check system information and compatibility
                Write-Host "Gathering system information..." -ForegroundColor Yellow
                $systemInfo = Get-SystemInfo
                $systemInfo | Format-List
                
                # Check if system supports Secure Boot
                try {
                    Get-SecureBootUEFI -Name SetupMode -ErrorAction Stop | Out-Null
                    Write-Host "System supports Secure Boot UEFI" -ForegroundColor Green
                } catch {
                    Write-Host "Warning: System may not support Secure Boot or is running in Legacy BIOS mode" -ForegroundColor Yellow
                }
            }
            3 {
                # Check current Secure Boot status
                Write-Host "Checking current Secure Boot status..." -ForegroundColor Yellow
                $status = Get-SecureBootStatus
                $status | Format-List
                
                # Provide recommendations based on status
                if (-not $status.SecureBoot_Enabled) {
                    Write-Host "Recommendation: Enable Secure Boot in UEFI settings" -ForegroundColor Yellow
                }
                if (-not $status.MicrosoftUpdateManagedOptIn) {
                    Write-Host "Recommendation: Use option 4 to set up prerequisites" -ForegroundColor Yellow
                }
                if (-not $status.DiagnosticDataEnabled) {
                    Write-Host "Recommendation: Enable diagnostic data for certificate updates" -ForegroundColor Yellow
                }
                if ($status.CertificateExpirationCheck -like "*update required*") {
                    Write-Host "Action Required: Update certificates before June 2026" -ForegroundColor Red
                }
            }
            4 {
                # Set up prerequisites for update
                Set-SecureBootPrerequisites
            }
            5 {
                # Export detailed report
                Write-Host "Generating detailed report..." -ForegroundColor Yellow
                Export-SecureBootReport
            }
            6 {
                # Set registry key for certificate update
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot" -Name "AvailableUpdates" -Value 0x40
                Write-Host "Registry key set successfully to apply the update" -ForegroundColor Green
    
                # Prompt to execute task 7 automatically or manually
                $task7Choice = Read-Host "Do you want to execute task 7 (Run scheduled task) automatically (Y) or manually (M)?"
                if ($task7Choice -eq 'Y' -or $task7Choice -eq 'y') {
                    # Run scheduled task to update Secure Boot DB with the new CA
                    RunScheduledTask
                } elseif ($task7Choice -eq 'M' -or $task7Choice -eq 'm') {
                    Write-Host "You can manually execute task 7 from the menu."
                } else {
                    Write-Host "Invalid choice. Task 7 will not be executed."
                }
            }
            7 {
                # Run scheduled task manually to update Secure Boot DB with the new CA
                RunScheduledTask
            }
            8 {
                # Confirm reboot
                $confirmReboot = Read-Host "Do you want to reboot the machine? (Y/N)"
                if ($confirmReboot -eq 'Y' -or $confirmReboot -eq 'y') {
                    # Reboot the machine
                    Write-Host "Rebooting the machine..." -ForegroundColor Yellow
                    Restart-Computer -Force
                } else {
                    Write-Host "Reboot canceled."
                }
            }
            9 {
                # Verify Secure Boot DB update with detailed analysis
                Write-Host "Performing detailed certificate verification..." -ForegroundColor Yellow
                $certInfo = Get-DetailedCertificateInfo
                
                Write-Host "================================================================" -ForegroundColor Gray
                Write-Host "VERIFICATION RESULTS" -ForegroundColor Yellow
                Write-Host "================================================================" -ForegroundColor Gray
                
                Write-Host "Overall Status: " -NoNewline
                switch ($certInfo.OverallStatus) {
                    "Fully Updated" { 
                        Write-Host $certInfo.OverallStatus -ForegroundColor Green 
                        Write-Host "✓ All certificates have been successfully updated" -ForegroundColor Green
                        Write-Host "✓ Your system is prepared for the June 2026 certificate expiration" -ForegroundColor Green
                    }
                    "Partial Update - Action Required" { 
                        Write-Host $certInfo.OverallStatus -ForegroundColor Yellow 
                        Write-Host "⚠ Some certificates still need updating - please retry the update process" -ForegroundColor Yellow
                    }
                    "Status Unknown" { 
                        Write-Host $certInfo.OverallStatus -ForegroundColor Gray 
                        Write-Host "? Unable to determine certificate status" -ForegroundColor Gray
                    }
                    "Error" { 
                        Write-Host $certInfo.OverallStatus -ForegroundColor Red 
                        Write-Host "✗ Error occurred during verification" -ForegroundColor Red
                    }
                }
                
                Write-Host ""
                Write-Host "Certificate Status Summary:" -ForegroundColor Yellow
                Write-Host "================================================================" -ForegroundColor Gray
                
                foreach ($cert in $certInfo.CertificateDetails) {
                    $statusColor = switch ($cert.Status) {
                        "Updated" { "Green" }
                        "Legacy - Update Required" { "Yellow" }
                        "Not Found" { "Gray" }
                        default { "Red" }
                    }
                    
                    $statusSymbol = switch ($cert.Status) {
                        "Updated" { "✓" }
                        "Legacy - Update Required" { "⚠" }
                        "Not Found" { "?" }
                        default { "✗" }
                    }
                    
                    Write-Host "$statusSymbol $($cert.Location) Certificate ($($cert.ExpirationDate)): " -NoNewline
                    Write-Host "$($cert.Status)" -ForegroundColor $statusColor
                    Write-Host "   Legacy: $($cert.LegacyFound) | Updated: $($cert.UpdatedFound)" -ForegroundColor Gray
                    Write-Host "   Purpose: $($cert.Purpose)" -ForegroundColor Gray
                    Write-Host ""
                }
            }
            10 {
                # Exit
                Write-Host "Exiting Secure Boot Update Menu."
            }
            default {
                # Invalid selection
                Write-Host "Invalid selection. Please enter a number between 1 and 10."
            }
        }
    }
    catch {
        # Catch any errors and display them
        Write-Host "An error occurred: $_" -ForegroundColor Red
    }    

    if ($choice -ne 10) {
        # Prompt to continue
        $null = Read-Host "Press Enter to continue..."
    }

} while ($choice -ne 10)