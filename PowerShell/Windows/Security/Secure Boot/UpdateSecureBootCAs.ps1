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
        09-07-2025 - Michael Morten Sonne - Enhanced with comprehensive system checking, status reporting, and prerequisites setup per Microsoft guidance like https://techcommunity.microsoft.com/blog/windows-itpro-blog/act-now-secure-boot-certificates-expire-in-june-2026/4426856

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
    #Clear-Host
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
    Write-Host "6. Show Secure Boot scheduled tasks"
    Write-Host ""
    Write-Host "Update Process:"
    Write-Host "7. Set registry key for certificate update"
    Write-Host "8. Run scheduled task"
    Write-Host "9. Reboot the machine"
    Write-Host "10. Verify Secure Boot DB update"
    Write-Host ""
    Write-Host "11. Exit"
}

function RunScheduledTask {
    # Split task path and name for proper PowerShell cmdlet usage
    $taskPath = "\Microsoft\Windows\PI\"
    $taskName = "Secure-Boot-Update"
    $fullTaskName = "$taskPath$taskName"
    
    Write-Host "================================================================" -ForegroundColor Gray
    Write-Host "RUNNING SECURE BOOT UPDATE TASK" -ForegroundColor Yellow
    Write-Host "================================================================" -ForegroundColor Gray
    
    try {
        # Check if the task exists using separate path and name
        Write-Host "Checking if task exists..." -ForegroundColor Cyan
        Write-Host "  Task Path: $taskPath" -ForegroundColor Gray
        Write-Host "  Task Name: $taskName" -ForegroundColor Gray
        
        $task = Get-ScheduledTask -TaskPath $taskPath -TaskName $taskName -ErrorAction Stop
        Write-Host "✓ Task found: $($task.TaskName)" -ForegroundColor Green
        Write-Host "  Full Path: $($task.TaskPath)$($task.TaskName)" -ForegroundColor Gray
        Write-Host "  Current State: $($task.State)" -ForegroundColor Gray
        
        # Check if task is already running
        if ($task.State -eq 'Running') {
            Write-Host "⚠ Task is already running. Waiting for it to complete..." -ForegroundColor Yellow
        } else {
            # Start the scheduled task using separate path and name
            Write-Host "Starting scheduled task..." -ForegroundColor Cyan
            Start-ScheduledTask -TaskPath $taskPath -TaskName $taskName
            Write-Host "✓ Task started successfully" -ForegroundColor Green
        }
        
        Write-Host "Monitoring task progress..." -ForegroundColor Yellow
        $timeout = 300  # 5 minutes timeout
        $elapsed = 0
        
        # Wait for the task to complete
        do {
            Start-Sleep -Seconds 3
            $elapsed += 3
            $currentTask = Get-ScheduledTask -TaskPath $taskPath -TaskName $taskName
            $taskState = $currentTask.State
            
            # Show progress indicator
            $dots = "." * (($elapsed / 3) % 4)
            Write-Host "Task status: $taskState$dots (Elapsed: $elapsed seconds)" -ForegroundColor Cyan
            
            # Check for timeout
            if ($elapsed -ge $timeout) {
                Write-Host "⚠ Task timeout reached ($timeout seconds). Task may still be running." -ForegroundColor Yellow
                break
            }
            
        } while ($taskState -ne 'Ready')
        
        if ($taskState -eq 'Ready') {
            Write-Host "✓ Scheduled task completed." -ForegroundColor Green
            
            # Check the last run result using separate path and name
            Write-Host "Checking task execution results..." -ForegroundColor Cyan
            $taskInfo = Get-ScheduledTaskInfo -TaskPath $taskPath -TaskName $taskName
            
            Write-Host "Task Execution Details:" -ForegroundColor Yellow
            Write-Host "  Last Run Time: $($taskInfo.LastRunTime)" -ForegroundColor Gray
            Write-Host "  Last Result: $($taskInfo.LastTaskResult)" -ForegroundColor Gray
            Write-Host "  Next Run Time: $($taskInfo.NextRunTime)" -ForegroundColor Gray
            
            if ($taskInfo.LastTaskResult -eq 0) {
                Write-Host "✓ Task completed successfully (Result: $($taskInfo.LastTaskResult))" -ForegroundColor Green
                Write-Host "✓ Secure Boot certificate update process completed" -ForegroundColor Green
            } elseif ($taskInfo.LastTaskResult -eq 267011) {
                Write-Host "⚠ Task completed with result: $($taskInfo.LastTaskResult) (Task was terminated)" -ForegroundColor Yellow
            } else {
                Write-Host "⚠ Task completed with result code: $($taskInfo.LastTaskResult)" -ForegroundColor Yellow
                Write-Host "  This may indicate an issue with the certificate update process" -ForegroundColor Yellow
            }
        }
        
    } catch [Microsoft.PowerShell.Cmdletization.Cim.CimJobException] {
        Write-Host "✗ Scheduled task not found: $fullTaskName" -ForegroundColor Red
        Write-Host "This may be normal if:" -ForegroundColor Yellow
        Write-Host "  - The system doesn't support Secure Boot certificate updates" -ForegroundColor Yellow
        Write-Host "  - Windows updates haven't created the task yet" -ForegroundColor Yellow
        Write-Host "  - The system is running an older version of Windows" -ForegroundColor Yellow
    } catch {
        Write-Host "✗ Error running scheduled task: $_" -ForegroundColor Red
        Write-Host "This may be normal if the task doesn't exist on this system or if Secure Boot updates are not available." -ForegroundColor Yellow
    }
    
    Write-Host "================================================================" -ForegroundColor Gray
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
        SecureBoot_Enabled            = $false
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
            if ($kekString -match 'Microsoft Corporation KEK CA 2023') {
                $results.KEK_Updated_Found = $true
                Write-Host "  ✓ Found: Microsoft Corporation KEK CA 2023 (updated certificate)" -ForegroundColor Green
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
                ExpiringCertificate = "Microsoft Corporation KEK CA 2011"
                ExpirationDate = "June 2026"
                NewCertificate = "Microsoft Corporation KEK CA 2023"
                StoringLocation = "Stored in KEK"
                Purpose = "Signs updates to DB and DBX"
                LegacyFound = $results.KEK_Legacy_Found
                UpdatedFound = $results.KEK_Updated_Found
                Status = $results.KEK_Status
            },
            [PSCustomObject]@{
                ExpiringCertificate = "Microsoft Windows Production PCA 2011"
                ExpirationDate = "Oct 2026"
                NewCertificate = "Windows UEFI CA 2023"
                StoringLocation = "Stored in DB"
                Purpose = "Used for signing the Windows boot loader"
                LegacyFound = $results.DB_Windows_Legacy_Found
                UpdatedFound = $results.DB_Windows_Updated_Found
                Status = $results.DB_Windows_Status
            },
            [PSCustomObject]@{
                ExpiringCertificate = "Microsoft UEFI CA 2011"
                ExpirationDate = "June 2026"
                NewCertificate = "Microsoft UEFI CA 2023"
                StoringLocation = "Stored in DB"
                Purpose = "Signs third-party boot loaders and EFI applications"
                LegacyFound = $results.DB_UEFI_Legacy_Found
                UpdatedFound = $results.DB_UEFI_Updated_Found
                Status = $results.DB_UEFI_Status
            },
            [PSCustomObject]@{
                ExpiringCertificate = "Microsoft UEFI CA 2011"
                ExpirationDate = "June 2026"
                NewCertificate = "Microsoft Option ROM UEFI CA 2023"
                StoringLocation = "Stored in DB"
                Purpose = "Signs third-party option ROMs"
                LegacyFound = $results.DB_UEFI_Legacy_Found
                UpdatedFound = ($dbString -match 'Microsoft Option ROM UEFI CA 2023')
                Status = if ($dbString -match 'Microsoft Option ROM UEFI CA 2023') { "Updated" } else { "Not Found" }
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
    
    # Get current certificate information
    $certInfo = Get-DetailedCertificateInfo
    
    # Display comprehensive certificate information table
    Write-Host "Certificate Update Summary:" -ForegroundColor Yellow
    Write-Host "================================================================" -ForegroundColor Gray
    Write-Host ""
    
    # Certificate data array matching your requested format
    $certificateData = @(
        [PSCustomObject]@{
            ExpiringCertificate = "Microsoft Corporation KEK CA 2011"
            ExpirationDate = "June 2026"
            NewCertificate = "Microsoft Corporation KEK CA 2023"
            StoringLocation = "Stored in KEK"
            Purpose = "Signs updates to DB and DBX"
            Status = $certInfo.KEK_Status
        },
        [PSCustomObject]@{
            ExpiringCertificate = "Microsoft Windows Production PCA 2011"
            ExpirationDate = "Oct 2026"
            NewCertificate = "Windows UEFI CA 2023"
            StoringLocation = "Stored in DB"
            Purpose = "Used for signing the Windows boot loader"
            Status = $certInfo.DB_Windows_Status
        },
        [PSCustomObject]@{
            ExpiringCertificate = "Microsoft UEFI CA 2011"
            ExpirationDate = "June 2026"
            NewCertificate = "Microsoft UEFI CA 2023"
            StoringLocation = "Stored in DB"
            Purpose = "Signs third-party boot loaders and EFI applications"
            Status = $certInfo.DB_UEFI_Status
        },
        [PSCustomObject]@{
            ExpiringCertificate = "Microsoft UEFI CA 2011"
            ExpirationDate = "June 2026"
            NewCertificate = "Microsoft Option ROM UEFI CA 2023"
            StoringLocation = "Stored in DB"
            Purpose = "Signs third-party option ROMs"
            Status = if ($certInfo.DB_String -match 'Microsoft Option ROM UEFI CA 2023') { "Updated" } else { "Not Found" }
        }
    )
    
    # Display table format
    Write-Host "`nCertificate Overview Table:" -ForegroundColor Cyan
    Write-Host ("=" * 170) -ForegroundColor Gray
    
    # Table header
    $headerFormat = "{0,-40} {1,-15} {2,-40} {3,-15} {4,-50}"
    Write-Host ($headerFormat -f "Expiring Certificate", "Expiration", "New Certificate", "Storing Location", "Purpose") -ForegroundColor Yellow
    Write-Host ("=" * 170) -ForegroundColor Gray
    
    # Table rows
    foreach ($cert in $certificateData) {
        $expiringColor = "Red"
        $newColor = if ($cert.Status -eq "Updated") { "Green" } else { "Yellow" }
        $locationColor = "Cyan"
        $purposeColor = "White"
        
        # Split the row to apply colors to each column
        $parts = @(
            $cert.ExpiringCertificate.PadRight(40),
            $cert.ExpirationDate.PadRight(15),
            $cert.NewCertificate.PadRight(40),
            $cert.StoringLocation.PadRight(15),
            $cert.Purpose.PadRight(50)
        )
        
        Write-Host $parts[0] -ForegroundColor $expiringColor -NoNewline
        Write-Host $parts[1] -ForegroundColor $expiringColor -NoNewline
        Write-Host $parts[2] -ForegroundColor $newColor -NoNewline
        Write-Host $parts[3] -ForegroundColor $locationColor -NoNewline
        Write-Host $parts[4] -ForegroundColor $purposeColor
    }
    
    Write-Host ("=" * 170) -ForegroundColor Gray
    
    # Display the certificate information in a structured format
    Write-Host "`nDetailed Certificate Information:" -ForegroundColor Yellow
    Write-Host "================================================================" -ForegroundColor Gray
    
    $counter = 1
    foreach ($cert in $certificateData) {
        Write-Host "$counter. Certificate Update Details:" -ForegroundColor White
        Write-Host "   Expiring Certificate:  " -NoNewline -ForegroundColor Gray
        Write-Host "$($cert.ExpiringCertificate)" -ForegroundColor Red
        Write-Host "   Expiration Date:       " -NoNewline -ForegroundColor Gray
        Write-Host "$($cert.ExpirationDate)" -ForegroundColor Yellow
        Write-Host "   New Certificate:       " -NoNewline -ForegroundColor Gray
        Write-Host "$($cert.NewCertificate)" -ForegroundColor Green
        Write-Host "   Storing Location:      " -NoNewline -ForegroundColor Gray
        Write-Host "$($cert.StoringLocation)" -ForegroundColor Cyan
        Write-Host "   Purpose:               " -NoNewline -ForegroundColor Gray
        Write-Host "$($cert.Purpose)" -ForegroundColor Gray
        Write-Host "   Status:                " -NoNewline -ForegroundColor Gray
        $statusColor = if ($cert.Status -eq "Updated") { "Green" } else { "Yellow" }
        Write-Host "$($cert.Status)" -ForegroundColor $statusColor
        Write-Host ""
        $counter++
    }
    
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

function Show-SecureBootTasks {
    Write-Host "================================================================" -ForegroundColor Gray
    Write-Host "SECURE BOOT SCHEDULED TASKS" -ForegroundColor Yellow
    Write-Host "================================================================" -ForegroundColor Gray
    
    # Define the expected Secure Boot task path and name
    $expectedTaskPath = "\Microsoft\Windows\PI\"
    $expectedTaskName = "Secure-Boot-Update"
    
    try {
        # Look for Secure Boot related tasks
        Write-Host "Searching for Secure Boot related scheduled tasks..." -ForegroundColor Cyan
        
        $secureBootTasks = Get-ScheduledTask | Where-Object { 
            $_.TaskName -like "*Secure*Boot*" #-or 
            #$_.TaskName -like "*UEFI*" -or
            #$_.TaskPath -like "*PI*" 
        }
        
        if ($secureBootTasks) {
            Write-Host "Found $($secureBootTasks.Count) Secure Boot related task(s):" -ForegroundColor Green
            Write-Host ""
            
            foreach ($task in $secureBootTasks) {
                Write-Host "Task Name: $($task.TaskName)" -ForegroundColor White
                Write-Host "  Path: $($task.TaskPath)" -ForegroundColor Gray
                Write-Host "  State: $($task.State)" -ForegroundColor $(if ($task.State -eq 'Ready') { 'Green' } elseif ($task.State -eq 'Running') { 'Yellow' } else { 'Red' })
                Write-Host "  Description: $($task.Description)" -ForegroundColor Gray
                
                # Get additional task info using proper path/name separation
                try {
                    $taskInfo = Get-ScheduledTaskInfo -TaskPath $task.TaskPath -TaskName $task.TaskName -ErrorAction SilentlyContinue
                    if ($taskInfo) {
                        Write-Host "  Last Run: $($taskInfo.LastRunTime)" -ForegroundColor Gray
                        Write-Host "  Last Result: $($taskInfo.LastTaskResult)" -ForegroundColor Gray
                        Write-Host "  Next Run: $($taskInfo.NextRunTime)" -ForegroundColor Gray
                    }
                } catch {
                    Write-Host "  (Unable to get additional task info)" -ForegroundColor Gray
                }
                Write-Host ""
            }
            
            # Specifically check for the main Secure Boot update task using expected path and name
            $mainTask = $secureBootTasks | Where-Object { 
                $_.TaskName -eq $expectedTaskName -and $_.TaskPath -eq $expectedTaskPath 
            }
            if ($mainTask) {
                Write-Host "✓ Main Secure Boot update task found and available" -ForegroundColor Green
                Write-Host "  Expected Path: $expectedTaskPath" -ForegroundColor Gray
                Write-Host "  Expected Name: $expectedTaskName" -ForegroundColor Gray
                if ($mainTask.State -eq 'Ready') {
                    Write-Host "✓ Task is ready to run" -ForegroundColor Green
                } elseif ($mainTask.State -eq 'Running') {
                    Write-Host "⚠ Task is currently running" -ForegroundColor Yellow
                } else {
                    Write-Host "⚠ Task state: $($mainTask.State)" -ForegroundColor Yellow
                }
            } else {
                Write-Host "⚠ Main 'Secure-Boot-Update' task not found at expected location" -ForegroundColor Yellow
                Write-Host "  Expected: $expectedTaskPath$expectedTaskName" -ForegroundColor Gray
                
                # Check if a similar task exists with different path/name
                $similarTask = $secureBootTasks | Where-Object { $_.TaskName -eq $expectedTaskName }
                if ($similarTask) {
                    Write-Host "  Found similar task at: $($similarTask.TaskPath)$($similarTask.TaskName)" -ForegroundColor Yellow
                }
            }
            
        } else {
            Write-Host "⚠ No Secure Boot related scheduled tasks found" -ForegroundColor Yellow
            Write-Host "This may indicate:" -ForegroundColor Gray
            Write-Host "  - System doesn't support Secure Boot certificate updates" -ForegroundColor Gray
            Write-Host "  - Windows updates haven't created the tasks yet" -ForegroundColor Gray
            Write-Host "  - Tasks may be in a different location" -ForegroundColor Gray
        }
        
        # Additional check: Try to directly access the expected task
        Write-Host ""
        Write-Host "Direct task check:" -ForegroundColor Cyan
        try {
            $directTask = Get-ScheduledTask -TaskPath $expectedTaskPath -TaskName $expectedTaskName -ErrorAction Stop
            Write-Host "✓ Direct access successful: $($directTask.TaskPath)$($directTask.TaskName)" -ForegroundColor Green
            Write-Host "  State: $($directTask.State)" -ForegroundColor Green
        } catch {
            Write-Host "✗ Direct access failed: Task not found at $expectedTaskPath$expectedTaskName" -ForegroundColor Red
            Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Gray
        }
        
    } catch {
        Write-Host "✗ Error searching for scheduled tasks: $_" -ForegroundColor Red
    }
    
    Write-Host "================================================================" -ForegroundColor Gray
}
    
Write-Host "================================================================" -ForegroundColor Gray

# Main execution loop
do {
    Show-Menu
    $choice = Read-Host "Select a task (1-11)"

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
                # Show Secure Boot scheduled tasks
                Show-SecureBootTasks
            }
            7 {
                # Set registry key for certificate update
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot" -Name "AvailableUpdates" -Value 0x40
                Write-Host "Registry key set successfully to apply the update" -ForegroundColor Green
    
                # Prompt to execute task 8 automatically or manually
                $task8Choice = Read-Host "Do you want to execute task 8 (Run scheduled task) automatically (Y) or manually (M)?"
                if ($task8Choice -eq 'Y' -or $task8Choice -eq 'y') {
                    # Run scheduled task to update Secure Boot DB with the new CA
                    RunScheduledTask
                } elseif ($task8Choice -eq 'M' -or $task8Choice -eq 'm') {
                    Write-Host "You can manually execute task 8 from the menu."
                } else {
                    Write-Host "Invalid choice. Task 8 will not be executed."
                }
            }
            8 {
                # Run scheduled task manually to update Secure Boot DB with the new CA
                RunScheduledTask
            }
            9 {
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
            10 {
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
            11 {
                # Exit
                Write-Host "Exiting Secure Boot Update Menu."
            }
            default {
                # Invalid selection
                Write-Host "Invalid selection. Please enter a number between 1 and 11."
            }
        }
    }
    catch {
        # Catch any errors and display them
        Write-Host "An error occurred: $_" -ForegroundColor Red
    }    

    if ($choice -ne 11) {
        # Prompt to continue
        $null = Read-Host "Press Enter to continue..."
    }

} while ($choice -ne 11)