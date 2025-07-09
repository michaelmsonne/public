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
    Write-Host ""
    Write-Host "********** Secure Boot Update Menu for UEFI CA 2023 **********" -ForegroundColor Cyan
    #Write-Host "*** Certificate Expiration: June 2026 - Update Required ***" -ForegroundColor Red
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
    Write-Host "7. Set registry key for certificate update (DB update)"
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
        Write-Host "[+] Task found: $($task.TaskName)" -ForegroundColor Green
        Write-Host "  Full Path: $($task.TaskPath)$($task.TaskName)" -ForegroundColor Gray
        Write-Host "  Current State: $($task.State)" -ForegroundColor Gray
        
        # Check if task is already running
        if ($task.State -eq 'Running') {
            Write-Host "[!] Task is already running. Waiting for it to complete..." -ForegroundColor Yellow
        } else {
            # Start the scheduled task using separate path and name
            Write-Host "Starting scheduled task..." -ForegroundColor Cyan
            Start-ScheduledTask -TaskPath $taskPath -TaskName $taskName
            Write-Host "[+] Task started successfully" -ForegroundColor Green
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
                Write-Host "[!] Task timeout reached ($timeout seconds). Task may still be running." -ForegroundColor Yellow
                break
            }
            
        } while ($taskState -ne 'Ready')
        
        if ($taskState -eq 'Ready') {
            Write-Host "[+] Scheduled task completed." -ForegroundColor Green
            
            # Check the last run result using separate path and name
            Write-Host "Checking task execution results..." -ForegroundColor Cyan
            $taskInfo = Get-ScheduledTaskInfo -TaskPath $taskPath -TaskName $taskName
            
            Write-Host "Task Execution Details:" -ForegroundColor Yellow
            Write-Host "  Last Run Time: $($taskInfo.LastRunTime)" -ForegroundColor Gray
            Write-Host "  Last Result: $($taskInfo.LastTaskResult)" -ForegroundColor Gray
            Write-Host "  Next Run Time: $($taskInfo.NextRunTime)" -ForegroundColor Gray
            
            if ($taskInfo.LastTaskResult -eq 0) {
                Write-Host "[+] Task completed successfully (Result: $($taskInfo.LastTaskResult))" -ForegroundColor Green
                Write-Host "[+] Secure Boot certificate update process completed" -ForegroundColor Green
            } elseif ($taskInfo.LastTaskResult -eq 267011) {
                Write-Host "[!] Task completed with result: $($taskInfo.LastTaskResult) (Task was terminated)" -ForegroundColor Yellow
            } else {
                Write-Host "[!] Task completed with result code: $($taskInfo.LastTaskResult)" -ForegroundColor Yellow
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
            if ($availableUpdates.AvailableUpdates -eq 0x40) { #DB update
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
        DB_OptionROM_Status = "Not Checked"
        DB_OptionROM_Updated_Found = $false
        OverallStatus = "Unknown"
        CertificateDetails = @()
    }
    
    try {
        # Check KEK (Key Exchange Key)
        Write-Host "> Checking KEK certificates..." -ForegroundColor Cyan
        try {
            $kekData = Get-SecureBootUEFI -Name kek -ErrorAction Stop
            $kekString = [System.Text.Encoding]::ASCII.GetString($kekData.bytes)
            
            # Check for legacy KEK certificate
            if ($kekString -match 'Microsoft Corporation KEK CA 2011') {
                $results.KEK_Legacy_Found = $true
                Write-Host "  [+] Found: Microsoft Corporation KEK CA 2011 (expires June 2026)" -ForegroundColor Yellow
            }
            
            # Check for updated KEK certificate - correct name from Microsoft table
            if ($kekString -match 'Microsoft Corporation KEK 2K CA 2023') {
                $results.KEK_Updated_Found = $true
                Write-Host "  [+] Found: Microsoft Corporation KEK 2K CA 2023 (updated certificate)" -ForegroundColor Green
            }
            
            $results.KEK_Status = if ($results.KEK_Updated_Found) { "Updated" } elseif ($results.KEK_Legacy_Found) { "Legacy - Update Required" } else { "Unknown" }
        } catch {
            $results.KEK_Status = "Error accessing KEK"
            Write-Host "  ✗ Error accessing KEK certificates: $_" -ForegroundColor Red
        }
        
        Write-Host ""
        
        # Check DB (Signature Database)
        Write-Host "> Checking DB certificates..." -ForegroundColor Cyan
        try {
            $dbData = Get-SecureBootUEFI -Name db -ErrorAction Stop
            $dbString = [System.Text.Encoding]::ASCII.GetString($dbData.bytes)
            
            # Check for legacy UEFI certificates
            if ($dbString -match 'Microsoft Corporation UEFI CA 2011') {
                $results.DB_UEFI_Legacy_Found = $true
                Write-Host "  [+] Found: Microsoft Corporation UEFI CA 2011 (expires June 2026)" -ForegroundColor Yellow
            }
            
            # Check for updated UEFI certificates - align with Microsoft table
            if ($dbString -match 'Microsoft Corporation UEFI CA 2023') {
                $results.DB_UEFI_Updated_Found = $true
                Write-Host "  [+] Found: Microsoft Corporation UEFI CA 2023 (updated certificate)" -ForegroundColor Green
            }
            
            if ($dbString -match 'Microsoft Option ROM UEFI CA 2023') {
                Write-Host "  [+] Found: Microsoft Option ROM UEFI CA 2023 (updated certificate)" -ForegroundColor Green
                $results.DB_OptionROM_Updated_Found = $true
            } else {
                $results.DB_OptionROM_Updated_Found = $false
            }
            
            # Check for legacy Windows certificates
            if ($dbString -match 'Microsoft Windows Production PCA 2011') {
                $results.DB_Windows_Legacy_Found = $true
                Write-Host "  [+] Found: Microsoft Windows Production PCA 2011 (expires October 2026)" -ForegroundColor Yellow
            }
            
            # Check for updated Windows certificates
            if ($dbString -match 'Windows UEFI CA 2023') {
                $results.DB_Windows_Updated_Found = $true
                Write-Host "  [+] Found: Windows UEFI CA 2023 (updated certificate)" -ForegroundColor Green
            }
            
            $results.DB_UEFI_Status = if ($results.DB_UEFI_Updated_Found) { "Updated" } elseif ($results.DB_UEFI_Legacy_Found) { "Legacy - Update Required" } else { "Unknown" }
            $results.DB_Windows_Status = if ($results.DB_Windows_Updated_Found) { "Updated" } elseif ($results.DB_Windows_Legacy_Found) { "Legacy - Update Required" } else { "Unknown" }
            $results.DB_OptionROM_Status = if ($results.DB_OptionROM_Updated_Found) { "Updated" } elseif ($results.DB_UEFI_Legacy_Found) { "Legacy - Update Required" } else { "Not Found" }
            
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
        
        # Create detailed certificate information - align with Microsoft table
        $results.CertificateDetails = @(
            [PSCustomObject]@{
                ExpiringCertificate = "Microsoft Corporation KEK CA 2011"
                ExpirationDate = "June 2026"
                NewCertificate = "Microsoft Corporation KEK 2K CA 2023"
                StoringLocation = "Stored in KEK"
                Purpose = "Signs updates to DB and DBX"
                LegacyFound = $results.KEK_Legacy_Found
                UpdatedFound = $results.KEK_Updated_Found
                Status = $results.KEK_Status
            },
            [PSCustomObject]@{
                ExpiringCertificate = "Microsoft Corporation UEFI CA 2011 (or third-party UEFI CA)"
                ExpirationDate = "June 2026"
                NewCertificate = "Microsoft Corporation UEFI CA 2023"
                StoringLocation = "Stored in DB"
                Purpose = "Signs third-party OS and hardware driver components"
                LegacyFound = $results.DB_UEFI_Legacy_Found
                UpdatedFound = $results.DB_UEFI_Updated_Found
                Status = $results.DB_UEFI_Status
            },
            [PSCustomObject]@{
                ExpiringCertificate = "Microsoft Corporation UEFI CA 2011 (or third-party UEFI CA)"
                ExpirationDate = "June 2026"
                NewCertificate = "Microsoft Option ROM UEFI CA 2023"
                StoringLocation = "Stored in DB"
                Purpose = "Signs third-party option ROMs"
                LegacyFound = $results.DB_UEFI_Legacy_Found
                UpdatedFound = $results.DB_OptionROM_Updated_Found
                Status = $results.DB_OptionROM_Status
            },
            [PSCustomObject]@{
                ExpiringCertificate = "Microsoft Windows Production PCA 2011"
                ExpirationDate = "Oct 2026"
                NewCertificate = "Windows UEFI CA 2023"
                StoringLocation = "Stored in DB"
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
    
    # Get current certificate information
    $certInfo = Get-DetailedCertificateInfo
    
    # Display comprehensive certificate information table
    Write-Host "Certificate Update Summary:" -ForegroundColor Yellow
    Write-Host "================================================================" -ForegroundColor Gray
    Write-Host ""
    
    # Certificate data array matching Microsoft table exactly
    $certificateData = @(
        [PSCustomObject]@{
            ExpiringCertificate = "Microsoft Corporation KEK CA 2011"
            ExpirationDate = "June 2026"
            NewCertificate = "Microsoft Corporation KEK 2K CA 2023"
            StoringLocation = "Stored in KEK"
            Purpose = "Signs updates to DB and DBX"
            Status = $certInfo.KEK_Status
        },
        [PSCustomObject]@{
            ExpiringCertificate = "Microsoft Corporation UEFI CA 2011 (or third-party UEFI CA)"
            ExpirationDate = "June 2026"
            NewCertificate = "Microsoft Corporation UEFI CA 2023"
            StoringLocation = "Stored in DB"
            Purpose = "Signs third-party OS and hardware driver components"
            Status = $certInfo.DB_UEFI_Status
        },
        [PSCustomObject]@{
            ExpiringCertificate = "Microsoft Corporation UEFI CA 2011 (or third-party UEFI CA)"
            ExpirationDate = "June 2026"
            NewCertificate = "Microsoft Option ROM UEFI CA 2023"
            StoringLocation = "Stored in DB"
            Purpose = "Signs third-party option ROMs"
            Status = $certInfo.DB_OptionROM_Status
        },
        [PSCustomObject]@{
            ExpiringCertificate = "Microsoft Windows Production PCA 2011"
            ExpirationDate = "Oct 2026"
            NewCertificate = "Windows UEFI CA 2023"
            StoringLocation = "Stored in DB"
            Purpose = "Signs the Windows bootloader and boot components"
            Status = $certInfo.DB_Windows_Status
        }
    )
    
    # Display table format - keeping original names but formatted for console
    Write-Host "`nCertificate Overview Table:" -ForegroundColor Cyan
    Write-Host "================================================================" -ForegroundColor Gray
    Write-Host ""
    
    # Display certificates in a list format instead of table for better readability
    $counter = 1
    foreach ($cert in $certificateData) {
        $statusColor = if ($cert.Status -eq "Updated") { "Green" } 
                      elseif ($cert.Status -like "*Legacy*") { "Yellow" } 
                      else { "Red" }
        
        $statusSymbol = if ($cert.Status -eq "Updated") { "[+]" } 
                       elseif ($cert.Status -like "*Legacy*") { "[!]" } 
                       else { "[-]" }
        
        Write-Host "$counter. " -NoNewline -ForegroundColor White
        Write-Host "Expiring: " -NoNewline -ForegroundColor Gray
        Write-Host "$($cert.ExpiringCertificate)" -ForegroundColor Red
        Write-Host "   Expires: " -NoNewline -ForegroundColor Gray
        Write-Host "$($cert.ExpirationDate)" -NoNewline -ForegroundColor Yellow
        Write-Host " | Location: " -NoNewline -ForegroundColor Gray
        Write-Host "$($cert.StoringLocation)" -NoNewline -ForegroundColor Cyan
        Write-Host " | Status: " -NoNewline -ForegroundColor Gray
        Write-Host "$statusSymbol $($cert.Status)" -ForegroundColor $statusColor
        
        Write-Host "   New Cert: " -NoNewline -ForegroundColor Gray
        Write-Host "$($cert.NewCertificate)" -ForegroundColor Green
        Write-Host "   Purpose:  " -NoNewline -ForegroundColor Gray
        Write-Host "$($cert.Purpose)" -ForegroundColor White
        Write-Host ""
        $counter++
    }
    
    Write-Host "================================================================" -ForegroundColor Gray
    
    # Quick summary
    Write-Host ""
    Write-Host "Summary:" -ForegroundColor Yellow
    
    # Fixed counting logic
    $updatedCount = 0
    $legacyCount = 0
    $notFoundCount = 0
    
    foreach ($cert in $certificateData) {
        switch ($cert.Status) {
            "Updated" { $updatedCount++ }
            "Legacy - Update Required" { $legacyCount++ }
            "Not Found" { $notFoundCount++ }
        }
    }
    
    $totalCount = $certificateData.Count
    
    Write-Host "Total certificates: $totalCount" -ForegroundColor White
    Write-Host "Updated: " -NoNewline -ForegroundColor Gray
    Write-Host "$updatedCount" -ForegroundColor Green
    Write-Host "Legacy (need update): " -NoNewline -ForegroundColor Gray  
    Write-Host "$legacyCount" -ForegroundColor Yellow
    Write-Host "Not found: " -NoNewline -ForegroundColor Gray
    Write-Host "$notFoundCount" -ForegroundColor Red
    Write-Host ""
    
    # Display the certificate information in a structured format with proper alignment
    Write-Host "`nDetailed Certificate Information:" -ForegroundColor Yellow
    Write-Host "================================================================" -ForegroundColor Gray
    
    $counter = 1
    foreach ($cert in $certificateData) {
        Write-Host "$counter. Certificate Update Details:" -ForegroundColor White
        
        # Use consistent field width for better alignment
        Write-Host "   Expiration Date:       " -NoNewline -ForegroundColor Gray
        Write-Host "$($cert.ExpirationDate)" -ForegroundColor Yellow
        
        Write-Host "   Expiring Certificate:  " -NoNewline -ForegroundColor Gray
        Write-Host "$($cert.ExpiringCertificate)" -ForegroundColor Red
        
        Write-Host "   Updated Certificate:   " -NoNewline -ForegroundColor Gray
        Write-Host "$($cert.NewCertificate)" -ForegroundColor Green
        
        Write-Host "   What it does:          " -NoNewline -ForegroundColor Gray
        Write-Host "$($cert.Purpose)" -ForegroundColor White
        
        Write-Host "   Storing Location:      " -NoNewline -ForegroundColor Gray
        # Simplify location display
        $location = if ($cert.StoringLocation -eq "Stored in KEK") { "KEK" } else { "DB" }
        Write-Host "$location" -ForegroundColor Cyan
        
        Write-Host "   Status:                " -NoNewline -ForegroundColor Gray
        $statusColor = switch ($cert.Status) {
            "Updated" { "Green" }
            "Legacy - Update Required" { "Yellow" }  
            "Not Found" { "Red" }
            default { "Gray" }
        }
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
            "Updated" { "[+]" }
            "Legacy - Update Required" { "[!]" }
            "Not Found" { "[?]" }
            default { "[-]" }
        }
        
        Write-Host "$statusSymbol $($cert.StoringLocation) - $($cert.ExpirationDate): " -NoNewline
        Write-Host "$($cert.Status)" -ForegroundColor $statusColor
        Write-Host "   Legacy Found: $($cert.LegacyFound) | Updated Found: $($cert.UpdatedFound)" -ForegroundColor Gray
    }
    
    Write-Host ""
    Write-Host "Recommendations:" -ForegroundColor Yellow
    Write-Host "================================================================" -ForegroundColor Gray
    if ($certInfo.OverallStatus -eq "Fully Updated") {
        Write-Host "[+] All certificates are up to date. No action required." -ForegroundColor Green
    } elseif ($certInfo.OverallStatus -eq "Partial Update - Action Required") {
        Write-Host "[!] Some certificates need updating. Use the update process (options 6-9) to complete the update." -ForegroundColor Yellow
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
                Write-Host "[+] Main Secure Boot update task found and available" -ForegroundColor Green
                Write-Host "  Expected Path: $expectedTaskPath" -ForegroundColor Gray
                Write-Host "  Expected Name: $expectedTaskName" -ForegroundColor Gray
                if ($mainTask.State -eq 'Ready') {
                    Write-Host "[+] Task is ready to run" -ForegroundColor Green
                } elseif ($mainTask.State -eq 'Running') {
                    Write-Host "[!] Task is currently running" -ForegroundColor Yellow
                } else {
                    Write-Host "[!] Task state: $($mainTask.State)" -ForegroundColor Yellow
                }
            } else {
                Write-Host "[!] Main 'Secure-Boot-Update' task not found at expected location" -ForegroundColor Yellow
                Write-Host "  Expected: $expectedTaskPath$expectedTaskName" -ForegroundColor Gray
                
                # Check if a similar task exists with different path/name
                $similarTask = $secureBootTasks | Where-Object { $_.TaskName -eq $expectedTaskName }
                if ($similarTask) {
                    Write-Host "  Found similar task at: $($similarTask.TaskPath)$($similarTask.TaskName)" -ForegroundColor Yellow
                }
            }
            
        } else {
            Write-Host "[!] No Secure Boot related scheduled tasks found" -ForegroundColor Yellow
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
            Write-Host "[+] Direct access successful: $($directTask.TaskPath)$($directTask.TaskName)" -ForegroundColor Green
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
    Write-Host ""
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
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot" -Name "AvailableUpdates" -Value 0x40 #DB update
                Write-Host "Registry key set successfully to apply the update for DB" -ForegroundColor Green
    
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
                        Write-Host "[+] All certificates have been successfully updated" -ForegroundColor Green
                        Write-Host "[+] Your system is prepared for the June 2026 certificate expiration" -ForegroundColor Green
                    }
                    "Partial Update - Action Required" { 
                        Write-Host $certInfo.OverallStatus -ForegroundColor Yellow 
                        Write-Host "[!] Some certificates still need updating - please retry the update process" -ForegroundColor Yellow
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
                        "Updated" { "[+]" }
                        "Legacy - Update Required" { "[!]" }
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
# SIG # Begin signature block
# MIIudgYJKoZIhvcNAQcCoIIuZzCCLmMCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAGVER/oRVIjl2v
# zcsHFZQYFGfKngp5KOo4kglAe6ZhzqCCEd8wggVvMIIEV6ADAgECAhBI/JO0YFWU
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
# gf9SsIAod1Dx9THs2qkXIwyf5lTJBvPHLRqxs/k+Mn70AUiyj50/JYMxghvtMIIb
# 6QIBATBoMFQxCzAJBgNVBAYTAkdCMRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQx
# KzApBgNVBAMTIlNlY3RpZ28gUHVibGljIENvZGUgU2lnbmluZyBDQSBSMzYCEBHh
# oIZkh66CYIKNKPBResYwDQYJYIZIAWUDBAIBBQCgfDAQBgorBgEEAYI3AgEMMQIw
# ADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYK
# KwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgwWSvZew59DX9KsiZvj+Z3VxJK7Yx
# 7CK2nJrvF68UguswDQYJKoZIhvcNAQEBBQAEggIAp1Q9tHJ7e5LvVMUQyz9rD2FX
# SaIWMxmzeksEdoz18LKZoF5a4wUbmIo/aGlg3Nm1DyNx3iSKzmk4XfaXL1hYwzad
# yCsGiVXb5JZPKoU8laV6NR2WnPirdSPPcsPNm8iWRK57S6BlwYC2rBRlRVeHwQxn
# aWRs5lJN6PUT1HBW9lXSxhUh+Ysph8UlukAGGaYRMX5NC0elldE31wwQoN24I7sn
# vZdnhF8TttaS+x86gHQTQne3PoZ58ZN+EnVwV2rBJ3BHqFzWMJ7D9cpwB8bzEHeO
# dO6kPrzQoU9vxcAQ9gXiO+zZlKk+SjPzFumiHqjw50BM3DQK4APIcQDQSIihOXxZ
# IxqeJJlZcc9ul79dhU9ZkZjcHbl6p4MDKsf+GZixZFQja59muYViof0YakIMPd+u
# /+GUL8Z0iu6OSE4LBcdlIqghT3PXnpm6xNLfjqxQQ8DMtNvbK7pYccqWSGdW0GIf
# Zs5T6Smz7EDn4cNrJb8MJMQcIlpBZ0mZhopligtf3IBg3pOkNdsshVxFeHJuUhKX
# VeZtIw87r2trPWGKQs/00ZT8URdL/oMjBTdDSa2Q9RGdNtWLhZrmC9cm3b6c6Lvb
# vqEjlgLfakcsG4dfPpSEcQtQRD18NcUAwlt3q5OIFsGlbGc1YJ2VKchBFfXqctTq
# WEOBAU+jZvDuCUcBDBShghjYMIIY1AYKKwYBBAGCNwMDATGCGMQwghjABgkqhkiG
# 9w0BBwKgghixMIIYrQIBAzEPMA0GCWCGSAFlAwQCAgUAMIH4BgsqhkiG9w0BCRAB
# BKCB6ASB5TCB4gIBAQYKKwYBBAGyMQIBATAxMA0GCWCGSAFlAwQCAQUABCAjmZn0
# CmG3J3pYbllzh1p3+1k5Id45hrLfsY1vveaSjwIVAPndcUzbInbl0NBvbNgyJroi
# m5ILGA8yMDI1MDcwOTIwMTIxMFqgdqR0MHIxCzAJBgNVBAYTAkdCMRcwFQYDVQQI
# Ew5XZXN0IFlvcmtzaGlyZTEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMTAwLgYD
# VQQDEydTZWN0aWdvIFB1YmxpYyBUaW1lIFN0YW1waW5nIFNpZ25lciBSMzagghME
# MIIGYjCCBMqgAwIBAgIRAKQpO24e3denNAiHrXpOtyQwDQYJKoZIhvcNAQEMBQAw
# VTELMAkGA1UEBhMCR0IxGDAWBgNVBAoTD1NlY3RpZ28gTGltaXRlZDEsMCoGA1UE
# AxMjU2VjdGlnbyBQdWJsaWMgVGltZSBTdGFtcGluZyBDQSBSMzYwHhcNMjUwMzI3
# MDAwMDAwWhcNMzYwMzIxMjM1OTU5WjByMQswCQYDVQQGEwJHQjEXMBUGA1UECBMO
# V2VzdCBZb3Jrc2hpcmUxGDAWBgNVBAoTD1NlY3RpZ28gTGltaXRlZDEwMC4GA1UE
# AxMnU2VjdGlnbyBQdWJsaWMgVGltZSBTdGFtcGluZyBTaWduZXIgUjM2MIICIjAN
# BgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA04SV9G6kU3jyPRBLeBIHPNyUgVNn
# YayfsGOyYEXrn3+SkDYTLs1crcw/ol2swE1TzB2aR/5JIjKNf75QBha2Ddj+4NEP
# KDxHEd4dEn7RTWMcTIfm492TW22I8LfH+A7Ehz0/safc6BbsNBzjHTt7FngNfhfJ
# oYOrkugSaT8F0IzUh6VUwoHdYDpiln9dh0n0m545d5A5tJD92iFAIbKHQWGbCQNY
# plqpAFasHBn77OqW37P9BhOASdmjp3IijYiFdcA0WQIe60vzvrk0HG+iVcwVZjz+
# t5OcXGTcxqOAzk1frDNZ1aw8nFhGEvG0ktJQknnJZE3D40GofV7O8WzgaAnZmoUn
# 4PCpvH36vD4XaAF2CjiPsJWiY/j2xLsJuqx3JtuI4akH0MmGzlBUylhXvdNVXcjA
# uIEcEQKtOBR9lU4wXQpISrbOT8ux+96GzBq8TdbhoFcmYaOBZKlwPP7pOp5Mzx/U
# MhyBA93PQhiCdPfIVOCINsUY4U23p4KJ3F1HqP3H6Slw3lHACnLilGETXRg5X/Fp
# 8G8qlG5Y+M49ZEGUp2bneRLZoyHTyynHvFISpefhBCV0KdRZHPcuSL5OAGWnBjAl
# RtHvsMBrI3AAA0Tu1oGvPa/4yeeiAyu+9y3SLC98gDVbySnXnkujjhIh+oaatsk/
# oyf5R2vcxHahajMCAwEAAaOCAY4wggGKMB8GA1UdIwQYMBaAFF9Y7UwxeqJhQo1S
# gLqzYZcZojKbMB0GA1UdDgQWBBSIYYyhKjdkgShgoZsx0Iz9LALOTzAOBgNVHQ8B
# Af8EBAMCBsAwDAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDBK
# BgNVHSAEQzBBMDUGDCsGAQQBsjEBAgEDCDAlMCMGCCsGAQUFBwIBFhdodHRwczov
# L3NlY3RpZ28uY29tL0NQUzAIBgZngQwBBAIwSgYDVR0fBEMwQTA/oD2gO4Y5aHR0
# cDovL2NybC5zZWN0aWdvLmNvbS9TZWN0aWdvUHVibGljVGltZVN0YW1waW5nQ0FS
# MzYuY3JsMHoGCCsGAQUFBwEBBG4wbDBFBggrBgEFBQcwAoY5aHR0cDovL2NydC5z
# ZWN0aWdvLmNvbS9TZWN0aWdvUHVibGljVGltZVN0YW1waW5nQ0FSMzYuY3J0MCMG
# CCsGAQUFBzABhhdodHRwOi8vb2NzcC5zZWN0aWdvLmNvbTANBgkqhkiG9w0BAQwF
# AAOCAYEAAoE+pIZyUSH5ZakuPVKK4eWbzEsTRJOEjbIu6r7vmzXXLpJx4FyGmcqn
# FZoa1dzx3JrUCrdG5b//LfAxOGy9Ph9JtrYChJaVHrusDh9NgYwiGDOhyyJ2zRy3
# +kdqhwtUlLCdNjFjakTSE+hkC9F5ty1uxOoQ2ZkfI5WM4WXA3ZHcNHB4V42zi7Jk
# 3ktEnkSdViVxM6rduXW0jmmiu71ZpBFZDh7Kdens+PQXPgMqvzodgQJEkxaION5X
# RCoBxAwWwiMm2thPDuZTzWp/gUFzi7izCmEt4pE3Kf0MOt3ccgwn4Kl2FIcQaV55
# nkjv1gODcHcD9+ZVjYZoyKTVWb4VqMQy/j8Q3aaYd/jOQ66Fhk3NWbg2tYl5jhQC
# uIsE55Vg4N0DUbEWvXJxtxQQaVR5xzhEI+BjJKzh3TQ026JxHhr2fuJ0mV68AluF
# r9qshgwS5SpN5FFtaSEnAwqZv3IS+mlG50rK7W3qXbWwi4hmpylUfygtYLEdLQuk
# NEX1jiOKMIIGFDCCA/ygAwIBAgIQeiOu2lNplg+RyD5c9MfjPzANBgkqhkiG9w0B
# AQwFADBXMQswCQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMS4w
# LAYDVQQDEyVTZWN0aWdvIFB1YmxpYyBUaW1lIFN0YW1waW5nIFJvb3QgUjQ2MB4X
# DTIxMDMyMjAwMDAwMFoXDTM2MDMyMTIzNTk1OVowVTELMAkGA1UEBhMCR0IxGDAW
# BgNVBAoTD1NlY3RpZ28gTGltaXRlZDEsMCoGA1UEAxMjU2VjdGlnbyBQdWJsaWMg
# VGltZSBTdGFtcGluZyBDQSBSMzYwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGK
# AoIBgQDNmNhDQatugivs9jN+JjTkiYzT7yISgFQ+7yavjA6Bg+OiIjPm/N/t3nC7
# wYUrUlY3mFyI32t2o6Ft3EtxJXCc5MmZQZ8AxCbh5c6WzeJDB9qkQVa46xiYEpc8
# 1KnBkAWgsaXnLURoYZzksHIzzCNxtIXnb9njZholGw9djnjkTdAA83abEOHQ4ujO
# GIaBhPXG2NdV8TNgFWZ9BojlAvflxNMCOwkCnzlH4oCw5+4v1nssWeN1y4+RlaOy
# wwRMUi54fr2vFsU5QPrgb6tSjvEUh1EC4M29YGy/SIYM8ZpHadmVjbi3Pl8hJiTW
# w9jiCKv31pcAaeijS9fc6R7DgyyLIGflmdQMwrNRxCulVq8ZpysiSYNi79tw5RHW
# ZUEhnRfs/hsp/fwkXsynu1jcsUX+HuG8FLa2BNheUPtOcgw+vHJcJ8HnJCrcUWhd
# Fczf8O+pDiyGhVYX+bDDP3GhGS7TmKmGnbZ9N+MpEhWmbiAVPbgkqykSkzyYVr15
# OApZYK8CAwEAAaOCAVwwggFYMB8GA1UdIwQYMBaAFPZ3at0//QET/xahbIICL9AK
# PRQlMB0GA1UdDgQWBBRfWO1MMXqiYUKNUoC6s2GXGaIymzAOBgNVHQ8BAf8EBAMC
# AYYwEgYDVR0TAQH/BAgwBgEB/wIBADATBgNVHSUEDDAKBggrBgEFBQcDCDARBgNV
# HSAECjAIMAYGBFUdIAAwTAYDVR0fBEUwQzBBoD+gPYY7aHR0cDovL2NybC5zZWN0
# aWdvLmNvbS9TZWN0aWdvUHVibGljVGltZVN0YW1waW5nUm9vdFI0Ni5jcmwwfAYI
# KwYBBQUHAQEEcDBuMEcGCCsGAQUFBzAChjtodHRwOi8vY3J0LnNlY3RpZ28uY29t
# L1NlY3RpZ29QdWJsaWNUaW1lU3RhbXBpbmdSb290UjQ2LnA3YzAjBggrBgEFBQcw
# AYYXaHR0cDovL29jc3Auc2VjdGlnby5jb20wDQYJKoZIhvcNAQEMBQADggIBABLX
# eyCtDjVYDJ6BHSVY/UwtZ3Svx2ImIfZVVGnGoUaGdltoX4hDskBMZx5NY5L6SCcw
# DMZhHOmbyMhyOVJDwm1yrKYqGDHWzpwVkFJ+996jKKAXyIIaUf5JVKjccev3w16m
# NIUlNTkpJEor7edVJZiRJVCAmWAaHcw9zP0hY3gj+fWp8MbOocI9Zn78xvm9XKGB
# p6rEs9sEiq/pwzvg2/KjXE2yWUQIkms6+yslCRqNXPjEnBnxuUB1fm6bPAV+Tsr/
# Qrd+mOCJemo06ldon4pJFbQd0TQVIMLv5koklInHvyaf6vATJP4DfPtKzSBPkKlO
# tyaFTAjD2Nu+di5hErEVVaMqSVbfPzd6kNXOhYm23EWm6N2s2ZHCHVhlUgHaC4AC
# MRCgXjYfQEDtYEK54dUwPJXV7icz0rgCzs9VI29DwsjVZFpO4ZIVR33LwXyPDbYF
# kLqYmgHjR3tKVkhh9qKV2WCmBuC27pIOx6TYvyqiYbntinmpOqh/QPAnhDgexKG9
# GX/n1PggkGi9HCapZp8fRwg8RftwS21Ln61euBG0yONM6noD2XQPrFwpm3GcuqJM
# f0o8LLrFkSLRQNwxPDDkWXhW+gZswbaiie5fd/W2ygcto78XCSPfFWveUOSZ5SqK
# 95tBO8aTHmEa4lpJVD7HrTEn9jb1EGvxOb1cnn0CMIIGgjCCBGqgAwIBAgIQNsKw
# vXwbOuejs902y8l1aDANBgkqhkiG9w0BAQwFADCBiDELMAkGA1UEBhMCVVMxEzAR
# BgNVBAgTCk5ldyBKZXJzZXkxFDASBgNVBAcTC0plcnNleSBDaXR5MR4wHAYDVQQK
# ExVUaGUgVVNFUlRSVVNUIE5ldHdvcmsxLjAsBgNVBAMTJVVTRVJUcnVzdCBSU0Eg
# Q2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMjEwMzIyMDAwMDAwWhcNMzgwMTE4
# MjM1OTU5WjBXMQswCQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVk
# MS4wLAYDVQQDEyVTZWN0aWdvIFB1YmxpYyBUaW1lIFN0YW1waW5nIFJvb3QgUjQ2
# MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAiJ3YuUVnnR3d6LkmgZpU
# VMB8SQWbzFoVD9mUEES0QUCBdxSZqdTkdizICFNeINCSJS+lV1ipnW5ihkQyC0cR
# LWXUJzodqpnMRs46npiJPHrfLBOifjfhpdXJ2aHHsPHggGsCi7uE0awqKggE/LkY
# w3sqaBia67h/3awoqNvGqiFRJ+OTWYmUCO2GAXsePHi+/JUNAax3kpqstbl3vcTd
# OGhtKShvZIvjwulRH87rbukNyHGWX5tNK/WABKf+Gnoi4cmisS7oSimgHUI0Wn/4
# elNd40BFdSZ1EwpuddZ+Wr7+Dfo0lcHflm/FDDrOJ3rWqauUP8hsokDoI7D/yUVI
# 9DAE/WK3Jl3C4LKwIpn1mNzMyptRwsXKrop06m7NUNHdlTDEMovXAIDGAvYynPt5
# lutv8lZeI5w3MOlCybAZDpK3Dy1MKo+6aEtE9vtiTMzz/o2dYfdP0KWZwZIXbYsT
# Ilg1YIetCpi5s14qiXOpRsKqFKqav9R1R5vj3NgevsAsvxsAnI8Oa5s2oy25qhso
# BIGo/zi6GpxFj+mOdh35Xn91y72J4RGOJEoqzEIbW3q0b2iPuWLA911cRxgY5SJY
# ubvjay3nSMbBPPFsyl6mY4/WYucmyS9lo3l7jk27MAe145GWxK4O3m3gEFEIkv7k
# RmefDR7Oe2T1HxAnICQvr9sCAwEAAaOCARYwggESMB8GA1UdIwQYMBaAFFN5v1qq
# K0rPVIDh2JvAnfKyA2bLMB0GA1UdDgQWBBT2d2rdP/0BE/8WoWyCAi/QCj0UJTAO
# BgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zATBgNVHSUEDDAKBggrBgEF
# BQcDCDARBgNVHSAECjAIMAYGBFUdIAAwUAYDVR0fBEkwRzBFoEOgQYY/aHR0cDov
# L2NybC51c2VydHJ1c3QuY29tL1VTRVJUcnVzdFJTQUNlcnRpZmljYXRpb25BdXRo
# b3JpdHkuY3JsMDUGCCsGAQUFBwEBBCkwJzAlBggrBgEFBQcwAYYZaHR0cDovL29j
# c3AudXNlcnRydXN0LmNvbTANBgkqhkiG9w0BAQwFAAOCAgEADr5lQe1oRLjlocXU
# EYfktzsljOt+2sgXke3Y8UPEooU5y39rAARaAdAxUeiX1ktLJ3+lgxtoLQhn5cFb
# 3GF2SSZRX8ptQ6IvuD3wz/LNHKpQ5nX8hjsDLRhsyeIiJsms9yAWnvdYOdEMq1W6
# 1KE9JlBkB20XBee6JaXx4UBErc+YuoSb1SxVf7nkNtUjPfcxuFtrQdRMRi/fInV/
# AobE8Gw/8yBMQKKaHt5eia8ybT8Y/Ffa6HAJyz9gvEOcF1VWXG8OMeM7Vy7Bs6mS
# IkYeYtddU1ux1dQLbEGur18ut97wgGwDiGinCwKPyFO7ApcmVJOtlw9FVJxw/mL1
# TbyBns4zOgkaXFnnfzg4qbSvnrwyj1NiurMp4pmAWjR+Pb/SIduPnmFzbSN/G8re
# ZCL4fvGlvPFk4Uab/JVCSmj59+/mB2Gn6G/UYOy8k60mKcmaAZsEVkhOFuoj4we8
# CYyaR9vd9PGZKSinaZIkvVjbH/3nlLb0a7SBIkiRzfPfS9T+JesylbHa1LtRV9U/
# 7m0q7Ma2CQ/t392ioOssXW7oKLdOmMBl14suVFBmbzrt5V5cQPnwtd3UOTpS9oCG
# +ZZheiIvPgkDmA8FzPsnfXW5qHELB43ET7HHFHeRPRYrMBKjkb8/IN7Po0d0hQoF
# 4TeMM+zYAJzoKQnVKOLg8pZVPT8xggSSMIIEjgIBATBqMFUxCzAJBgNVBAYTAkdC
# MRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQxLDAqBgNVBAMTI1NlY3RpZ28gUHVi
# bGljIFRpbWUgU3RhbXBpbmcgQ0EgUjM2AhEApCk7bh7d16c0CIetek63JDANBglg
# hkgBZQMEAgIFAKCCAfkwGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMBwGCSqG
# SIb3DQEJBTEPFw0yNTA3MDkyMDEyMTBaMD8GCSqGSIb3DQEJBDEyBDDV8yIe9Zpa
# NqUXlWkmvRqqEKFNm//pZ4ccsXcRlwobzB4xtKMWOQ7mQGoFXTHr65YwggF6Bgsq
# hkiG9w0BCRACDDGCAWkwggFlMIIBYTAWBBQ4yRSBEES03GY+k9R0S4FBhqm1sTCB
# hwQUxq5U5HiG8Xw9VRJIjGnDSnr5wt0wbzBbpFkwVzELMAkGA1UEBhMCR0IxGDAW
# BgNVBAoTD1NlY3RpZ28gTGltaXRlZDEuMCwGA1UEAxMlU2VjdGlnbyBQdWJsaWMg
# VGltZSBTdGFtcGluZyBSb290IFI0NgIQeiOu2lNplg+RyD5c9MfjPzCBvAQUhT1j
# LZOCgmF80JA1xJHeksFC2scwgaMwgY6kgYswgYgxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpOZXcgSmVyc2V5MRQwEgYDVQQHEwtKZXJzZXkgQ2l0eTEeMBwGA1UEChMV
# VGhlIFVTRVJUUlVTVCBOZXR3b3JrMS4wLAYDVQQDEyVVU0VSVHJ1c3QgUlNBIENl
# cnRpZmljYXRpb24gQXV0aG9yaXR5AhA2wrC9fBs656Oz3TbLyXVoMA0GCSqGSIb3
# DQEBAQUABIICAJPAH1jJ+97TBHEWtAj2NdF5P9m/0QS5Mk4nQ1cJMy5RWDjNKSBV
# 43ckOUH+3ucCzKT7pRWWjwp27qAT3v0FeV/2GilKPCopg59jNNa1h/FNCHdW9Yhh
# MdxwazBD4HVPZ7rm5YEb533GgEj5xgxEUEEeajVOI8GWoO21gp1WiIx1gTUMrhqe
# BkWWNK5SoX0cNIl5p5p+4/hYEON3ExiCztGGmZKpau5zigTH8ZPU4p/BfUFgNcyi
# jM8GsUJpOpDo+39EHUGZAax9zEh4nwOkKP2Ry5JZFgO6iebIgFZB8x2UI9dqdbi9
# nL5v4er2fJw3xsdDIT/5QHgMIxgufCdTV03VKWkhMK4evIBMJTxgPKUfLZA/wpn6
# BHRg37PvN8YFrbYEru1Kno+sFlU016eMBnJ5lpSPLdY32JFvEymk22999Ne7IEvl
# NceDQnFflN/zEhkdAznI6du/JCPhFsmb39Rba5vGpDc7DGcLEZvQMOTVfP5+rSK/
# /t9vwsFyFX4gFM6l91vYnb05pQ9ez1tm1W9llXuzF+WiTKpaUDauaHOrGGdnv8mA
# ZOaqkOYrzt6Rd8FC5se8a/9vB1SEG8riNes+0LMmqCo1ppV7r7k4glFtaF59wqT3
# kGl3ILyEVigQDsU59XduGwZnD+fzfEJi/JdpX2yiFSposeHY7ISCGCpt
# SIG # End signature block
