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

    .INFO
        In the coming months, Microsoft will be rolling out updated Secure Boot certificates needed to ensure a secure startup environment of Windows.
        Current certificates will start expiring in June 2026 on all Windows systems released since 2012, except for 2025 Copilot+ PCs.
        This also affects third-party operating systems. Start by checking on the latest available firmware from original equipment manufacturers (OEMs) and enabling Windows diagnostic data. 

        How this will affect your organization: 
            Most supported Windows systems released since 2012, including the long-term servicing channel (LTSC), are affected.
            Not affected are Copilot+ PCs released in 2025. Affected third-party OS includes MacOS. However, it’s outside the scope of Microsoft support.
            For Linux systems dual booting with Windows, Windows will update the certificates that Linux relies on. 

        Unless prepared, affected physical and virtual machine (VM) devices will: 
            Lose ability to install Secure Boot security updates after June 2026. 
            Not trust third-party software signed with new certificates after June 2026. 
            Not receive security fixes for Windows boot manager by October 2026. 

        What you need to do to prepare: 
            First, check on the latest available firmware from original equipment manufacturers (OEMs). Then, allow Microsoft to manage Windows updates, including Secure Boot updates: 
            Configure your organizational policies to allow at least the “required” level of diagnostic data. 
            Allow Microsoft to manage Secure Boot-related updates for your devices by setting the following registry key: 
            Registry path: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Secureboot 
            Key name: MicrosoftUpdateManagedOptIn 
            Type: DWORD 
            DWORD value: 0x5944 (opt in to Windows Secure Boot updates)  

    .CHANGELOG
        14-02-2024 - Michael Morten Sonne - Initial release
        09-07-2025 - Michael Morten Sonne - Enhanced with comprehensive system checking, status reporting,
                     and prerequisites setup per Microsoft guidance like:
                     > Act now. Secure Boot certificates expire in June 2026: https://techcommunity.microsoft.com/blog/windows-itpro-blog/act-now-secure-boot-certificates-expire-in-june-2026/4426856
                     > Secure Boot certificate rollout landing page: https://aka.ms/getsecureboot
                     > Windows devices for businesses and organizations with IT-managed updates: https://support.microsoft.com/topic/e2b43f9f-b424-42df-bc6a-8476db65ab2f
                     > Windows devices for home users, businesses, and schools with Microsoft-managed updates: https://support.microsoft.com/topic/29bfd847-5855-49f1-bb94-e18497fe2315
                     > Windows 11 and Secure Boot to check if it’s enabled: https://support.microsoft.com/windows/windows-11-and-secure-boot-a8ff1202-c0d9-42f5-940f-843abef64fad
                     > Get additional technical guidance at Updating Microsoft Secure Boot keys: https://techcommunity.microsoft.com/blog/windows-itpro-blog/updating-microsoft-secure-boot-keys/4055324

                     Message center: https://admin.microsoft.com/#/MessageCenter/:/messages/MC1104112 - Act now: Secure Boot certificates expire in June 2026

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

# ============================================================================
# CERTIFICATE NAME CONFIGURATION
# ============================================================================
# Centralized certificate names for easy maintenance
# Based on Microsoft Tech Community guidance for June 2026 certificate expiration

# Legacy Certificate Names (Expiring)
$Script:CERT_KEK_LEGACY = "Microsoft Corporation KEK CA 2011"
$Script:CERT_UEFI_LEGACY = "Microsoft Corporation UEFI CA 2011"
$Script:CERT_WINDOWS_LEGACY = "Microsoft Windows Production PCA 2011"

# Updated Certificate Names (New)
$Script:CERT_KEK_UPDATED = "Microsoft Corporation KEK 2K CA 2023"
$Script:CERT_UEFI_UPDATED = "Microsoft Corporation UEFI CA 2023"
$Script:CERT_OPTION_ROM_UPDATED = "Microsoft Option ROM UEFI CA 2023"
$Script:CERT_WINDOWS_UPDATED = "Windows UEFI CA 2023"

# Certificate Expiration Dates
$Script:CERT_KEK_EXPIRY = "June 2026"
$Script:CERT_UEFI_EXPIRY = "June 2026"
$Script:CERT_WINDOWS_EXPIRY = "Oct 2026"

# Certificate Storage Locations
$Script:CERT_LOCATION_KEK = "Stored in KEK"
$Script:CERT_LOCATION_DB = "Stored in DB"

# Certificate Purposes/Descriptions
$Script:CERT_PURPOSE_KEK = "Signs updates to DB and DBX"
$Script:CERT_PURPOSE_UEFI = "Signs third-party OS and hardware driver components"
$Script:CERT_PURPOSE_OPTION_ROM = "Signs third-party option ROMs"
$Script:CERT_PURPOSE_WINDOWS = "Signs the Windows bootloader and boot components"

# Certificate Display Names (with context)
$Script:CERT_UEFI_DISPLAY = "Microsoft Corporation UEFI CA 2011 (or third-party UEFI CA)"

# ============================================================================
# END CERTIFICATE CONFIGURATION
# ============================================================================

function Show-Menu {
    #Clear-Host
    Write-Host "********** Secure Boot Update Menu for UEFI CA 2023 **********" -ForegroundColor Cyan
    #Write-Host "*** Certificate Expiration: June 2026 ***" -ForegroundColor Red
    Write-Host ""
    Write-Host "Certificate Analysis:"
    Write-Host "1. Show certificate overview and expiration timeline"
    Write-Host "2. Check system information and compatibility"
    Write-Host "3. Check current Secure Boot status"
    Write-Host ""
    Write-Host "Prerequisites & Setup:"
    Write-Host "4. Set up prerequisites for update"
    Write-Host "5. Export detailed report"
    Write-Host "6. Export TPM event logs"
    Write-Host "7. Show Secure Boot scheduled tasks"
    Write-Host ""
    Write-Host "Update Process:"
    Write-Host "8. Set registry key for certificate update (DB update)"
    Write-Host "9. Set registry key for DBX update (restart required)"
    Write-Host "10. Run scheduled task"
    Write-Host "11. Reboot the machine"
    Write-Host "12. Verify Secure Boot DB update"
    Write-Host ""
    Write-Host "13. Exit"
    Write-Host ""
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

    # Get Windows version information
    $v = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $windowsVersionString = "Windows version: {0} (Build {1}.{2})" -f $v.DisplayVersion, $v.CurrentBuildNumber, $v.UBR

    $info = [PSCustomObject]@{
        ComputerName     = $env:COMPUTERNAME
        Manufacturer     = $system.Manufacturer
        Model            = $system.Model
        BIOS_Version     = $bios.SMBIOSBIOSVersion
        BIOS_ReleaseDate = $bios.ReleaseDate
        OS_Version       = $os.Version
        OS_BuildNumber   = $os.BuildNumber
        OS_VersionMajor  = $windowsVersionString
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
        DBUpdateAvailable             = $false
        DBXUpdateAvailable            = $false
        AvailableUpdatesValue         = 0
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
            if ($availableUpdates) {
                $results.AvailableUpdatesValue = $availableUpdates.AvailableUpdates
                
                # Check for DB update (0x40 = 64 decimal)
                if (($availableUpdates.AvailableUpdates -band 0x40) -eq 0x40) {
                    $results.DBUpdateAvailable = $true
                    $results.AvailableUpdatesSet = $true
                }
                
                # Check for DBX update (0x02 = 2 decimal) 
                if (($availableUpdates.AvailableUpdates -band 0x02) -eq 0x02) {
                    $results.DBXUpdateAvailable = $true
                    $results.AvailableUpdatesSet = $true
                }
            }
        }
    } catch {
        $results.AvailableUpdatesSet = $false
        $results.DBUpdateAvailable = $false
        $results.DBXUpdateAvailable = $false
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
            if ($dbString -match $Script:CERT_WINDOWS_UPDATED) {
                $results.CertificateExpirationCheck = "Updated certificates found"
            } else {
                $results.CertificateExpirationCheck = "Legacy certificates - update required before $Script:CERT_KEK_EXPIRY"
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
    $logPath = "C:\Temp"
    if (-not (Test-Path $logPath)) {
        New-Item -Path $logPath -ItemType Directory -Force | Out-Null
    }
    
    # Export system information
    $systemReportPath = Join-Path $logPath "SecureBootSystemInfo_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $systemInfo | Export-Csv -Path $systemReportPath -NoTypeInformation
    
    # Export Secure Boot status
    $statusReportPath = Join-Path $logPath "SecureBootStatus_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $secureBootStatus | Export-Csv -Path $statusReportPath -NoTypeInformation
    
    # Export TPM event logs
    Write-Host "`nExporting TPM and Secure Boot event logs..." -ForegroundColor Yellow
    $tpmExportResult = Export-TPMEventLogs -LogPath $logPath -DaysBack 30
    
    Write-Host "`nReports exported to:" -ForegroundColor Green
    Write-Host "  System Info: $systemReportPath" -ForegroundColor Cyan
    Write-Host "  Secure Boot Status: $statusReportPath" -ForegroundColor Cyan
    if ($tpmExportResult.TPMEventsPath) {
        Write-Host "  TPM Events (CSV): $($tpmExportResult.TPMEventsPath)" -ForegroundColor Cyan
        Write-Host "  TPM Events (JSON): $($tpmExportResult.TPMEventsJsonPath)" -ForegroundColor Cyan
    }
    if ($tpmExportResult.SecureBootEventsPath) {
        Write-Host "  Secure Boot Events: $($tpmExportResult.SecureBootEventsPath)" -ForegroundColor Cyan
    }
    
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
            if ($kekString -match $Script:CERT_KEK_LEGACY) {
                $results.KEK_Legacy_Found = $true
                Write-Host "  [+] Found: $Script:CERT_KEK_LEGACY (expires $Script:CERT_KEK_EXPIRY)" -ForegroundColor Yellow
            }
            
            # Check for updated KEK certificate - correct name from Microsoft table
            if ($kekString -match $Script:CERT_KEK_UPDATED) {
                $results.KEK_Updated_Found = $true
                Write-Host "  [+] Found: $Script:CERT_KEK_UPDATED (updated certificate)" -ForegroundColor Green
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
            if ($dbString -match $Script:CERT_UEFI_LEGACY) {
                $results.DB_UEFI_Legacy_Found = $true
                Write-Host "  [+] Found: $Script:CERT_UEFI_LEGACY (expires $Script:CERT_UEFI_EXPIRY)" -ForegroundColor Yellow
            }
            
            # Check for updated UEFI certificates - align with Microsoft table
            if ($dbString -match $Script:CERT_UEFI_UPDATED) {
                $results.DB_UEFI_Updated_Found = $true
                Write-Host "  [+] Found: $Script:CERT_UEFI_UPDATED (updated certificate)" -ForegroundColor Green
            }
            
            if ($dbString -match $Script:CERT_OPTION_ROM_UPDATED) {
                Write-Host "  [+] Found: $Script:CERT_OPTION_ROM_UPDATED (updated certificate)" -ForegroundColor Green
                $results.DB_OptionROM_Updated_Found = $true
            } else {
                $results.DB_OptionROM_Updated_Found = $false
            }
            
            # Check for legacy Windows certificates
            if ($dbString -match $Script:CERT_WINDOWS_LEGACY) {
                $results.DB_Windows_Legacy_Found = $true
                Write-Host "  [+] Found: $Script:CERT_WINDOWS_LEGACY (expires $Script:CERT_WINDOWS_EXPIRY)" -ForegroundColor Yellow
            }
            
            # Check for updated Windows certificates
            if ($dbString -match $Script:CERT_WINDOWS_UPDATED) {
                $results.DB_Windows_Updated_Found = $true
                Write-Host "  [+] Found: $Script:CERT_WINDOWS_UPDATED (updated certificate)" -ForegroundColor Green
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
                ExpiringCertificate = $Script:CERT_KEK_LEGACY
                ExpirationDate = $Script:CERT_KEK_EXPIRY
                NewCertificate = $Script:CERT_KEK_UPDATED
                StoringLocation = $Script:CERT_LOCATION_KEK
                Purpose = $Script:CERT_PURPOSE_KEK
                LegacyFound = $results.KEK_Legacy_Found
                UpdatedFound = $results.KEK_Updated_Found
                Status = $results.KEK_Status
            },
            [PSCustomObject]@{
                ExpiringCertificate = $Script:CERT_UEFI_DISPLAY
                ExpirationDate = $Script:CERT_UEFI_EXPIRY
                NewCertificate = $Script:CERT_UEFI_UPDATED
                StoringLocation = $Script:CERT_LOCATION_DB
                Purpose = $Script:CERT_PURPOSE_UEFI
                LegacyFound = $results.DB_UEFI_Legacy_Found
                UpdatedFound = $results.DB_UEFI_Updated_Found
                Status = $results.DB_UEFI_Status
            },
            [PSCustomObject]@{
                ExpiringCertificate = $Script:CERT_UEFI_DISPLAY
                ExpirationDate = $Script:CERT_UEFI_EXPIRY
                NewCertificate = $Script:CERT_OPTION_ROM_UPDATED
                StoringLocation = $Script:CERT_LOCATION_DB
                Purpose = $Script:CERT_PURPOSE_OPTION_ROM
                LegacyFound = $results.DB_UEFI_Legacy_Found
                UpdatedFound = $results.DB_OptionROM_Updated_Found
                Status = $results.DB_OptionROM_Status
            },
            [PSCustomObject]@{
                ExpiringCertificate = $Script:CERT_WINDOWS_LEGACY
                ExpirationDate = $Script:CERT_WINDOWS_EXPIRY
                NewCertificate = $Script:CERT_WINDOWS_UPDATED
                StoringLocation = $Script:CERT_LOCATION_DB
                Purpose = $Script:CERT_PURPOSE_WINDOWS
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
            ExpiringCertificate = $Script:CERT_KEK_LEGACY
            ExpirationDate = $Script:CERT_KEK_EXPIRY
            NewCertificate = $Script:CERT_KEK_UPDATED
            StoringLocation = $Script:CERT_LOCATION_KEK
            Purpose = $Script:CERT_PURPOSE_KEK
            Status = $certInfo.KEK_Status
        },
        [PSCustomObject]@{
            ExpiringCertificate = $Script:CERT_UEFI_DISPLAY
            ExpirationDate = $Script:CERT_UEFI_EXPIRY
            NewCertificate = $Script:CERT_UEFI_UPDATED
            StoringLocation = $Script:CERT_LOCATION_DB
            Purpose = $Script:CERT_PURPOSE_UEFI
            Status = $certInfo.DB_UEFI_Status
        },
        [PSCustomObject]@{
            ExpiringCertificate = $Script:CERT_UEFI_DISPLAY
            ExpirationDate = $Script:CERT_UEFI_EXPIRY
            NewCertificate = $Script:CERT_OPTION_ROM_UPDATED
            StoringLocation = $Script:CERT_LOCATION_DB
            Purpose = $Script:CERT_PURPOSE_OPTION_ROM
            Status = $certInfo.DB_OptionROM_Status
        },
        [PSCustomObject]@{
            ExpiringCertificate = $Script:CERT_WINDOWS_LEGACY
            ExpirationDate = $Script:CERT_WINDOWS_EXPIRY
            NewCertificate = $Script:CERT_WINDOWS_UPDATED
            StoringLocation = $Script:CERT_LOCATION_DB
            Purpose = $Script:CERT_PURPOSE_WINDOWS
            Status = $certInfo.DB_Windows_Status
        }
    )
    
    # Display table format - keeping original names but formatted for console
    Write-Host "Certificate Overview Table:" -ForegroundColor Cyan
    Write-Host "================================================================" -ForegroundColor Gray
    
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

function Export-TPMEventLogs {
    param(
        [string]$LogPath = "C:\Temp",
        [int]$DaysBack = 30
    )
    
    Write-Host "Exporting TPM-related event logs..." -ForegroundColor Yellow
    
    # Create logs directory if it doesn't exist
    if (-not (Test-Path $LogPath)) {
        New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
    }
    
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $tpmLogPath = Join-Path $LogPath "TPMEvents_$timestamp.csv"
    $tpmLogJsonPath = Join-Path $LogPath "TPMEvents_$timestamp.json"
    
    # Calculate start time for filtering
    $startTime = (Get-Date).AddDays(-$DaysBack)
    
    try {
        Write-Host "  Querying TPM events from the last $DaysBack days..." -ForegroundColor Cyan
        
        # Get TPM-related events with specific IDs that are relevant to Secure Boot and certificate updates
        $tpmEvents = Get-WinEvent -FilterHashtable @{
            ProviderName = 'microsoft-windows-tpm-wmi'
            Id = 1032, 1033, 1034, 1035, 1036, 1037, 1795, 1796, 1797, 1798, 1799
            StartTime = $startTime
        } -ErrorAction SilentlyContinue
        
        if ($tpmEvents) {
            Write-Host "  Found $($tpmEvents.Count) TPM events" -ForegroundColor Green
            
            # Create structured data for export
            $structuredEvents = $tpmEvents | ForEach-Object {
                [PSCustomObject]@{
                    TimeCreated = $_.TimeCreated
                    Id = $_.Id
                    Level = $_.Level
                    LevelDisplayName = $_.LevelDisplayName
                    ProviderName = $_.ProviderName
                    Message = $_.Message
                    UserId = $_.UserId
                    ProcessId = $_.ProcessId
                    ThreadId = $_.ThreadId
                    MachineName = $_.MachineName
                    ActivityId = $_.ActivityId
                    RelatedActivityId = $_.RelatedActivityId
                    Keywords = $_.Keywords
                    KeywordsDisplayNames = ($_.KeywordsDisplayNames -join ', ')
                    OpcodeName = $_.OpcodeName
                    TaskDisplayName = $_.TaskDisplayName
                    Properties = ($_.Properties | ForEach-Object { $_.Value }) -join '; '
                }
            }
            
            # Export to CSV
            $structuredEvents | Export-Csv -Path $tpmLogPath -NoTypeInformation -Encoding UTF8
            Write-Host "  CSV export: $tpmLogPath" -ForegroundColor Cyan
            
            # Export to JSON for better readability of complex data
            $structuredEvents | ConvertTo-Json -Depth 3 | Out-File -FilePath $tpmLogJsonPath -Encoding UTF8
            Write-Host "  JSON export: $tpmLogJsonPath" -ForegroundColor Cyan
            
            # Display summary of events by ID
            Write-Host "`n  Event Summary:" -ForegroundColor Yellow
            $eventSummary = $tpmEvents | Group-Object Id | Sort-Object Name
            foreach ($group in $eventSummary) {
                $eventDescription = switch ($group.Name) {
                    1032 { "TPM initialization" }
                    1033 { "TPM clear operation" }
                    1034 { "TPM ownership taken" }
                    1035 { "TPM physical presence operation" }
                    1036 { "TPM platform configuration register (PCR) extension" }
                    1037 { "TPM measurement" }
                    1795 { "TPM attestation identity key creation" }
                    1796 { "TPM endorsement key creation" }
                    1797 { "TPM storage root key creation" }
                    1798 { "TPM platform configuration register (PCR) quote" }
                    1799 { "TPM command execution" }
                    default { "TPM event" }
                }
                Write-Host "    Event $($group.Name): $($group.Count) events - $eventDescription" -ForegroundColor Gray
            }
            
            # Show recent critical events
            $criticalEvents = $tpmEvents | Where-Object { $_.Level -le 3 } | Sort-Object TimeCreated -Descending | Select-Object -First 5
            if ($criticalEvents) {
                Write-Host "`n  Recent Critical/Warning Events:" -ForegroundColor Yellow
                foreach ($tpmEvent in $criticalEvents) {
                    $levelColor = switch ($tpmEvent.Level) {
                        1 { "Red" }    # Critical
                        2 { "Red" }    # Error
                        3 { "Yellow" } # Warning
                        default { "Gray" }
                    }
                    Write-Host "    [$($tpmEvent.TimeCreated)] ID $($tpmEvent.Id) - $($tpmEvent.LevelDisplayName)" -ForegroundColor $levelColor
                    Write-Host "      $($tpmEvent.Message.Substring(0, [Math]::Min(100, $tpmEvent.Message.Length)))..." -ForegroundColor Gray
                }
            }
            
        } else {
            Write-Host "  No TPM events found in the specified time range" -ForegroundColor Yellow
            Write-Host "  This might indicate:" -ForegroundColor Gray
            Write-Host "    - TPM is not enabled or not present" -ForegroundColor Gray
            Write-Host "    - No TPM operations occurred recently" -ForegroundColor Gray
            Write-Host "    - Event log has been cleared" -ForegroundColor Gray
        }
        
    } catch {
        Write-Host "  Error retrieving TPM events: $_" -ForegroundColor Red
        Write-Host "  This might indicate insufficient permissions or TPM not available" -ForegroundColor Yellow
    }
    
    # Also check for Secure Boot related events in the System log
    try {
        Write-Host "`n  Checking for Secure Boot events in System log..." -ForegroundColor Cyan
        
        $secureBootEvents = Get-WinEvent -FilterHashtable @{
            LogName = 'System'
            ProviderName = 'Microsoft-Windows-Kernel-Boot', 'Microsoft-Windows-Kernel-General'
            StartTime = $startTime
        } -ErrorAction SilentlyContinue | Where-Object { 
            $_.Message -match 'Secure Boot|UEFI|Boot Manager|winload|bootmgr' 
        }
        
        if ($secureBootEvents) {
            $secureBootLogPath = Join-Path $LogPath "SecureBootEvents_$timestamp.csv"
            $secureBootEvents | Select-Object TimeCreated, Id, Level, LevelDisplayName, ProviderName, Message | 
                Export-Csv -Path $secureBootLogPath -NoTypeInformation -Encoding UTF8
            Write-Host "  Secure Boot events exported: $secureBootLogPath" -ForegroundColor Cyan
            Write-Host "  Found $($secureBootEvents.Count) Secure Boot related events" -ForegroundColor Green
        } else {
            Write-Host "  No Secure Boot related events found in System log" -ForegroundColor Gray
        }
        
    } catch {
        Write-Host "  Could not retrieve Secure Boot events: $_" -ForegroundColor Yellow
    }
    
    Write-Host "`nTPM event log export completed" -ForegroundColor Green
    return @{
        TPMEventsPath = $tpmLogPath
        TPMEventsJsonPath = $tpmLogJsonPath
        SecureBootEventsPath = if ($secureBootEvents) { $secureBootLogPath } else { $null }
        EventCount = if ($tpmEvents) { $tpmEvents.Count } else { 0 }
    }
}

    
Write-Host "================================================================" -ForegroundColor Gray

# Main execution loop
do {

    $IsArm = $false
    try {
        $arch = (Get-WmiObject Win32_Processor -ErrorAction Stop).Architecture
        # 0 = x86, 9 = x64, 5 = ARM, 12 = ARM64
        if ($arch -eq 5 -or $arch -eq 12) {
            $IsArm = $true
        }
        if ($arch -eq 0) {
            Write-Host "Detected x86 architecture (32-bit).`n"
        } elseif ($arch -eq 9) {
            Write-Host "Detected x64 architecture (64-bit).`n"
        } elseif ($IsArm) {
            Write-Host "Detected ARM architecture.`n"
        } else {
            Write-Host "Unknown CPU architecture detected. Proceeding with defaults." -ForegroundColor Yellow
        }
    } catch {
        Write-Warning "Unable to determine CPU architecture, proceeding with defaults (x64).`n"
    }

    Show-Menu

    $choice = Read-Host "Select a task (1-13)"

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
                    Write-Host "System supports Secure Boot UEFI`n" -ForegroundColor Green
                } catch {
                    Write-Host "Warning: System may not support Secure Boot or is running in Legacy BIOS mode`n" -ForegroundColor Yellow
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
                    Write-Host "Action Required: Update certificates before $Script:CERT_KEK_EXPIRY" -ForegroundColor Red
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
                # Export TPM event logs
                Write-Host "Exporting TPM event logs..." -ForegroundColor Yellow
                $exportResult = Export-TPMEventLogs
                
                if ($exportResult.EventCount -gt 0) {
                    Write-Host "`nTPM event log export completed successfully!" -ForegroundColor Green
                    Write-Host "Found $($exportResult.EventCount) TPM events" -ForegroundColor Cyan
                } else {
                    Write-Host "`nNo TPM events found or TPM not available" -ForegroundColor Yellow
                }
            }
            7 {
                # Show Secure Boot scheduled tasks
                Show-SecureBootTasks
            }
            8 {
                # Set registry key for certificate update
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot" -Name "AvailableUpdates" -Value 0x40 #DB update
                Write-Host "Registry key set successfully to apply the update for DB" -ForegroundColor Green
    
                # Prompt to execute task 10 automatically or manually
                $task10Choice = Read-Host "Do you want to execute task 10 (Run scheduled task) automatically (Y) or manually (M)?"
                if ($task10Choice -eq 'Y' -or $task10Choice -eq 'y') {
                    # Run scheduled task to update Secure Boot DB with the new CA
                    RunScheduledTask
                } elseif ($task10Choice -eq 'M' -or $task10Choice -eq 'm') {
                    Write-Host "You can manually execute task 10 from the menu."
                } else {
                    Write-Host "Invalid choice. Task 10 will not be executed."
                }
            }
            9 {
                # Set registry key for DBX update (restart required)
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot" -Name "AvailableUpdates" -Value 0x02 -Force
                Write-Host "Registry key set successfully to apply the DBX update" -ForegroundColor Green
                Write-Host "WARNING: A restart is required for DBX updates to take effect!" -ForegroundColor Yellow
                Write-Host "The DBX (forbidden signatures database) will be updated on next reboot." -ForegroundColor Cyan
                
                # Prompt for reboot
                $rebootChoice = Read-Host "Do you want to reboot now to apply the DBX update? (Y/N)"
                if ($rebootChoice -eq 'Y' -or $rebootChoice -eq 'y') {
                    Write-Host "Rebooting the machine to apply DBX update..." -ForegroundColor Yellow
                    Restart-Computer -Force
                } else {
                    Write-Host "Remember to reboot manually to apply the DBX update." -ForegroundColor Yellow
                }
            }
            10 {
                # Run scheduled task manually to update Secure Boot DB with the new CA
                RunScheduledTask
            }
            11 {
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
            12 {
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
                        Write-Host "[+] Your system is prepared for the $Script:CERT_KEK_EXPIRY certificate expiration" -ForegroundColor Green
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
            13 {
                # Exit
                Write-Host "Exiting Secure Boot Update Menu."
            }
            default {
                # Invalid selection
                Write-Host "Invalid selection. Please enter a number between 1 and 13."
            }
        }
    }
    catch {
        # Catch any errors and display them
        Write-Host "An error occurred: $_" -ForegroundColor Red
    }    

    if ($choice -ne 13) {
        # Prompt to continue
        $null = Read-Host "Press Enter to continue..."
    }

} while ($choice -ne 13)


# SIG # Begin signature block
# MIIudQYJKoZIhvcNAQcCoIIuZjCCLmICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDyK+XbM/LH5OjP
# PPYqErTIoUIm5NCVhmsOqeSTyiKgA6CCEd8wggVvMIIEV6ADAgECAhBI/JO0YFWU
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
# gf9SsIAod1Dx9THs2qkXIwyf5lTJBvPHLRqxs/k+Mn70AUiyj50/JYMxghvsMIIb
# 6AIBATBoMFQxCzAJBgNVBAYTAkdCMRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQx
# KzApBgNVBAMTIlNlY3RpZ28gUHVibGljIENvZGUgU2lnbmluZyBDQSBSMzYCEBHh
# oIZkh66CYIKNKPBResYwDQYJYIZIAWUDBAIBBQCgfDAQBgorBgEEAYI3AgEMMQIw
# ADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYK
# KwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgGGf59sdWimsu4FbgVjmotCnKr9JA
# /nzEtTVWzMrnM04wDQYJKoZIhvcNAQEBBQAEggIAZ1E9iSArV8nY9WXOJhoSzhuz
# QTf9OndAU0OJ2/IQhawA4CZxpAV2Otc5iOXNxzOh27/8ZwaXcTn4C1LVM6jwVAnj
# NagCxIzawZugl1K0B4DwUqohH0QxZ1ngSOX7qybbhABWcYbGYghRXfaSP8ESinlN
# yQCCvpdziHBZpFztCgOlrpltz0PP703oWM9g4G3mjFZYIlB0pNydp/Cd8/QGxy4X
# HuIZXoyAPrqzbrhuaFcIeCm2rvtJifmdjHvXu3qtUpa0zC3TlKSqdeVrbwBI/mea
# /VqaJwxF8fSO6fAtjFa6m5huup/mTTM2yaK8K5UC1n2cmNU8IyeAqnElD+kr0Nu8
# /3ClecFWy8a1Z5mY+ezJNgtMKz9R72PrGmVnbRPtqAu19wtvMHiAFTKzdYA8lzAG
# yEN4jFj+W2CO7MJEJl7duby9YRlJSS3ny6sQvXRuyvHhRvvaqNz+VT8YV5jt4wUV
# q7uieMtQ17cvW9HSeVuT/4izlcMYDBg3uoa/+jOOID3O0o+00spqFBUhhEQU5IlB
# JnB1rxHIcUbFHIYu1YLFDca8AJ5eyZc9LXlXuC/Jd0p7ogsfvB/+hP+16vdtKpeb
# dHphKU5rNMozWRxZJ5rbU68MSByxUtv7cMSA5dBxQTiVSHtdf8GfFijxwR8qFC+S
# tNT8q8kNxkl2YSOVZbmhghjXMIIY0wYKKwYBBAGCNwMDATGCGMMwghi/BgkqhkiG
# 9w0BBwKgghiwMIIYrAIBAzEPMA0GCWCGSAFlAwQCAgUAMIH3BgsqhkiG9w0BCRAB
# BKCB5wSB5DCB4QIBAQYKKwYBBAGyMQIBATAxMA0GCWCGSAFlAwQCAQUABCCl4G0X
# skJ2GJiDvRNFzqHQe0HXH/Qmg3oLD1xPhL7yngIUD3xOwDuZoeKgBLh47kU8pnm4
# JOoYDzIwMjUwNzA5MjEzNTA4WqB2pHQwcjELMAkGA1UEBhMCR0IxFzAVBgNVBAgT
# Dldlc3QgWW9ya3NoaXJlMRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQxMDAuBgNV
# BAMTJ1NlY3RpZ28gUHVibGljIFRpbWUgU3RhbXBpbmcgU2lnbmVyIFIzNqCCEwQw
# ggZiMIIEyqADAgECAhEApCk7bh7d16c0CIetek63JDANBgkqhkiG9w0BAQwFADBV
# MQswCQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMSwwKgYDVQQD
# EyNTZWN0aWdvIFB1YmxpYyBUaW1lIFN0YW1waW5nIENBIFIzNjAeFw0yNTAzMjcw
# MDAwMDBaFw0zNjAzMjEyMzU5NTlaMHIxCzAJBgNVBAYTAkdCMRcwFQYDVQQIEw5X
# ZXN0IFlvcmtzaGlyZTEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMTAwLgYDVQQD
# EydTZWN0aWdvIFB1YmxpYyBUaW1lIFN0YW1waW5nIFNpZ25lciBSMzYwggIiMA0G
# CSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDThJX0bqRTePI9EEt4Egc83JSBU2dh
# rJ+wY7JgReuff5KQNhMuzVytzD+iXazATVPMHZpH/kkiMo1/vlAGFrYN2P7g0Q8o
# PEcR3h0SftFNYxxMh+bj3ZNbbYjwt8f4DsSHPT+xp9zoFuw0HOMdO3sWeA1+F8mh
# g6uS6BJpPwXQjNSHpVTCgd1gOmKWf12HSfSbnjl3kDm0kP3aIUAhsodBYZsJA1im
# WqkAVqwcGfvs6pbfs/0GE4BJ2aOnciKNiIV1wDRZAh7rS/O+uTQcb6JVzBVmPP63
# k5xcZNzGo4DOTV+sM1nVrDycWEYS8bSS0lCSeclkTcPjQah9Xs7xbOBoCdmahSfg
# 8Km8ffq8PhdoAXYKOI+wlaJj+PbEuwm6rHcm24jhqQfQyYbOUFTKWFe901VdyMC4
# gRwRAq04FH2VTjBdCkhKts5Py7H73obMGrxN1uGgVyZho4FkqXA8/uk6nkzPH9Qy
# HIED3c9CGIJ098hU4Ig2xRjhTbengoncXUeo/cfpKXDeUcAKcuKUYRNdGDlf8Wnw
# byqUblj4zj1kQZSnZud5EtmjIdPLKce8UhKl5+EEJXQp1Fkc9y5Ivk4AZacGMCVG
# 0e+wwGsjcAADRO7Wga89r/jJ56IDK773LdIsL3yANVvJKdeeS6OOEiH6hpq2yT+j
# J/lHa9zEdqFqMwIDAQABo4IBjjCCAYowHwYDVR0jBBgwFoAUX1jtTDF6omFCjVKA
# urNhlxmiMpswHQYDVR0OBBYEFIhhjKEqN2SBKGChmzHQjP0sAs5PMA4GA1UdDwEB
# /wQEAwIGwDAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMEoG
# A1UdIARDMEEwNQYMKwYBBAGyMQECAQMIMCUwIwYIKwYBBQUHAgEWF2h0dHBzOi8v
# c2VjdGlnby5jb20vQ1BTMAgGBmeBDAEEAjBKBgNVHR8EQzBBMD+gPaA7hjlodHRw
# Oi8vY3JsLnNlY3RpZ28uY29tL1NlY3RpZ29QdWJsaWNUaW1lU3RhbXBpbmdDQVIz
# Ni5jcmwwegYIKwYBBQUHAQEEbjBsMEUGCCsGAQUFBzAChjlodHRwOi8vY3J0LnNl
# Y3RpZ28uY29tL1NlY3RpZ29QdWJsaWNUaW1lU3RhbXBpbmdDQVIzNi5jcnQwIwYI
# KwYBBQUHMAGGF2h0dHA6Ly9vY3NwLnNlY3RpZ28uY29tMA0GCSqGSIb3DQEBDAUA
# A4IBgQACgT6khnJRIfllqS49Uorh5ZvMSxNEk4SNsi7qvu+bNdcuknHgXIaZyqcV
# mhrV3PHcmtQKt0blv/8t8DE4bL0+H0m2tgKElpUeu6wOH02BjCIYM6HLInbNHLf6
# R2qHC1SUsJ02MWNqRNIT6GQL0Xm3LW7E6hDZmR8jlYzhZcDdkdw0cHhXjbOLsmTe
# S0SeRJ1WJXEzqt25dbSOaaK7vVmkEVkOHsp16ez49Bc+Ayq/Oh2BAkSTFog43ldE
# KgHEDBbCIyba2E8O5lPNan+BQXOLuLMKYS3ikTcp/Qw63dxyDCfgqXYUhxBpXnme
# SO/WA4NwdwP35lWNhmjIpNVZvhWoxDL+PxDdpph3+M5DroWGTc1ZuDa1iXmOFAK4
# iwTnlWDg3QNRsRa9cnG3FBBpVHnHOEQj4GMkrOHdNDTbonEeGvZ+4nSZXrwCW4Wv
# 2qyGDBLlKk3kUW1pIScDCpm/chL6aUbnSsrtbepdtbCLiGanKVR/KC1gsR0tC6Q0
# RfWOI4owggYUMIID/KADAgECAhB6I67aU2mWD5HIPlz0x+M/MA0GCSqGSIb3DQEB
# DAUAMFcxCzAJBgNVBAYTAkdCMRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQxLjAs
# BgNVBAMTJVNlY3RpZ28gUHVibGljIFRpbWUgU3RhbXBpbmcgUm9vdCBSNDYwHhcN
# MjEwMzIyMDAwMDAwWhcNMzYwMzIxMjM1OTU5WjBVMQswCQYDVQQGEwJHQjEYMBYG
# A1UEChMPU2VjdGlnbyBMaW1pdGVkMSwwKgYDVQQDEyNTZWN0aWdvIFB1YmxpYyBU
# aW1lIFN0YW1waW5nIENBIFIzNjCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoC
# ggGBAM2Y2ENBq26CK+z2M34mNOSJjNPvIhKAVD7vJq+MDoGD46IiM+b83+3ecLvB
# hStSVjeYXIjfa3ajoW3cS3ElcJzkyZlBnwDEJuHlzpbN4kMH2qRBVrjrGJgSlzzU
# qcGQBaCxpectRGhhnOSwcjPMI3G0hedv2eNmGiUbD12OeORN0ADzdpsQ4dDi6M4Y
# hoGE9cbY11XxM2AVZn0GiOUC9+XE0wI7CQKfOUfigLDn7i/WeyxZ43XLj5GVo7LD
# BExSLnh+va8WxTlA+uBvq1KO8RSHUQLgzb1gbL9Ihgzxmkdp2ZWNuLc+XyEmJNbD
# 2OIIq/fWlwBp6KNL19zpHsODLIsgZ+WZ1AzCs1HEK6VWrxmnKyJJg2Lv23DlEdZl
# QSGdF+z+Gyn9/CRezKe7WNyxRf4e4bwUtrYE2F5Q+05yDD68clwnweckKtxRaF0V
# zN/w76kOLIaFVhf5sMM/caEZLtOYqYadtn034ykSFaZuIBU9uCSrKRKTPJhWvXk4
# CllgrwIDAQABo4IBXDCCAVgwHwYDVR0jBBgwFoAU9ndq3T/9ARP/FqFsggIv0Ao9
# FCUwHQYDVR0OBBYEFF9Y7UwxeqJhQo1SgLqzYZcZojKbMA4GA1UdDwEB/wQEAwIB
# hjASBgNVHRMBAf8ECDAGAQH/AgEAMBMGA1UdJQQMMAoGCCsGAQUFBwMIMBEGA1Ud
# IAQKMAgwBgYEVR0gADBMBgNVHR8ERTBDMEGgP6A9hjtodHRwOi8vY3JsLnNlY3Rp
# Z28uY29tL1NlY3RpZ29QdWJsaWNUaW1lU3RhbXBpbmdSb290UjQ2LmNybDB8Bggr
# BgEFBQcBAQRwMG4wRwYIKwYBBQUHMAKGO2h0dHA6Ly9jcnQuc2VjdGlnby5jb20v
# U2VjdGlnb1B1YmxpY1RpbWVTdGFtcGluZ1Jvb3RSNDYucDdjMCMGCCsGAQUFBzAB
# hhdodHRwOi8vb2NzcC5zZWN0aWdvLmNvbTANBgkqhkiG9w0BAQwFAAOCAgEAEtd7
# IK0ONVgMnoEdJVj9TC1ndK/HYiYh9lVUacahRoZ2W2hfiEOyQExnHk1jkvpIJzAM
# xmEc6ZvIyHI5UkPCbXKspioYMdbOnBWQUn733qMooBfIghpR/klUqNxx6/fDXqY0
# hSU1OSkkSivt51UlmJElUICZYBodzD3M/SFjeCP59anwxs6hwj1mfvzG+b1coYGn
# qsSz2wSKr+nDO+Db8qNcTbJZRAiSazr7KyUJGo1c+MScGfG5QHV+bps8BX5Oyv9C
# t36Y4Il6ajTqV2ifikkVtB3RNBUgwu/mSiSUice/Jp/q8BMk/gN8+0rNIE+QqU63
# JoVMCMPY2752LmESsRVVoypJVt8/N3qQ1c6FibbcRabo3azZkcIdWGVSAdoLgAIx
# EKBeNh9AQO1gQrnh1TA8ldXuJzPSuALOz1Ujb0PCyNVkWk7hkhVHfcvBfI8NtgWQ
# upiaAeNHe0pWSGH2opXZYKYG4Lbukg7HpNi/KqJhue2Keak6qH9A8CeEOB7Eob0Z
# f+fU+CCQaL0cJqlmnx9HCDxF+3BLbUufrV64EbTI40zqegPZdA+sXCmbcZy6okx/
# SjwsusWRItFA3DE8MORZeFb6BmzBtqKJ7l939bbKBy2jvxcJI98Va95Q5JnlKor3
# m0E7xpMeYRriWklUPsetMSf2NvUQa/E5vVyefQIwggaCMIIEaqADAgECAhA2wrC9
# fBs656Oz3TbLyXVoMA0GCSqGSIb3DQEBDAUAMIGIMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKTmV3IEplcnNleTEUMBIGA1UEBxMLSmVyc2V5IENpdHkxHjAcBgNVBAoT
# FVRoZSBVU0VSVFJVU1QgTmV0d29yazEuMCwGA1UEAxMlVVNFUlRydXN0IFJTQSBD
# ZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTAeFw0yMTAzMjIwMDAwMDBaFw0zODAxMTgy
# MzU5NTlaMFcxCzAJBgNVBAYTAkdCMRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQx
# LjAsBgNVBAMTJVNlY3RpZ28gUHVibGljIFRpbWUgU3RhbXBpbmcgUm9vdCBSNDYw
# ggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCIndi5RWedHd3ouSaBmlRU
# wHxJBZvMWhUP2ZQQRLRBQIF3FJmp1OR2LMgIU14g0JIlL6VXWKmdbmKGRDILRxEt
# ZdQnOh2qmcxGzjqemIk8et8sE6J+N+Gl1cnZocew8eCAawKLu4TRrCoqCAT8uRjD
# eypoGJrruH/drCio28aqIVEn45NZiZQI7YYBex48eL78lQ0BrHeSmqy1uXe9xN04
# aG0pKG9ki+PC6VEfzutu6Q3IcZZfm00r9YAEp/4aeiLhyaKxLuhKKaAdQjRaf/h6
# U13jQEV1JnUTCm511n5avv4N+jSVwd+Wb8UMOs4netapq5Q/yGyiQOgjsP/JRUj0
# MAT9YrcmXcLgsrAimfWY3MzKm1HCxcquinTqbs1Q0d2VMMQyi9cAgMYC9jKc+3mW
# 62/yVl4jnDcw6ULJsBkOkrcPLUwqj7poS0T2+2JMzPP+jZ1h90/QpZnBkhdtixMi
# WDVgh60KmLmzXiqJc6lGwqoUqpq/1HVHm+Pc2B6+wCy/GwCcjw5rmzajLbmqGygE
# gaj/OLoanEWP6Y52Hflef3XLvYnhEY4kSirMQhtberRvaI+5YsD3XVxHGBjlIli5
# u+NrLedIxsE88WzKXqZjj9Zi5ybJL2WjeXuOTbswB7XjkZbErg7ebeAQUQiS/uRG
# Z58NHs57ZPUfECcgJC+v2wIDAQABo4IBFjCCARIwHwYDVR0jBBgwFoAUU3m/Wqor
# Ss9UgOHYm8Cd8rIDZsswHQYDVR0OBBYEFPZ3at0//QET/xahbIICL9AKPRQlMA4G
# A1UdDwEB/wQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MBMGA1UdJQQMMAoGCCsGAQUF
# BwMIMBEGA1UdIAQKMAgwBgYEVR0gADBQBgNVHR8ESTBHMEWgQ6BBhj9odHRwOi8v
# Y3JsLnVzZXJ0cnVzdC5jb20vVVNFUlRydXN0UlNBQ2VydGlmaWNhdGlvbkF1dGhv
# cml0eS5jcmwwNQYIKwYBBQUHAQEEKTAnMCUGCCsGAQUFBzABhhlodHRwOi8vb2Nz
# cC51c2VydHJ1c3QuY29tMA0GCSqGSIb3DQEBDAUAA4ICAQAOvmVB7WhEuOWhxdQR
# h+S3OyWM637ayBeR7djxQ8SihTnLf2sABFoB0DFR6JfWS0snf6WDG2gtCGflwVvc
# YXZJJlFfym1Doi+4PfDP8s0cqlDmdfyGOwMtGGzJ4iImyaz3IBae91g50QyrVbrU
# oT0mUGQHbRcF57olpfHhQEStz5i6hJvVLFV/ueQ21SM99zG4W2tB1ExGL98idX8C
# hsTwbD/zIExAopoe3l6JrzJtPxj8V9rocAnLP2C8Q5wXVVZcbw4x4ztXLsGzqZIi
# Rh5i111TW7HV1AtsQa6vXy633vCAbAOIaKcLAo/IU7sClyZUk62XD0VUnHD+YvVN
# vIGezjM6CRpcWed/ODiptK+evDKPU2K6synimYBaNH49v9Ih24+eYXNtI38byt5k
# Ivh+8aW88WThRpv8lUJKaPn37+YHYafob9Rg7LyTrSYpyZoBmwRWSE4W6iPjB7wJ
# jJpH29308ZkpKKdpkiS9WNsf/eeUtvRrtIEiSJHN899L1P4l6zKVsdrUu1FX1T/u
# bSrsxrYJD+3f3aKg6yxdbugot06YwGXXiy5UUGZvOu3lXlxA+fC13dQ5OlL2gIb5
# lmF6Ii8+CQOYDwXM+yd9dbmocQsHjcRPsccUd5E9FiswEqORvz8g3s+jR3SFCgXh
# N4wz7NgAnOgpCdUo4uDyllU9PzGCBJIwggSOAgEBMGowVTELMAkGA1UEBhMCR0Ix
# GDAWBgNVBAoTD1NlY3RpZ28gTGltaXRlZDEsMCoGA1UEAxMjU2VjdGlnbyBQdWJs
# aWMgVGltZSBTdGFtcGluZyBDQSBSMzYCEQCkKTtuHt3XpzQIh616TrckMA0GCWCG
# SAFlAwQCAgUAoIIB+TAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwHAYJKoZI
# hvcNAQkFMQ8XDTI1MDcwOTIxMzUwOFowPwYJKoZIhvcNAQkEMTIEMJnpy+7m9wiv
# Y1N28nuLPJHDMNNaAInU/qSoFLbYNoGSx3atlskBEmhsGkhn4RktLDCCAXoGCyqG
# SIb3DQEJEAIMMYIBaTCCAWUwggFhMBYEFDjJFIEQRLTcZj6T1HRLgUGGqbWxMIGH
# BBTGrlTkeIbxfD1VEkiMacNKevnC3TBvMFukWTBXMQswCQYDVQQGEwJHQjEYMBYG
# A1UEChMPU2VjdGlnbyBMaW1pdGVkMS4wLAYDVQQDEyVTZWN0aWdvIFB1YmxpYyBU
# aW1lIFN0YW1waW5nIFJvb3QgUjQ2AhB6I67aU2mWD5HIPlz0x+M/MIG8BBSFPWMt
# k4KCYXzQkDXEkd6SwULaxzCBozCBjqSBizCBiDELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCk5ldyBKZXJzZXkxFDASBgNVBAcTC0plcnNleSBDaXR5MR4wHAYDVQQKExVU
# aGUgVVNFUlRSVVNUIE5ldHdvcmsxLjAsBgNVBAMTJVVTRVJUcnVzdCBSU0EgQ2Vy
# dGlmaWNhdGlvbiBBdXRob3JpdHkCEDbCsL18Gzrno7PdNsvJdWgwDQYJKoZIhvcN
# AQEBBQAEggIAInQRgacHyIzyqL70mtb3xkHadpQInHNdyeeP1/rm4X4qyXnP7MTB
# sK/iQAgRgzskHQc2TRzedYmt5+ISdC31Zb/wUnABSAJoSsiSqIADA14YU4l9egvF
# srYuxUzhHFtQRYtp9Ok+hh8qAAn4Zn4sX7EuedFKK6BT8apQ0XSWsTi1iWXbKi04
# 1GVB6EOA1EPaVzVM7JVGgAp0nSVOUb7G9nL6lVaj4ffVcRwnK/S945E5v/A/iA69
# c0WXCmR3Sz/CwgWOrMWarrlSqpdthVuWrxiLL6FV5T3uPn1p/Cr0JEzF24dyx4bK
# 0CDsh+9xPyFVSH8PaiCh9iCQkizcQZOiMz7woUPtMKd6sX14j9MfUxhHKoAI2vUx
# NrXOelYTswC3Be/HZsFj/Ux2F3QBCmtI9qYdZrKgr0/kyKeTjKAkaRnxLcsQYBmp
# 00VCtKaV7p5w8NmgXU2OBgER/qhnzteg3RFD48qg/himp5nQK0ioFlWK9vx9wAAL
# u3+OAw/oxFgtGzV3S52eLrgmdBJTdmBKmMfh9Ms+Qjd/g7EWOqMmZodeklTnfbRh
# aAN8pIaZsMQoJ/jvi4OTgjUTpcepq/ckYIcwYfwGctS/UscbVI1AdvUFIDtSu7dD
# hSYN/uAgGHDhOAyApV9euHTg5glpQrpo0H+Sw/XVlB6mcuNebcrrQj4=
# SIG # End signature block
