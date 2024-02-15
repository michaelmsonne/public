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
		PowerShell script to update Secure Boot DB on Windows. The script sets the registry key, runs the scheduled task, reboots the machine twice, and verifies the Secure Boot DB update.

    .REQUREMENT
        - Administrator rights on the machine

    .CHANGELOG
        14-02-2024 - Michael Morten Sonne - Initial release

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
    Write-Host "********** Secure Boot Update Menu for UEFI CA 2023 **********"
    Write-Host "1. Set registry key"
    Write-Host "2. Run scheduled task"
    Write-Host "3. Reboot the machine"
    Write-Host "4. Verify Secure Boot DB update"
    Write-Host "5. Exit"
}

function RunScheduledTask {
    Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"
    Write-Host "Scheduled task started. Waiting for it to complete..." -ForegroundColor Yellow
    Wait-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"
    Write-Host "Scheduled task completed." -ForegroundColor Green
}

do {
    Show-Menu
    $choice = Read-Host "Select a task (1-5)"

    try {
        switch ($choice) {
            1 {
                # Set registry key
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot" -Name "AvailableUpdates" -Value 0x40
                Write-Host "Registry key set successfully to apply the update" -ForegroundColor Green
    
                # Prompt to execute task 2 automatically or manually
                $task2Choice = Read-Host "Do you want to execute task 2 automatically (Y) or manually (M)?"
                if ($task2Choice -eq 'Y' -or $task2Choice -eq 'y') {
                    # Run scheduled task to update Secure Boot DB with the new CA
                    RunScheduledTask
                } elseif ($task2Choice -eq 'M' -or $task2Choice -eq 'm') {
                    Write-Host "You can manually execute task 2 from the menu."
                } else {
                    Write-Host "Invalid choice. Task 2 will not be executed."
                }
            }
            2 {
                # Run scheduled task manually to update Secure Boot DB with the new CA
                RunScheduledTask
            }
            3 {
                # Confirm reboot
                $confirmReboot = Read-Host "Do you want to reboot the machine? (Y/N)"
                if ($confirmReboot -eq 'Y' -or $confirmReboot -eq 'y') {
                    # Reboot the machine
                    Write-host "Rebooting the machine..."
                    Restart-Computer -Force
                } else {
                    Write-Host "Reboot canceled."
                }
            }
            4 {
                # Verify Secure Boot DB update
                $secureBootDB = [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI db).bytes)
                if ($secureBootDB -match 'Windows UEFI CA 2023') {
                    Write-Host "Secure Boot DB update was successful." -ForegroundColor Green
                } else {
                    Write-Host "Secure Boot DB update verification failed. Please check the update status." -ForegroundColor Red
                }
            }
            5 {
                # Exit
                Write-Host "Exiting Secure Boot Update Menu."
            }
            default {
                # Invalid selection
                Write-Host "Invalid selection. Please enter a number between 1 and 5."
            }
        }
    }
    catch {
        # Catch any errors and display them
        Write-Host "An error occurred: $_" -ForegroundColor Red
    }    

    if ($choice -ne 5) {
        # Prompt to continue
        $null = Read-Host "Press Enter to continue..."
    }

} while ($choice -ne 5)