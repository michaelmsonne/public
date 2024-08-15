<#	
	.NOTES
	===========================================================================
	 Created on:   	11-08-2024 10:58
	 Created by:   	Michael Morten Sonne
	 Organization: 	Sonne´s Cloud
	 Filename:     	"Clear-MDISensorInstallation.ps1"
	 Version:		1.0
	===========================================================================
	.DESCRIPTION
        This script will remove the Microsoft Defender for Identity sensor installation from the host.

        It will cleanup the following:
        - Disable, stop and remove the services
        - Stop the processes running
        - Remove the running named pipes
        - Uninstall NPCAP
        - Remove the sensor installation folders
        - Remove the sensor installation files
        - Remove the sensor installation registry keys
        - Remove the ATP certificate

        The script will also display a warning banner before proceeding with the removal of the sensor installation.

    .EXAMPLE
        Uninstall the Microsoft Defender for Identity sensor installation from the host in normal mode:

        .\Clear-MDISensorInstallation.ps1

    .EXAMPLE
        Uninstall the Microsoft Defender for Identity sensor installation from the host in debug mode:

        .\Clear-MDISensorInstallation.ps1 -Debug

    .CHANGELOG
        1.0 - 15-08-2024 - Initial version of the script
#>

param (
    [switch]$Debug # Enable debug mode for verbose output
)

# Define the regex pattern for GUID validation
$REGEX_GUID = '(?<guid>[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12})'

# Function to validate that the path is not a root key
function IsValidRegistryPath {
    param (
        [string]$path,
        [string]$guid
    )
    # Check if the path ends with the GUID (either with or without braces)
    return $path -and $null -ne $path -and $guid -and ($path -like "*\$guid" -or $path -like "*\{$guid\}")
}

function Invoke-AsAdministrator {
    # Check if the script is running as an administrator
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        # Tell the user that the script needs to be run as an administrator
        Write-Host "This script needs to be run as an administrator!" -ForegroundColor Red

        # Ask the user if they want to restart the script as an administrator
        $confirmation = Read-Host "Do you want to restart the script as an administrator? (y/n)"
        if ($confirmation -ne "y") {
            Write-Host "Exiting the script..." -ForegroundColor Yellow
            Exit
        }

        # Restart the script as an administrator
        Write-Host "Restarting the script as an administrator..." -ForegroundColor Yellow
        Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
        
        # Exit the current script
        Exit
    }
    else {
        # Tell the user that the script is running as an administrator - all good
        Write-Host "Running as an administrator... All good!" -ForegroundColor Green
    }
}

function Remove-ATPCertiticate {
    # Remove the ATP certificate from Computer store based on name where the CN = "Azure ATP Sensor"
    $certificateName = "Azure ATP Sensor"
    $certificates = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object { $_.Subject -like "*$certificateName*" }

    # Check if the certificate exists and meets the criteria
    if ($certificates.Count -eq 0) {
        Write-Host "No certificates found with the name: '$certificateName' and meets on the criterias" -ForegroundColor Yellow
    } else {
        # Filter the certificates based on the criteria that the certificate is valid for 2 years
        $validCertificates = $certificates | Where-Object {
            ($_.NotAfter - $_.NotBefore).Days -ge 730
        }

        # Check if no valid certificates exists
        if ($validCertificates.Count -eq 0) {
            Write-Host "No certificates found with the name: '$certificateName' that are valid for 2 years." -ForegroundColor Yellow
        } else {
            # Display the found certificates based on the criterias and ask for confirmation to remove them if any
            Write-Host "`nFound the following certificates based on the criterias:`n"
            Write-Host "----------------------------------------"
            foreach ($certificate in $validCertificates) {
                Write-Host "Subject: $($certificate.Subject), Issued Date: $($certificate.NotBefore), Expiration Date: $($certificate.NotAfter), Thumbprint: $($certificate.Thumbprint)" -ForegroundColor Yellow
                Write-Host "----------------------------------------"
            }

            # Ask for confirmation to remove the certificates
            $confirmation = Read-Host "`nDo you want to remove all these certificates? (y/n)"
            if ($confirmation -eq "y") {
                Write-Host ""
                foreach ($certificate in $validCertificates) {
                    try {
                        Remove-Item -Path $certificate.PSPath -Force
                        Write-Host "Removed certificate: $($certificate.Subject), $($certificate.Thumbprint)" -ForegroundColor Green
                    }
                    catch {
                        Write-Host "Failed to remove certificate: $($certificate.Subject), $($certificate.Thumbprint) - Error: $_" -ForegroundColor Red
                    }
                }
            } else {
                Write-Host "Skipped removal of certificates." -ForegroundColor Yellow
            }
        }
    }
}

function Stop-NamedPipes {
    param (
        [string]$aatpsensorPID,
        [string]$aatpsensorUpdaterPID
    )

    # Stop the named pipes to console
    Write-Host "Stopping named pipes..."

    # Define the named pipes
    $namedPipes = @(
        "\\.\pipe\CPFATP_${aatpsensorPID}_v4.0.30319",
        "\\.\pipe\CPFATP_${aatpsensorUpdaterPID}_v4.0.30319"
    )

    # Loop through each named pipe and attempt to stop the service
    foreach ($namedPipe in $namedPipes) {
        if (Test-Path -Path $namedPipe) {
            try {
                Stop-Service -Name $namedPipe -Force -ErrorAction SilentlyContinue
                Write-Host "Stopped named pipe: $namedPipe" -ForegroundColor Green
            }
            catch {
                Write-Host "Failed to stop named pipe: $namedPipe - Error: $_" -ForegroundColor Red
            }
        } else {
            Write-Host "Named pipe does not exist: $namedPipe - skipping!" -ForegroundColor Yellow
        }
    }
}

function Disable-Services {
    # Disable the services:
    Write-Host "Disabling services..."
    try {
        # Check if the services exist before disabling them
        $aatpsensorService = Get-Service -Name aatpsensor -ErrorAction SilentlyContinue
        $aatpsensorUpdaterService = Get-Service -Name aatpsensorupdater -ErrorAction SilentlyContinue

        # If the services exist, disable them
        if ($aatpsensorService -and $aatpsensorUpdaterService) {
            Set-Service -Name aatpsensor -StartupType Disabled
            Set-Service -Name aatpsensorupdater -StartupType Disabled
        }       
        
        # Check if the services are disabled
        $aatpsensorService = Get-Service -Name aatpsensor -ErrorAction SilentlyContinue
        $aatpsensorUpdaterService = Get-Service -Name aatpsensorupdater -ErrorAction SilentlyContinue

        if ($null -eq $aatpsensorService -and $null -eq $aatpsensorUpdaterService) {
            Write-Host "Both services not found." -ForegroundColor Green
        } elseif ($null -eq $aatpsensorService) {
            Write-Host "aatpsensor service not found."
        } elseif ($null -eq $aatpsensorUpdaterService) {
            Write-Host "aatpsensorupdater service not found."
        } elseif ($aatpsensorService.StartType -eq 'Disabled' -and $aatpsensorUpdaterService.StartType -eq 'Disabled') {
            Write-Host "Both services disabled successfully." -ForegroundColor Green
        } elseif ($aatpsensorService.StartType -eq 'Disabled') {
            Write-Host "aatpsensor service disabled successfully, but failed to disable aatpsensorupdater service." -ForegroundColor Yellow
        } elseif ($aatpsensorUpdaterService.StartType -eq 'Disabled') {
            Write-Host "aatpsensorupdater service disabled successfully, but failed to disable aatpsensor service." -ForegroundColor Yellow
        } else {
            Write-Host "Failed to disable services - Error: $_" -ForegroundColor Red
        }
    }
    catch {
        Write-Host "Failed to disable services - Error: $_" -ForegroundColor Red
    }
}

function Stop-Services{
    # Stop the services:
    Write-Host "Stopping services..."
    try {
        # Check if the services exist before stopping them
        $aatpsensorService = Get-Service -Name aatpsensor -ErrorAction SilentlyContinue
        $aatpsensorUpdaterService = Get-Service -Name aatpsensorupdater -ErrorAction SilentlyContinue

        # If the services exist, stop them
        if ($aatpsensorService -and $aatpsensorUpdaterService) {
            Stop-Service -Name aatpsensorupdater -Force
            Stop-Service -Name aatpsensor -Force
        }
        
        # Check if the services are stopped
        $aatpsensorService = Get-Service -Name aatpsensor -ErrorAction SilentlyContinue
        $aatpsensorUpdaterService = Get-Service -Name aatpsensorupdater -ErrorAction SilentlyContinue

        if ($null -eq $aatpsensorService -and $null -eq $aatpsensorUpdaterService) {
            Write-Host "Both services not found so cant stop them." -ForegroundColor Green
        } elseif ($null -eq $aatpsensorService) {
            Write-Host "aatpsensor service not found."
        } elseif ($null -eq $aatpsensorUpdaterService) {
            Write-Host "aatpsensorupdater service not found."
        } elseif ($aatpsensorService.Status -eq 'Stopped' -and $aatpsensorUpdaterService.Status -eq 'Stopped') {
            Write-Host "Both services stopped successfully." -ForegroundColor Green
        } elseif ($aatpsensorService.Status -eq 'Stopped') {
            Write-Host "aatpsensor service stopped successfully, but failed to stop aatpsensorupdater service." -ForegroundColor Yellow
        } elseif ($aatpsensorUpdaterService.Status -eq 'Stopped') {
            Write-Host "aatpsensorupdater service stopped successfully, but failed to stop aatpsensor service." -ForegroundColor Yellow
        } else {
            Write-Host "Failed to stop services - Error: $_" -ForegroundColor Red
        }
    }
    catch {
        Write-Host "Failed to stop services - Error: $_" -ForegroundColor Red
    }
}

function Remove-Services
{
    # Remove the services:
    Write-Host "Removing services..."
    try {
        C:\Windows\System32\sc.exe delete aatpsensorupdater | Out-Null
        C:\Windows\System32\sc.exe delete aatpsensor | Out-Null
        
        # Check if the services are removed
        $aatpsensorService = Get-Service -Name aatpsensor -ErrorAction SilentlyContinue
        $aatpsensorUpdaterService = Get-Service -Name aatpsensorupdater -ErrorAction SilentlyContinue

        # Check if the services are removed successfully or not
        if ($null -eq $aatpsensorService -and $null -eq $aatpsensorUpdaterService) {
            Write-Host "Both services removed successfully." -ForegroundColor Green
        } elseif ($null -eq $aatpsensorService) {
            Write-Host "aatpsensor service removed successfully, but aatpsensorupdater service still exists." -ForegroundColor Yellow
        } elseif ($null -eq $aatpsensorUpdaterService) {
            Write-Host "aatpsensorupdater service removed successfully, but aatpsensor service still exists." -ForegroundColor Yellow
        } else {
            Write-Host "Failed to remove services - Error: $_" -ForegroundColor Red
        }
    }
    catch {
        Write-Host "Failed to remove services - Error: $_" -ForegroundColor Red
    }
}

function Stop-Processes{
    # Stop processes if they are running:
    Write-Host "Stopping processes..."

    # Define the processes to stop
    $processesToStop = @(
        'Microsoft.Tri.Sensor.exe',
        'Microsoft.Tri.Sensor.Updater.exe'
    )

    # Loop through each process and attempt to stop it
    foreach ($process in $processesToStop) {
        $runningProcess = Get-Process -Name $process -ErrorAction SilentlyContinue
        if ($runningProcess) {
            try {
                Stop-Process -Name $process -Force -ErrorAction SilentlyContinue
                Write-Host "Stopped process: $process" -ForegroundColor Green
            }
            catch {
                Write-Host "Failed to stop process: $process - Error: $_" -ForegroundColor Red
            }
        } else {
            Write-Host "Process not running: $process - skipping!" -ForegroundColor Yellow
        }
    }

    # Check if the processes are stopped
    $runningProcesses = $processesToStop | ForEach-Object { Get-Process -Name $_ -ErrorAction SilentlyContinue }
    if ($runningProcesses) {
        Write-Host "Failed to stop all processes - still running: $($runningProcesses.Name -join ', ')" -ForegroundColor Red
    } else {
        Write-Host "All processes stopped successfully." -ForegroundColor Green
    }
}

function Uninstall-NPCAP {
    Write-Host "Checking for NPCAP installation..."

    # Define the path to the NPCAP uninstaller
    $npcapUninstallPath = "C:\Program Files\Npcap\Uninstall.exe"

    # Check if the NPCAP installation exists
    if (Test-Path -Path $npcapUninstallPath) {
        try {
            # Uninstall NPCAP silently
            Write-Host "Uninstalling NPCAP..."
            Start-Process -FilePath $npcapUninstallPath -ArgumentList "/S" -Wait
            Write-Host "NPCAP uninstalled process ended successfully - will check if ininstalled..." -ForegroundColor Green

            # Check if the NPCAP installation is removed
            if (Test-Path -Path $npcapUninstallPath) {
                Write-Host "Failed to uninstall NPCAP - Uninstall.exe still exists!" -ForegroundColor Red
            } else {
                Write-Host "NPCAP uninstalled successfully." -ForegroundColor Green

                # Delete the NPCAP folder
                try {
                    Remove-Item -Path "C:\Program Files\Npcap" -Force -Recurse
                    Write-Host "Removed NPCAP folder." -ForegroundColor Green
                }
                catch {
                    Write-Host "Failed to remove NPCAP folder - Error: $_" -ForegroundColor Red
                }
            }
        }
        catch {
            # Display an error message if the NPCAP uninstallation fails
            Write-Host "Failed to uninstall NPCAP - Error: $_" -ForegroundColor Red
        }
    } else {
        # Display a message if NPCAP is not installed
        Write-Host "NPCAP is not installed." -ForegroundColor Yellow
    }
}

function Clear-MDISensorInstallation {
    # Get the PID of the services (needed for later use)
    $aatpsensorPID = Get-WmiObject -Class Win32_Service | Where-Object { $_.Name -eq 'aatpsensor' } | Select-Object -ExpandProperty ProcessId
    $aatpsensorUpdaterPID = Get-WmiObject -Class Win32_Service | Where-Object { $_.Name -eq 'aatpsensorupdater' } | Select-Object -ExpandProperty ProcessId

    # Call the functions to disable the services
    Disable-Services

    # Call the functions to stop the services
    Stop-Services

    # Call the functions to remove the services
    Remove-Services

    # Call the function to stop the processes
    Stop-Processes

    # Call the function to remove the running named pipes
    Stop-NamedPipes -aatpsensorPID $aatpsensorPID -aatpsensorUpdaterPID $aatpsensorUpdaterPID

    # Call the function to uninstall NPCAP
    Uninstall-NPCAP

    # Find GUID´s and remove folders:
    Write-Host "Finding GUID´s..."
    $foldersToRemove = @('C:\Program Files\Azure Advanced Threat Protection Sensor')
    $folder1Path = (Get-ChildItem -Path 'C:\ProgramData\Package Cache\*\Microsoft.Tri.Sensor.Deployment.Package.msi').Directory.FullName
    if ($folder1Path -match $REGEX_GUID) {
        $guid1 = $Matches['guid']
        $foldersToRemove += $folder1Path

        # Output the found GUID
        if ($guid1) {
            Write-Host "Found GUID1: $guid1 - Package Cache for .msi file" -ForegroundColor Green
        } else {
            Write-Host "GUID1 for Package Cache .msi file not found." -ForegroundColor Yellow
        }
    }
    else {
        Write-Host "GUID1 for Package Cache .msi file not found." -ForegroundColor Yellow
    }

    $folder2Path = (Get-ChildItem -Path 'C:\ProgramData\Package Cache\*\Azure ATP Sensor Setup.exe').Directory.FullName
    if ($folder2Path -match $REGEX_GUID) {
        $guid2 = $Matches['guid']
        $foldersToRemove += $folder2Path

        # Output the found GUID
        if ($guid2) {
            Write-Host "Found GUID2: $guid2 - Package Cache for .exe file" -ForegroundColor Green
        } else {
            Write-Host "GUID2 for Package Cache .exe file not found." -ForegroundColor Yellow
        }
    }
    else {
        Write-Host "GUID2 for Package Cache .exe file not found." -ForegroundColor Yellow
    }

    # Define the registry path and the display name to search for
    $baseRegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products"
    $targetDisplayName = "Azure Advanced Threat Protection Sensor"

    # Get all subkeys under the base registry path
    $subKeys = Get-ChildItem -Path $baseRegistryPath

    # Initialize a variable to store the found GUID
    $foundGuid3 = $null

    # Iterate through each subkey to check the DisplayName value
    foreach ($subKey in $subKeys) {
        $installPropertiesPath = "$($subKey.PSPath)\InstallProperties"
        if (Test-Path -Path $installPropertiesPath) {
            $displayName = Get-ItemProperty -Path $installPropertiesPath -Name DisplayName -ErrorAction SilentlyContinue
            if ($displayName.DisplayName -eq $targetDisplayName) {
                $foundGuid3 = $subKey.PSChildName
                break
            }
        }
    }

    # Output the found GUID
    if ($foundGuid3) {
        Write-Host "Found GUID3: $foundGuid3 - for Windows Installer database" -ForegroundColor Green
        $guid3 = $foundGuid3
    } else {
        Write-Host "GUID3 for Windows Installer database not found." -ForegroundColor Yellow
    }
    <#
    if ($foundGuid -match $REGEX_GUID) {
        $guid3 = $Matches['guid']
    }
    #>

    # Find the GUID in the specified registry path and save it as guid4
    $componentPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Components"
    $guid4 = $null
    $targetValue = 'C:\Microsoft.Tri.Sensor.Deployment.Deployer.exe'
    if (Test-Path -Path $componentPath) {
        $subKeys = Get-ChildItem -Path $componentPath
        foreach ($subKey in $subKeys) {
            $keyPath = "$componentPath\$($subKey.PSChildName)"
            $keyProperties = Get-ItemProperty -Path $keyPath -ErrorAction SilentlyContinue
            foreach ($property in $keyProperties.PSObject.Properties) {
                if ($property.Value -eq $targetValue) {
                    $guid4 = $subKey.PSChildName
                    Write-Host "Found GUID4: $guid4 - for Windows Installer database components" -ForegroundColor Green
                    break
                }
            }
            if ($guid4) { break }
        }
        if (-not $guid4) {
            Write-Host "GUID4 for Windows Installer database components not found." -ForegroundColor Yellow
        }
    } else {
        Write-Host "Specified registry path for GUID4 (Windows Installer database components) does not exist." -ForegroundColor Yellow
    }

    # Remove folders
    Write-Host "Removing folders..."

    # Loop through each folder and attempt to remove it - based on the found GUIDs and folders
    $foldersToRemove | ForEach-Object {
        Write-Host "Trying to remove folder: $_"

        # Check if the folder exists before removing it
        if (Test-Path -Path $_) {
            try {
                # Remove the folder
                Remove-Item -Path $_ -Force -Recurse -ErrorAction SilentlyContinue
                Write-Host "Removed folder: $_" -ForegroundColor Green
            }
            catch {
                # Display an error message if the folder removal fails
                Write-Host "Failed to remove folder: $_ - Error: $_" -ForegroundColor Red
            }
        } else {
            # Display a message if the folder does not exist
            Write-Host "Folder does not exist: $_ - skipping!" -ForegroundColor Yellow
        }
    }

    # Remove files:
    Write-Host "Removing files..."
    $filesToRemove = @(
        'C:\Microsoft.Tri.Sensor.Deployment.Deployer.exe'
    )
    # Loop through each file and attempt to remove it
    foreach($filePath in $filesToRemove) {
        # Check if the file exists before removing it
        if (Test-Path -Path $filePath) {
            try {
                # Remove the file
                Remove-Item -Path $filePath -Force -ErrorAction SilentlyContinue
                Write-Host "Removed file: $filePath" -ForegroundColor Green
            }
            catch {
                # Display an error message if the file removal fails
                Write-Host "Failed to remove file: $filePath - Error: $_" -ForegroundColor Red
            }
        } else {
            # Display a message if the file does not exist
            Write-Host "File does not exist: $filePath - skipping!" -ForegroundColor Yellow
        }
    }

    # Remove registry:
    $regPathsToRemove = @(
        'HKLM:\SOFTWARE\Classes\Installer\Products\{0}',
        'HKLM:\SOFTWARE\Classes\Installer\Features\{0}',
        'HKLM:\SOFTWARE\Classes\Installer\Dependencies\{0}',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{0}',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{0}',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\{0}',
        'HKLM:\SOFTWARE\Classes\Installer\UpgradeCodes\{0}',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Components\{0}',
        'HKCR:\Installer\UpgradeCodes\{0}'
    )  

    foreach($regPath in $regPathsToRemove) {
        # Ensure the GUIDs are not null or empty before processing
    
        # Remove the registry keys based on the found GUIDs
        if ($guid1) {
            $guidWithBraces = "{$guid1}"
            $guidWithoutBraces = $guid1.Trim('{}')

            # Paths to delete using GUID with braces
            $pathToDelete1 = ($regPath -f $guidWithBraces)
            $pathToDelete1NoBraces = ($regPath -f $guidWithoutBraces)

            # Attempt to delete paths with braces
            if (IsValidRegistryPath -path $pathToDelete1 -guid $guidWithBraces) {
                # Check if the registry key exists before removing it
                if (Test-Path -Path $pathToDelete1) {
                    Write-Host "Attempting to remove registry key: $pathToDelete1"
                    try {
                        Remove-Item -Path $pathToDelete1 -Recurse -Force
                        Write-Host "Removed registry key: $pathToDelete1" -ForegroundColor Green
                    }
                    catch {
                        Write-Host "Failed to remove registry key: $pathToDelete1 - Error: $_" -ForegroundColor Red
                    }
                } else {
                    if ($Debug)
                    {
                        Write-Host "Registry key does not exist: $pathToDelete1 - skipping (not needed to exist)!" -ForegroundColor Yellow
                    }                    
                }
            } else {
                Write-Host "Skipping invalid registry key: $pathToDelete1" -ForegroundColor Yellow
            }

            # Attempt to delete paths without braces
            if (IsValidRegistryPath -path $pathToDelete1NoBraces -guid $guidWithoutBraces) {
                # Check if the registry key exists before removing it
                if (Test-Path -Path $pathToDelete1NoBraces) {
                    Write-Host "Attempting to remove registry key: $pathToDelete1NoBraces"
                    try {
                        Remove-Item -Path $pathToDelete1NoBraces -Recurse -Force
                        if (-not (Test-Path -Path $pathToDelete1NoBraces)) {
                            Write-Host "Removed registry key: $pathToDelete1NoBraces" -ForegroundColor Green
                        } else {
                            Write-Host "Failed to remove registry key: $pathToDelete1NoBraces - Error: $_" -ForegroundColor Red
                        }
                    }
                    catch {
                        Write-Host "Failed to remove registry key: $pathToDelete1NoBraces" -ForegroundColor Red
                    }
                } else {
                    if ($Debug)
                    {
                        Write-Host "Registry key does not exist: $pathToDelete1NoBraces - skipping (not needed to exist)!" -ForegroundColor Yellow
                    }                    
                }
            } else {
                Write-Host "Skipping invalid registry key: $pathToDelete1NoBraces" -ForegroundColor Yellow
            }
        }

        if ($guid2) {
            $guid2WithBraces = "{$guid2}"
            $guid2WithoutBraces = $guid2.Trim('{}')

            # Paths to delete using GUID with braces
            $pathToDelete2 = ($regPath -f $guid2WithBraces)
            $pathToDelete2NoBraces = ($regPath -f $guid2WithoutBraces)

            # Attempt to delete paths with braces
            if (IsValidRegistryPath -path $pathToDelete2 -guid $guid2WithBraces) {
                # Check if the registry key exists before removing it
                if (Test-Path -Path $pathToDelete2) {
                    Write-Host "Attempting to remove registry key: $pathToDelete2"
                    try {
                        Remove-Item -Path $pathToDelete2 -Recurse -Force
                        if (-not (Test-Path -Path $pathToDelete2)) {
                            Write-Host "Removed registry key: $pathToDelete2" -ForegroundColor Green
                        } else {
                            Write-Host "Failed to remove registry key: $pathToDelete2 - Error: $_" -ForegroundColor Red
                        }
                    }
                    catch {
                        Write-Host "Failed to remove registry key: $pathToDelete2" -ForegroundColor Red
                    }
                } else {
                    if ($Debug)
                    {
                        Write-Host "Registry key does not exist: $pathToDelete2 - skipping (not needed to exist)!" -ForegroundColor Yellow
                    }                    
                }
            } else {
                Write-Host "Skipping invalid registry key: $pathToDelete2" -ForegroundColor Yellow
            }

            # Attempt to delete paths without braces
            if (IsValidRegistryPath -path $pathToDelete2NoBraces -guid $guid2WithoutBraces) {
                # Check if the registry key exists before removing it
                if (Test-Path -Path $pathToDelete2NoBraces) {
                    Write-Host "Attempting to remove registry key: $pathToDelete2NoBraces"
                    try {
                        Remove-Item -Path $pathToDelete2NoBraces -Recurse -Force
                        if (-not (Test-Path -Path $pathToDelete2NoBraces)) {
                            Write-Host "Removed registry key: $pathToDelete2NoBraces" -ForegroundColor Green
                        } else {
                            Write-Host "Failed to remove registry key: $pathToDelete2NoBraces - Error: $_" -ForegroundColor Red
                        }
                    }
                    catch {
                        Write-Host "Failed to remove registry key: $pathToDelete2NoBraces" -ForegroundColor Red
                    }
                } else {
                    if ($Debug)
                    {
                        Write-Host "Registry key does not exist: $pathToDelete2NoBraces - skipping (not needed to exist)!" -ForegroundColor Yellow
                    }                    
                }
            } else {
                Write-Host "Skipping invalid registry key: $pathToDelete2NoBraces" -ForegroundColor Yellow
            }
        }

        if ($guid3) {
            $guid3WithBraces = "{$guid3}"
            $guid3WithoutBraces = $guid3.Trim('{}')

            # Paths to delete using GUID with braces
            $pathToDelete3 = ($regPath -f $guid3WithBraces)
            $pathToDelete3NoBraces = ($regPath -f $guid3WithoutBraces)

            # Attempt to delete paths with braces
            if (IsValidRegistryPath -path $pathToDelete3 -guid $guid3WithBraces) {
                # Check if the registry key exists before removing it
                if (Test-Path -Path $pathToDelete3) {
                    Write-Host "Attempting to remove registry key: $pathToDelete3"
                    try {
                        Remove-Item -Path $pathToDelete3 -Recurse -Force
                        if (-not (Test-Path -Path $pathToDelete3)) {
                            Write-Host "Removed registry key: $pathToDelete3" -ForegroundColor Green
                        } else {
                            Write-Host "Failed to remove registry key: $pathToDelete3 - Error: $_" -ForegroundColor Red
                        }
                    }
                    catch {
                        Write-Host "Failed to remove registry key: $pathToDelete3" -ForegroundColor Red
                    }
                } else {
                    if ($Debug)
                    {
                        Write-Host "Registry key does not exist: $pathToDelete3 - skipping (not needed to exist)!" -ForegroundColor Yellow
                    }                    
                }
            } else {
                Write-Host "Skipping invalid registry key: $pathToDelete3" -ForegroundColor Yellow
            }

            # Attempt to delete paths without braces
            if (IsValidRegistryPath -path $pathToDelete3NoBraces -guid $guid3WithoutBraces) {
                if (Test-Path -Path $pathToDelete3NoBraces) {
                    # Check if the registry key exists before removing it
                    Write-Host "Attempting to remove registry key: $pathToDelete3NoBraces"
                    try {
                        Remove-Item -Path $pathToDelete3NoBraces -Recurse -Force
                        if (-not (Test-Path -Path $pathToDelete3NoBraces)) {
                            Write-Host "Removed registry key: $pathToDelete3NoBraces" -ForegroundColor Green
                        } else {
                            Write-Host "Failed to remove registry key: $pathToDelete3NoBraces - Error: $_" -ForegroundColor Red
                        }
                    }
                    catch {
                        Write-Host "Failed to remove registry key: $pathToDelete3NoBraces" -ForegroundColor Red
                    }
                } else {
                    if ($Debug)
                    {
                        Write-Host "Registry key does not exist: $pathToDelete3NoBraces - skipping (not needed to exist)!" -ForegroundColor Yellow
                    }                    
                }
            } else {
                Write-Host "Skipping invalid registry key: $pathToDelete3NoBraces" -ForegroundColor Yellow
            }
        }

        if ($guid4) {
            $guid4WithBraces = "{$guid4}"
            $guid4WithoutBraces = $guid4.Trim('{}')

            # Paths to delete using GUID with braces
            $pathToDelete4 = ($regPath -f $guid4WithBraces)
            $pathToDelete4NoBraces = ($regPath -f $guid4WithoutBraces)

            # Attempt to delete paths with braces
            if (IsValidRegistryPath -path $pathToDelete4 -guid $guid4WithBraces) {
                # Check if the registry key exists before removing it
                if (Test-Path -Path $pathToDelete4) {
                    Write-Host "Attempting to remove registry key: $pathToDelete4"
                    try {
                        Remove-Item -Path $pathToDelete4 -Recurse -Force
                        if (-not (Test-Path -Path $pathToDelete4)) {
                            Write-Host "Removed registry key: $pathToDelete4" -ForegroundColor Green
                        } else {
                            Write-Host "Failed to remove registry key: $pathToDelete4 - Error: $_" -ForegroundColor
                        }
                    }
                    catch {
                        Write-Host "Failed to remove registry key: $pathToDelete4" -ForegroundColor Red
                    }
                } else {
                    if ($Debug)
                    {
                        Write-Host "Registry key does not exist: $pathToDelete4 - skipping (not needed to exist)!" -ForegroundColor Yellow
                    }                    
                }
            } else {
                Write-Host "Skipping invalid registry key: $pathToDelete4" -ForegroundColor Yellow
            }

            # Attempt to delete paths without braces
            if (IsValidRegistryPath -path $pathToDelete4NoBraces -guid $guid4WithoutBraces) {
                # Check if the registry key exists before removing it
                if (Test-Path -Path $pathToDelete4NoBraces) {
                    Write-Host "Attempting to remove registry key: $pathToDelete4NoBraces"
                    try {
                        Remove-Item -Path $pathToDelete4NoBraces -Recurse -Force
                        if (-not (Test-Path -Path $pathToDelete4NoBraces)) {
                            Write-Host "Removed registry key: $pathToDelete4NoBraces" -ForegroundColor Green
                        } else {
                            Write-Host "Failed to remove registry key: $pathToDelete4NoBraces - Error: $_" -ForegroundColor Red
                        }
                    }
                    catch {
                        Write-Host "Failed to remove registry key: $pathToDelete4NoBraces" -ForegroundColor Red
                    }
                } else {
                    if ($Debug)
                    {
                        Write-Host "Registry key does not exist: $pathToDelete4NoBraces - skipping (not needed to exist)!" -ForegroundColor Yellow
                    }                    
                }
            } else {
                Write-Host "Skipping invalid registry key: $pathToDelete4NoBraces" -ForegroundColor Yellow
            }
        }
    }

    # Call the function to remove the ATP certificate
    Remove-ATPCertiticate

    # Display done message as a banner
    $bannerMessage = "Manual removal tasks completed successfully on $($env:COMPUTERNAME)!`n`nRemember to remove the sensor from the Microsoft Defender for Identity portal here:`n`nhttps://security.microsoft.com/securitysettings/identities?tabid=sensor"

    # Split the message into lines and find the length of the longest line
    $bannerLines = $bannerMessage -split "`n"
    $maxLineLength = ($bannerLines | Measure-Object -Property Length -Maximum).Maximum

    # Add padding for the border
    $bannerLength = $maxLineLength + 4
    $bannerBorder = "*" * $bannerLength

    Write-Host ""
    Write-Host $bannerBorder -ForegroundColor Green

    # Write each line with padding
    foreach ($line in $bannerLines) {
        $paddedLine = "* " + $line.PadRight($maxLineLength) + " *"
        Write-Host $paddedLine -ForegroundColor Green
    }

    Write-Host $bannerBorder -ForegroundColor Green
    Write-Host ""
}

# Run the script as an administrator/check if the script is running as an administrator
Invoke-AsAdministrator

# Display a risk warning banner
# Define the warning messages with new lines before and after
$warningMessages = @(
    "",
    "WARNING: Removing the Microsoft Defender for Identity sensor manually can have serious consequences.",
    "Accept the risk before proceeding!",
    ""
)

# Calculate the length of the banner based on the longest line
$bannerLength = ($warningMessages | Measure-Object -Maximum Length).Maximum + 4
$bannerBorder = "*" * $bannerLength + "*"

# Create the banner
$banner = $bannerBorder + "`n"
foreach ($message in $warningMessages) {
    $paddedMessage = "* " + $message.PadRight($bannerLength - 3) + " *"
    $banner += $paddedMessage + "`n"
}
$banner += $bannerBorder

# Display the banner
Write-Host ""
Write-Host $banner -ForegroundColor Red
Write-Host ""

# Show beta warning message
Write-Host "This script is in beta and may not work as expected. Use at your own risk!`n" -ForegroundColor Yellow

# Ask to confirm the removal of the registry keys, files, services, and the sensor installation
$confirm = Read-Host "Do you accept the risk and want to remove the sensor installation? (Y/N)"
if ($confirm -eq "Y") {
    #Ask for confirmation before proceeding again
    Write-Host "`n!! This action is irreversible and may cause issues with the sensor installation !!`n" -ForegroundColor Red
    $confirm2 = Read-Host "Are you still sure you want to remove the sensor installation??! (Y/N)"
    if ($confirm2 -eq "Y") {
        Write-Host ""
        Clear-MDISensorInstallation
    } else {
        Write-Host "`nSensor installation not removed - not confirmed by user second time" -ForegroundColor Yellow
    }
} else {
    Write-Host "`nSensor installation not removed - not confirmed by user" -ForegroundColor Yellow
}
# SIG # Begin signature block
# MIIubAYJKoZIhvcNAQcCoIIuXTCCLlkCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC2s+QkVdYP9sxS
# 1xxqHAmj7jts1Rpj1SifN3SZa38Zz6CCEd8wggVvMIIEV6ADAgECAhBI/JO0YFWU
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
# gf9SsIAod1Dx9THs2qkXIwyf5lTJBvPHLRqxs/k+Mn70AUiyj50/JYMxghvjMIIb
# 3wIBATBoMFQxCzAJBgNVBAYTAkdCMRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQx
# KzApBgNVBAMTIlNlY3RpZ28gUHVibGljIENvZGUgU2lnbmluZyBDQSBSMzYCEBHh
# oIZkh66CYIKNKPBResYwDQYJYIZIAWUDBAIBBQCgfDAQBgorBgEEAYI3AgEMMQIw
# ADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYK
# KwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgCUavGG9CnX97g5aIVN+ijqvxDr7N
# HUiU22WxBBQ+rHQwDQYJKoZIhvcNAQEBBQAEggIAoXWBTftz+U3SJrV85+np/v2x
# W/N0vF/qiD0DYNnTW2Gc8Kl2L5ThoFhqYUQaw/sVoViT/rj9STx9xf+xLJGPLIzD
# 5xN9LtPDR+7WRvSYgBbocYwM6ZMTEBgWXZBAdtcr+QX0af1F/fwkXNQvXWjx0ffn
# JG1kj2LXUoRb23TIucLp3cfmYFVh1B/q7WluROc2NimlFJDrvyM9xL/piiQ+juSk
# vm6uchGiyuIj6fb71JJkNfKAu8AD2L2ie0/K/Nl1BgZ5VwsNEdN+YYkeFkN4j9M9
# RB1O9KfH6bI+ENCiKxu6nA1Ou2AjH5Ny7Iau3uSS3Tmi9FX2ink37Ish2RwFYf+3
# jrEowZGin84ykEPfTeRsBdTnkmffhXXT923B61RrPNnqEhnNqMHxB3cCLEvewmgY
# RubvcqvIOfXlMfNqqLPnfBt2FjM4vncdJwTBizty0SP1qtsHiDiJTNoGAtPDUBZv
# 3VTmbreKGxYG4mA5v+5+w9TTbQF1pJRjRui4kjEJjamw3UVx9IXg5OpFI24bEowm
# KhVKl1ZF0e57oluK1jO1/HYLF4TpJzHeEAzykC1OaqOhOQhgtCvt+zj7xU08NBOe
# 2hUD/R5xZanBjheginH0xpp5UJUnLBCvsgMYPjnAtlFD9PG+Zbi5Nx+LHpEwSNh+
# CudzvRWJnOHZZW14pSqhghjOMIIYygYKKwYBBAGCNwMDATGCGLowghi2BgkqhkiG
# 9w0BBwKgghinMIIYowIBAzEPMA0GCWCGSAFlAwQCAgUAMIH0BgsqhkiG9w0BCRAB
# BKCB5ASB4TCB3gIBAQYKKwYBBAGyMQIBATAxMA0GCWCGSAFlAwQCAQUABCBgY6co
# EUWmJ3wIUBNBdDPNynyJKcwjdtg6YVP+wOuOnAIVANudb9mTXqnLg4YTEWyGgSoY
# K3MYGA8yMDI0MDgxNTE5MjAyMFqgcqRwMG4xCzAJBgNVBAYTAkdCMRMwEQYDVQQI
# EwpNYW5jaGVzdGVyMRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQxMDAuBgNVBAMT
# J1NlY3RpZ28gUHVibGljIFRpbWUgU3RhbXBpbmcgU2lnbmVyIFIzNaCCEv8wggZd
# MIIExaADAgECAhA6UmoshM5V5h1l/MwS2OmJMA0GCSqGSIb3DQEBDAUAMFUxCzAJ
# BgNVBAYTAkdCMRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQxLDAqBgNVBAMTI1Nl
# Y3RpZ28gUHVibGljIFRpbWUgU3RhbXBpbmcgQ0EgUjM2MB4XDTI0MDExNTAwMDAw
# MFoXDTM1MDQxNDIzNTk1OVowbjELMAkGA1UEBhMCR0IxEzARBgNVBAgTCk1hbmNo
# ZXN0ZXIxGDAWBgNVBAoTD1NlY3RpZ28gTGltaXRlZDEwMC4GA1UEAxMnU2VjdGln
# byBQdWJsaWMgVGltZSBTdGFtcGluZyBTaWduZXIgUjM1MIICIjANBgkqhkiG9w0B
# AQEFAAOCAg8AMIICCgKCAgEAjdFn9MFIm739OEk6TWGBm8PY3EWlYQQ2jQae45iW
# gPXUGVuYoIa1xjTGIyuw3suUSBzKiyG0/c/Yn++d5mG6IyayljuGT9DeXQU9k8GW
# Wj2/BPoamg2fFctnPsdTYhMGxM06z1+Ft0Bav8ybww21ii/faiy+NhiUM195+cFq
# OtCpJXxZ/lm9tpjmVmEqpAlRpfGmLhNdkqiEuDFTuD1GsV3jvuPuPGKUJTam3P53
# U4LM0UCxeDI8Qz40Qw9TPar6S02XExlc8X1YsiE6ETcTz+g1ImQ1OqFwEaxsMj/W
# oJT18GG5KiNnS7n/X4iMwboAg3IjpcvEzw4AZCZowHyCzYhnFRM4PuNMVHYcTXGg
# vuq9I7j4ke281x4e7/90Z5Wbk92RrLcS35hO30TABcGx3Q8+YLRy6o0k1w4jRefC
# MT7b5mTxtq5XPmKvtgfPuaWPkGZ/tbxInyNDA7YgOgccULjp4+D56g2iuzRCsLQ9
# ac6AN4yRbqCYsG2rcIQ5INTyI2JzA2w1vsAHPRbUTeqVLDuNOY2gYIoKBWQsPYVo
# yzaoBVU6O5TG+a1YyfWkgVVS9nXKs8hVti3VpOV3aeuaHnjgC6He2CCDL9aW6gte
# Ue0AmC8XCtWwpePx6QW3ROZo8vSUe9AR7mMdu5+FzTmW8K13Bt8GX/YBFJO7LWzw
# KAUCAwEAAaOCAY4wggGKMB8GA1UdIwQYMBaAFF9Y7UwxeqJhQo1SgLqzYZcZojKb
# MB0GA1UdDgQWBBRo76QySWm2Ujgd6kM5LPQUap4MhTAOBgNVHQ8BAf8EBAMCBsAw
# DAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDBKBgNVHSAEQzBB
# MDUGDCsGAQQBsjEBAgEDCDAlMCMGCCsGAQUFBwIBFhdodHRwczovL3NlY3RpZ28u
# Y29tL0NQUzAIBgZngQwBBAIwSgYDVR0fBEMwQTA/oD2gO4Y5aHR0cDovL2NybC5z
# ZWN0aWdvLmNvbS9TZWN0aWdvUHVibGljVGltZVN0YW1waW5nQ0FSMzYuY3JsMHoG
# CCsGAQUFBwEBBG4wbDBFBggrBgEFBQcwAoY5aHR0cDovL2NydC5zZWN0aWdvLmNv
# bS9TZWN0aWdvUHVibGljVGltZVN0YW1waW5nQ0FSMzYuY3J0MCMGCCsGAQUFBzAB
# hhdodHRwOi8vb2NzcC5zZWN0aWdvLmNvbTANBgkqhkiG9w0BAQwFAAOCAYEAsNwu
# yfpPNkyKL/bJT9XvGE8fnw7Gv/4SetmOkjK9hPPa7/Nsv5/MHuVus+aXwRFqM5Vu
# 51qfrHTwnVExcP2EHKr7IR+m/Ub7PamaeWfle5x8D0x/MsysICs00xtSNVxFywCv
# Xx55l6Wg3lXiPCui8N4s51mXS0Ht85fkXo3auZdo1O4lHzJLYX4RZovlVWD5EfwV
# 6Ve1G9UMslnm6pI0hyR0Zr95QWG0MpNPP0u05SHjq/YkPlDee3yYOECNMqnZ+j8o
# noUtZ0oC8CkbOOk/AOoV4kp/6Ql2gEp3bNC7DOTlaCmH24DjpVgryn8FMklqEoK4
# Z3IoUgV8R9qQLg1dr6/BjghGnj2XNA8ujta2JyoxpqpvyETZCYIUjIs69YiDjzft
# t37rQVwIZsfCYv+DU5sh/StFL1x4rgNj2t8GccUfa/V3iFFW9lfIJWWsvtlC5XOO
# OQswr1UmVdNWQem4LwrlLgcdO/YAnHqY52QwnBLiAuUnuBeshWmfEb5oieIYMIIG
# FDCCA/ygAwIBAgIQeiOu2lNplg+RyD5c9MfjPzANBgkqhkiG9w0BAQwFADBXMQsw
# CQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMS4wLAYDVQQDEyVT
# ZWN0aWdvIFB1YmxpYyBUaW1lIFN0YW1waW5nIFJvb3QgUjQ2MB4XDTIxMDMyMjAw
# MDAwMFoXDTM2MDMyMTIzNTk1OVowVTELMAkGA1UEBhMCR0IxGDAWBgNVBAoTD1Nl
# Y3RpZ28gTGltaXRlZDEsMCoGA1UEAxMjU2VjdGlnbyBQdWJsaWMgVGltZSBTdGFt
# cGluZyBDQSBSMzYwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQDNmNhD
# Qatugivs9jN+JjTkiYzT7yISgFQ+7yavjA6Bg+OiIjPm/N/t3nC7wYUrUlY3mFyI
# 32t2o6Ft3EtxJXCc5MmZQZ8AxCbh5c6WzeJDB9qkQVa46xiYEpc81KnBkAWgsaXn
# LURoYZzksHIzzCNxtIXnb9njZholGw9djnjkTdAA83abEOHQ4ujOGIaBhPXG2NdV
# 8TNgFWZ9BojlAvflxNMCOwkCnzlH4oCw5+4v1nssWeN1y4+RlaOywwRMUi54fr2v
# FsU5QPrgb6tSjvEUh1EC4M29YGy/SIYM8ZpHadmVjbi3Pl8hJiTWw9jiCKv31pcA
# aeijS9fc6R7DgyyLIGflmdQMwrNRxCulVq8ZpysiSYNi79tw5RHWZUEhnRfs/hsp
# /fwkXsynu1jcsUX+HuG8FLa2BNheUPtOcgw+vHJcJ8HnJCrcUWhdFczf8O+pDiyG
# hVYX+bDDP3GhGS7TmKmGnbZ9N+MpEhWmbiAVPbgkqykSkzyYVr15OApZYK8CAwEA
# AaOCAVwwggFYMB8GA1UdIwQYMBaAFPZ3at0//QET/xahbIICL9AKPRQlMB0GA1Ud
# DgQWBBRfWO1MMXqiYUKNUoC6s2GXGaIymzAOBgNVHQ8BAf8EBAMCAYYwEgYDVR0T
# AQH/BAgwBgEB/wIBADATBgNVHSUEDDAKBggrBgEFBQcDCDARBgNVHSAECjAIMAYG
# BFUdIAAwTAYDVR0fBEUwQzBBoD+gPYY7aHR0cDovL2NybC5zZWN0aWdvLmNvbS9T
# ZWN0aWdvUHVibGljVGltZVN0YW1waW5nUm9vdFI0Ni5jcmwwfAYIKwYBBQUHAQEE
# cDBuMEcGCCsGAQUFBzAChjtodHRwOi8vY3J0LnNlY3RpZ28uY29tL1NlY3RpZ29Q
# dWJsaWNUaW1lU3RhbXBpbmdSb290UjQ2LnA3YzAjBggrBgEFBQcwAYYXaHR0cDov
# L29jc3Auc2VjdGlnby5jb20wDQYJKoZIhvcNAQEMBQADggIBABLXeyCtDjVYDJ6B
# HSVY/UwtZ3Svx2ImIfZVVGnGoUaGdltoX4hDskBMZx5NY5L6SCcwDMZhHOmbyMhy
# OVJDwm1yrKYqGDHWzpwVkFJ+996jKKAXyIIaUf5JVKjccev3w16mNIUlNTkpJEor
# 7edVJZiRJVCAmWAaHcw9zP0hY3gj+fWp8MbOocI9Zn78xvm9XKGBp6rEs9sEiq/p
# wzvg2/KjXE2yWUQIkms6+yslCRqNXPjEnBnxuUB1fm6bPAV+Tsr/Qrd+mOCJemo0
# 6ldon4pJFbQd0TQVIMLv5koklInHvyaf6vATJP4DfPtKzSBPkKlOtyaFTAjD2Nu+
# di5hErEVVaMqSVbfPzd6kNXOhYm23EWm6N2s2ZHCHVhlUgHaC4ACMRCgXjYfQEDt
# YEK54dUwPJXV7icz0rgCzs9VI29DwsjVZFpO4ZIVR33LwXyPDbYFkLqYmgHjR3tK
# Vkhh9qKV2WCmBuC27pIOx6TYvyqiYbntinmpOqh/QPAnhDgexKG9GX/n1PggkGi9
# HCapZp8fRwg8RftwS21Ln61euBG0yONM6noD2XQPrFwpm3GcuqJMf0o8LLrFkSLR
# QNwxPDDkWXhW+gZswbaiie5fd/W2ygcto78XCSPfFWveUOSZ5SqK95tBO8aTHmEa
# 4lpJVD7HrTEn9jb1EGvxOb1cnn0CMIIGgjCCBGqgAwIBAgIQNsKwvXwbOuejs902
# y8l1aDANBgkqhkiG9w0BAQwFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCk5l
# dyBKZXJzZXkxFDASBgNVBAcTC0plcnNleSBDaXR5MR4wHAYDVQQKExVUaGUgVVNF
# UlRSVVNUIE5ldHdvcmsxLjAsBgNVBAMTJVVTRVJUcnVzdCBSU0EgQ2VydGlmaWNh
# dGlvbiBBdXRob3JpdHkwHhcNMjEwMzIyMDAwMDAwWhcNMzgwMTE4MjM1OTU5WjBX
# MQswCQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMS4wLAYDVQQD
# EyVTZWN0aWdvIFB1YmxpYyBUaW1lIFN0YW1waW5nIFJvb3QgUjQ2MIICIjANBgkq
# hkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAiJ3YuUVnnR3d6LkmgZpUVMB8SQWbzFoV
# D9mUEES0QUCBdxSZqdTkdizICFNeINCSJS+lV1ipnW5ihkQyC0cRLWXUJzodqpnM
# Rs46npiJPHrfLBOifjfhpdXJ2aHHsPHggGsCi7uE0awqKggE/LkYw3sqaBia67h/
# 3awoqNvGqiFRJ+OTWYmUCO2GAXsePHi+/JUNAax3kpqstbl3vcTdOGhtKShvZIvj
# wulRH87rbukNyHGWX5tNK/WABKf+Gnoi4cmisS7oSimgHUI0Wn/4elNd40BFdSZ1
# EwpuddZ+Wr7+Dfo0lcHflm/FDDrOJ3rWqauUP8hsokDoI7D/yUVI9DAE/WK3Jl3C
# 4LKwIpn1mNzMyptRwsXKrop06m7NUNHdlTDEMovXAIDGAvYynPt5lutv8lZeI5w3
# MOlCybAZDpK3Dy1MKo+6aEtE9vtiTMzz/o2dYfdP0KWZwZIXbYsTIlg1YIetCpi5
# s14qiXOpRsKqFKqav9R1R5vj3NgevsAsvxsAnI8Oa5s2oy25qhsoBIGo/zi6GpxF
# j+mOdh35Xn91y72J4RGOJEoqzEIbW3q0b2iPuWLA911cRxgY5SJYubvjay3nSMbB
# PPFsyl6mY4/WYucmyS9lo3l7jk27MAe145GWxK4O3m3gEFEIkv7kRmefDR7Oe2T1
# HxAnICQvr9sCAwEAAaOCARYwggESMB8GA1UdIwQYMBaAFFN5v1qqK0rPVIDh2JvA
# nfKyA2bLMB0GA1UdDgQWBBT2d2rdP/0BE/8WoWyCAi/QCj0UJTAOBgNVHQ8BAf8E
# BAMCAYYwDwYDVR0TAQH/BAUwAwEB/zATBgNVHSUEDDAKBggrBgEFBQcDCDARBgNV
# HSAECjAIMAYGBFUdIAAwUAYDVR0fBEkwRzBFoEOgQYY/aHR0cDovL2NybC51c2Vy
# dHJ1c3QuY29tL1VTRVJUcnVzdFJTQUNlcnRpZmljYXRpb25BdXRob3JpdHkuY3Js
# MDUGCCsGAQUFBwEBBCkwJzAlBggrBgEFBQcwAYYZaHR0cDovL29jc3AudXNlcnRy
# dXN0LmNvbTANBgkqhkiG9w0BAQwFAAOCAgEADr5lQe1oRLjlocXUEYfktzsljOt+
# 2sgXke3Y8UPEooU5y39rAARaAdAxUeiX1ktLJ3+lgxtoLQhn5cFb3GF2SSZRX8pt
# Q6IvuD3wz/LNHKpQ5nX8hjsDLRhsyeIiJsms9yAWnvdYOdEMq1W61KE9JlBkB20X
# Bee6JaXx4UBErc+YuoSb1SxVf7nkNtUjPfcxuFtrQdRMRi/fInV/AobE8Gw/8yBM
# QKKaHt5eia8ybT8Y/Ffa6HAJyz9gvEOcF1VWXG8OMeM7Vy7Bs6mSIkYeYtddU1ux
# 1dQLbEGur18ut97wgGwDiGinCwKPyFO7ApcmVJOtlw9FVJxw/mL1TbyBns4zOgka
# XFnnfzg4qbSvnrwyj1NiurMp4pmAWjR+Pb/SIduPnmFzbSN/G8reZCL4fvGlvPFk
# 4Uab/JVCSmj59+/mB2Gn6G/UYOy8k60mKcmaAZsEVkhOFuoj4we8CYyaR9vd9PGZ
# KSinaZIkvVjbH/3nlLb0a7SBIkiRzfPfS9T+JesylbHa1LtRV9U/7m0q7Ma2CQ/t
# 392ioOssXW7oKLdOmMBl14suVFBmbzrt5V5cQPnwtd3UOTpS9oCG+ZZheiIvPgkD
# mA8FzPsnfXW5qHELB43ET7HHFHeRPRYrMBKjkb8/IN7Po0d0hQoF4TeMM+zYAJzo
# KQnVKOLg8pZVPT8xggSRMIIEjQIBATBpMFUxCzAJBgNVBAYTAkdCMRgwFgYDVQQK
# Ew9TZWN0aWdvIExpbWl0ZWQxLDAqBgNVBAMTI1NlY3RpZ28gUHVibGljIFRpbWUg
# U3RhbXBpbmcgQ0EgUjM2AhA6UmoshM5V5h1l/MwS2OmJMA0GCWCGSAFlAwQCAgUA
# oIIB+TAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwHAYJKoZIhvcNAQkFMQ8X
# DTI0MDgxNTE5MjAyMFowPwYJKoZIhvcNAQkEMTIEMD+MRcW6wtKEEjK6gO6E8C7Z
# Umy5KLwG6wqKas40YfuB7/nXtwRpc2nJ7uNUQ+MASDCCAXoGCyqGSIb3DQEJEAIM
# MYIBaTCCAWUwggFhMBYEFPhgmBmm+4gs9+hSl/KhGVIaFndfMIGHBBTGrlTkeIbx
# fD1VEkiMacNKevnC3TBvMFukWTBXMQswCQYDVQQGEwJHQjEYMBYGA1UEChMPU2Vj
# dGlnbyBMaW1pdGVkMS4wLAYDVQQDEyVTZWN0aWdvIFB1YmxpYyBUaW1lIFN0YW1w
# aW5nIFJvb3QgUjQ2AhB6I67aU2mWD5HIPlz0x+M/MIG8BBSFPWMtk4KCYXzQkDXE
# kd6SwULaxzCBozCBjqSBizCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCk5ldyBK
# ZXJzZXkxFDASBgNVBAcTC0plcnNleSBDaXR5MR4wHAYDVQQKExVUaGUgVVNFUlRS
# VVNUIE5ldHdvcmsxLjAsBgNVBAMTJVVTRVJUcnVzdCBSU0EgQ2VydGlmaWNhdGlv
# biBBdXRob3JpdHkCEDbCsL18Gzrno7PdNsvJdWgwDQYJKoZIhvcNAQEBBQAEggIA
# Vxn290SRFVC8xGOg2H3RrcUMtqk2RsW5jhLmLuTdofh5gjyFxPvUjIiC9fpLuxGp
# eIXGKJm3GZGlB9RCkqJp8VajbKvAcdgX7p16p0RanaxDs8LIy3a1dpjl/1UDW7Os
# lWHRM4+omfuH6g/4061CZKvUKTEjmlBzDfg9vuFhn+hkOr2M57aBmRHLB5Atyz/H
# VvIVTpXQmF9cNhnfNcQ38VvfGxg5iLwqceMv7XKeSiYFYF4OUmBZj3V1EhIE5CXa
# wHh2bDdcAOHDrEkrW9n5wTaDd0SN0s9ctB0rSMTllPjwvZF9BfxeI1aHlZFprcus
# FbL2QUIxKyqJ/k1dpbXYG5sMrWa6lZSJAIlJCfIkR2vDCrc/YjzSnJ1dEa0CI4UO
# rcnPxygFSxqsc4K7dv+N+SEGKGGAPLvBtzcADshJ4AUtoqvtSLtr6O0bWeFksdiZ
# qFeu3kVIPE4MvkAriy+LAziN0jo4bRYqgD500/F9Rdm6VbXqC2o0t4K/a9V7uuA8
# UdR1UYA/HjF5QWernyJZbVIXprBsN5bE1fctWzZ1hryPCzKlgcKDrM1NrBZ/DFs2
# 53Ye6IWc+URXsAGmVv5kSoXbyQkx1B44ucTTzDRXB92mdT2PTBZk/N+xTDE1m8NG
# gGe6NNOf9xeVL8h8DQJby+PWeeV4cepa+eMiPqvntNU=
# SIG # End signature block
