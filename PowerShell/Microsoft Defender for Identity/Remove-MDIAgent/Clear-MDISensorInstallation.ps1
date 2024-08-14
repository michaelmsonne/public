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

    .EXAMPLE
        .\Clear-MDISensorInstallation.ps1
#>

function Clear-MDISensorInstallation {
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

    # Display a message that the script is starting
    Write-Host ""

    # Disable the services:
    Write-Host "Disabling services..."
    try {
        Set-Service -Name aatpsensor -StartupType Disabled -ErrorAction SilentlyContinue
        Set-Service -Name aatpsensorupdater -StartupType Disabled -ErrorAction SilentlyContinue
        
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

    # Stop the services:
    Write-Host "Stopping services..."
    try {
        Stop-Service -Name aatpsensor -Force -ErrorAction SilentlyContinue
        Stop-Service -Name aatpsensorupdater -Force -ErrorAction SilentlyContinue

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

    # Remove the services:
    Write-Host "Removing services..."
    try {
        C:\Windows\System32\sc.exe delete aatpsensor | Out-Null
        C:\Windows\System32\sc.exe delete aatpsensorupdater | Out-Null

        # Check if the services are removed
        $aatpsensorService = Get-Service -Name aatpsensor -ErrorAction SilentlyContinue
        $aatpsensorUpdaterService = Get-Service -Name aatpsensorupdater -ErrorAction SilentlyContinue

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
    $foldersToRemove | ForEach-Object {
        Write-Host "Trying to remove folder: $_"
        if (Test-Path -Path $_) {
            try {
                Remove-Item -Path $_ -Force -Recurse -ErrorAction SilentlyContinue
                Write-Host "Removed folder: $_" -ForegroundColor Green
            }
            catch {
                Write-Host "Failed to remove folder: $_ - Error: $_" -ForegroundColor Red
            }
        } else {
            Write-Host "Folder does not exist: $_ - skipping!" -ForegroundColor Yellow
        }
    }

    # Remove files:
    Write-Host "Removing files..."
    $filesToRemove = @(
        'C:\Microsoft.Tri.Sensor.Deployment.Deployer.exe'
    )
    foreach($filePath in $filesToRemove) {
        if (Test-Path -Path $filePath) {
            try {
                Remove-Item -Path $filePath -Force -ErrorAction SilentlyContinue
                Write-Host "Removed file: $filePath" -ForegroundColor Green
            }
            catch {
                Write-Host "Failed to remove file: $filePath - Error: $_" -ForegroundColor Red
            }
        } else {
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
    
        if ($guid1) {
            $guidWithBraces = "{$guid1}"
            $guidWithoutBraces = $guid1.Trim('{}')

            # Paths to delete using GUID with braces
            $pathToDelete1 = ($regPath -f $guidWithBraces)
            $pathToDelete1NoBraces = ($regPath -f $guidWithoutBraces)

            # Attempt to delete paths with braces
            if (IsValidRegistryPath -path $pathToDelete1 -guid $guidWithBraces) {
                if (Test-Path -Path $pathToDelete1) {
                    Write-Host "Attempting to remove registry key: $pathToDelete1"
                    try {
                        Remove-Item -Path $pathToDelete1 -Recurse -Force -ErrorAction SilentlyContinue
                        Write-Host "Removed registry key: $pathToDelete1" -ForegroundColor Green
                    }
                    catch {
                        Write-Host "Failed to remove registry key: $pathToDelete1" -ForegroundColor Red
                    }
                } else {
                    Write-Host "Registry key does not exist: $pathToDelete1 - skipping (not neede to exist)!" -ForegroundColor Yellow
                }
            } else {
                Write-Host "Skipping invalid registry key: $pathToDelete1" -ForegroundColor Yellow
            }

            # Attempt to delete paths without braces
            if (IsValidRegistryPath -path $pathToDelete1NoBraces -guid $guidWithoutBraces) {
                if (Test-Path -Path $pathToDelete1NoBraces) {
                    Write-Host "Attempting to remove registry key: $pathToDelete1NoBraces"
                    try {
                        Remove-Item -Path $pathToDelete1NoBraces -Recurse -Force -ErrorAction SilentlyContinue
                        if (-not (Test-Path -Path $pathToDelete1NoBraces)) {
                            Write-Host "Removed registry key: $pathToDelete1NoBraces" -ForegroundColor Green
                        } else {
                            Write-Host "Failed to remove registry key: $pathToDelete1NoBraces" -ForegroundColor Red
                        }
                    }
                    catch {
                        Write-Host "Failed to remove registry key: $pathToDelete1NoBraces" -ForegroundColor Red
                    }
                } else {
                    Write-Host "Registry key does not exist: $pathToDelete1NoBraces - skipping (not neede to exist)!" -ForegroundColor Yellow
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
                if (Test-Path -Path $pathToDelete2) {
                    Write-Host "Attempting to remove registry key: $pathToDelete2"
                    try {
                        Remove-Item -Path $pathToDelete2 -Recurse -Force -ErrorAction SilentlyContinue
                        if (-not (Test-Path -Path $pathToDelete2)) {
                            Write-Host "Removed registry key: $pathToDelete2" -ForegroundColor Green
                        } else {
                            Write-Host "Failed to remove registry key: $pathToDelete2" -ForegroundColor Red
                        }
                    }
                    catch {
                        Write-Host "Failed to remove registry key: $pathToDelete2" -ForegroundColor Red
                    }
                } else {
                    Write-Host "Registry key does not exist: $pathToDelete2 - skipping (not neede to exist)!" -ForegroundColor Yellow
                }
            } else {
                Write-Host "Skipping invalid registry key: $pathToDelete2" -ForegroundColor Yellow
            }

            # Attempt to delete paths without braces
            if (IsValidRegistryPath -path $pathToDelete2NoBraces -guid $guid2WithoutBraces) {
                if (Test-Path -Path $pathToDelete2NoBraces) {
                    Write-Host "Attempting to remove registry key: $pathToDelete2NoBraces"
                    try {
                        Remove-Item -Path $pathToDelete2NoBraces -Recurse -Force -ErrorAction SilentlyContinue
                        if (-not (Test-Path -Path $pathToDelete2NoBraces)) {
                            Write-Host "Removed registry key: $pathToDelete2NoBraces" -ForegroundColor Green
                        } else {
                            Write-Host "Failed to remove registry key: $pathToDelete2NoBraces" -ForegroundColor Red
                        }
                    }
                    catch {
                        Write-Host "Failed to remove registry key: $pathToDelete2NoBraces" -ForegroundColor Red
                    }
                } else {
                    Write-Host "Registry key does not exist: $pathToDelete2NoBraces - skipping (not neede to exist)!" -ForegroundColor Yellow
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
                if (Test-Path -Path $pathToDelete3) {
                    Write-Host "Attempting to remove registry key: $pathToDelete3"
                    try {
                        Remove-Item -Path $pathToDelete3 -Recurse -Force -ErrorAction SilentlyContinue
                        if (-not (Test-Path -Path $pathToDelete3)) {
                            Write-Host "Removed registry key: $pathToDelete3" -ForegroundColor Green
                        } else {
                            Write-Host "Failed to remove registry key: $pathToDelete3" -ForegroundColor Red
                        }
                    }
                    catch {
                        Write-Host "Failed to remove registry key: $pathToDelete3" -ForegroundColor Red
                    }
                } else {
                    Write-Host "Registry key does not exist: $pathToDelete3 - skipping (not neede to exist)!" -ForegroundColor Yellow
                }
            } else {
                Write-Host "Skipping invalid registry key: $pathToDelete3" -ForegroundColor Yellow
            }

            # Attempt to delete paths without braces
            if (IsValidRegistryPath -path $pathToDelete3NoBraces -guid $guid3WithoutBraces) {
                if (Test-Path -Path $pathToDelete3NoBraces) {
                    Write-Host "Attempting to remove registry key: $pathToDelete3NoBraces"
                    try {
                        Remove-Item -Path $pathToDelete3NoBraces -Recurse -Force -ErrorAction SilentlyContinue
                        if (-not (Test-Path -Path $pathToDelete3NoBraces)) {
                            Write-Host "Removed registry key: $pathToDelete3NoBraces" -ForegroundColor Green
                        } else {
                            Write-Host "Failed to remove registry key: $pathToDelete3NoBraces" -ForegroundColor Red
                        }
                    }
                    catch {
                        Write-Host "Failed to remove registry key: $pathToDelete3NoBraces" -ForegroundColor Red
                    }
                } else {
                    Write-Host "Registry key does not exist: $pathToDelete3NoBraces - skipping (not neede to exist)!" -ForegroundColor Yellow
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
                if (Test-Path -Path $pathToDelete4) {
                    Write-Host "Attempting to remove registry key: $pathToDelete4"
                    try {
                        Remove-Item -Path $pathToDelete4 -Recurse -Force -ErrorAction SilentlyContinue
                        if (-not (Test-Path -Path $pathToDelete4)) {
                            Write-Host "Removed registry key: $pathToDelete4" -ForegroundColor Green
                        } else {
                            Write-Host "Failed to remove registry key: $pathToDelete4" -ForegroundColor
                        }
                    }
                    catch {
                        Write-Host "Failed to remove registry key: $pathToDelete4" -ForegroundColor Red
                    }
                } else {
                    Write-Host "Registry key does not exist: $pathToDelete4 - skipping (not neede to exist)!" -ForegroundColor Yellow
                }
            } else {
                Write-Host "Skipping invalid registry key: $pathToDelete4" -ForegroundColor Yellow
            }

            # Attempt to delete paths without braces
            if (IsValidRegistryPath -path $pathToDelete4NoBraces -guid $guid4WithoutBraces) {
                if (Test-Path -Path $pathToDelete4NoBraces) {
                    Write-Host "Attempting to remove registry key: $pathToDelete4NoBraces"
                    try {
                        Remove-Item -Path $pathToDelete4NoBraces -Recurse -Force -ErrorAction SilentlyContinue
                        if (-not (Test-Path -Path $pathToDelete4NoBraces)) {
                            Write-Host "Removed registry key: $pathToDelete4NoBraces" -ForegroundColor Green
                        } else {
                            Write-Host "Failed to remove registry key: $pathToDelete4NoBraces" -ForegroundColor Red
                        }
                    }
                    catch {
                        Write-Host "Failed to remove registry key: $pathToDelete4NoBraces" -ForegroundColor Red
                    }
                } else {
                    Write-Host "Registry key does not exist: $pathToDelete4NoBraces - skipping (not neede to exist)!" -ForegroundColor Yellow
                }
            } else {
                Write-Host "Skipping invalid registry key: $pathToDelete4NoBraces" -ForegroundColor Yellow
            }
        }
    }

    # Display done message as a banner
    $bannerMessage = "Manual removal tasks completed successfully. Please verify that all components have been removed correctly!"
    $bannerLength = $bannerMessage.Length + 4
    $bannerBorder = "*" * $bannerLength

    Write-Host ""
    Write-Host $bannerBorder -ForegroundColor Green
    Write-Host "* $bannerMessage *" -ForegroundColor Green
    Write-Host $bannerBorder -ForegroundColor Green
    Write-Host ""
}

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

# Ask to confirm the removal of the registry keys, files, services, and the sensor installation
$confirm = Read-Host "Do you accept the risk and want to remove the sensor installation? (Y/N)"
if ($confirm -eq "Y") {
    #Ask for confirmation before proceeding again
    Write-Host ""
    Write-Host "!! This action is irreversible and may cause issues with the sensor installation !!" -ForegroundColor Red
    Write-Host ""
    $confirm2 = Read-Host "Are you still sure you want to remove the sensor installation??! (Y/N)"
    if ($confirm2 -eq "Y") {
        Clear-MDISensorInstallation
    } else {
        Write-Host "Sensor installation not removed - not confirmed second time"
    }
} else {
    Write-Host "Sensor installation not removed - not confirmed"
}