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
# SIG # Begin signature block
# MIIuawYJKoZIhvcNAQcCoIIuXDCCLlgCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCKSmQwFqB0syJY
# 66vWlghBtqR5iYqfDIpgRjQi5vPZcaCCEd8wggVvMIIEV6ADAgECAhBI/JO0YFWU
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
# gf9SsIAod1Dx9THs2qkXIwyf5lTJBvPHLRqxs/k+Mn70AUiyj50/JYMxghviMIIb
# 3gIBATBoMFQxCzAJBgNVBAYTAkdCMRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQx
# KzApBgNVBAMTIlNlY3RpZ28gUHVibGljIENvZGUgU2lnbmluZyBDQSBSMzYCEBHh
# oIZkh66CYIKNKPBResYwDQYJYIZIAWUDBAIBBQCgfDAQBgorBgEEAYI3AgEMMQIw
# ADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYK
# KwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgDVc0MT2HcohKCIzziadaLz+9Qrrr
# Lf+J+ngh1/KqQF0wDQYJKoZIhvcNAQEBBQAEggIAj8is5HT0+4Nz810xj0xOf9ug
# h2VxdWqX1LYME6dG98BooofaQdtmBtzFdf/nPO+4HPojDGrUo/2BxLnHUDSk7Vib
# EQ9sNTsUn2SrR29goohi9n1EdfcOuZNwqq0ZVCm5d84EchCe+skwIAJeaY7mOf1k
# s0FMLNzxWNBO8W1tdu4hbsQ/ArN3fIMiq9hppHdDGJqO0tc6QaJaxdHgyxg5ZCas
# GI8qhHoskVw0W1IvHTBVki14Z/m4eRZZ85pZvGlwgFCE8umG4Jx+Rr3ys5iGyTOK
# rqY2GGAgyO3WaKBUVesREwUnylQjXLP23h4FcffvZ/i2/D7gEZNf5uIg7kbRizRr
# ZrRHXCz7ZfSDhfvGgGQeBxs+rWmRAng5bxHx9Dq5EIT1oyo32eyLvgZ9juQ1Y92e
# rlku2sYhXEuag1wrwVFy34PJDbUAxcOh80+tEYmOm8g+1dB2tXBIop90XW9uwYTG
# XVauyJ9eDTaegIqC4ud3FY3t9Feb/pq0nUJRVzjMppGdsWdrhSgBb0h1lrVijwtL
# Rw3gFPzUUvL+qcYPnSitO/z6If7pBHL6KYbbnaYyE0fxkM02GoFNmVneIKQXmp30
# t2/O/jian30HOPYl8LRt37pVvkTGv/cBEFc3MXk3LJBVYX0VaWDLKcctFN2MaKTU
# 7RYcGMTGESSMk6jhLIyhghjNMIIYyQYKKwYBBAGCNwMDATGCGLkwghi1BgkqhkiG
# 9w0BBwKgghimMIIYogIBAzEPMA0GCWCGSAFlAwQCAgUAMIHzBgsqhkiG9w0BCRAB
# BKCB4wSB4DCB3QIBAQYKKwYBBAGyMQIBATAxMA0GCWCGSAFlAwQCAQUABCCdu0+r
# QMajnSHFu+nRbWdUHm5vSD9L2ulcUe0Pj2OppAIUGApV/Z/oQeTYtouWFUbBHu9z
# gYUYDzIwMjQwODE0MTgxOTQ2WqBypHAwbjELMAkGA1UEBhMCR0IxEzARBgNVBAgT
# Ck1hbmNoZXN0ZXIxGDAWBgNVBAoTD1NlY3RpZ28gTGltaXRlZDEwMC4GA1UEAxMn
# U2VjdGlnbyBQdWJsaWMgVGltZSBTdGFtcGluZyBTaWduZXIgUjM1oIIS/zCCBl0w
# ggTFoAMCAQICEDpSaiyEzlXmHWX8zBLY6YkwDQYJKoZIhvcNAQEMBQAwVTELMAkG
# A1UEBhMCR0IxGDAWBgNVBAoTD1NlY3RpZ28gTGltaXRlZDEsMCoGA1UEAxMjU2Vj
# dGlnbyBQdWJsaWMgVGltZSBTdGFtcGluZyBDQSBSMzYwHhcNMjQwMTE1MDAwMDAw
# WhcNMzUwNDE0MjM1OTU5WjBuMQswCQYDVQQGEwJHQjETMBEGA1UECBMKTWFuY2hl
# c3RlcjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMTAwLgYDVQQDEydTZWN0aWdv
# IFB1YmxpYyBUaW1lIFN0YW1waW5nIFNpZ25lciBSMzUwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQCN0Wf0wUibvf04STpNYYGbw9jcRaVhBDaNBp7jmJaA
# 9dQZW5ighrXGNMYjK7Dey5RIHMqLIbT9z9if753mYbojJrKWO4ZP0N5dBT2TwZZa
# Pb8E+hqaDZ8Vy2c+x1NiEwbEzTrPX4W3QFq/zJvDDbWKL99qLL42GJQzX3n5wWo6
# 0KklfFn+Wb22mOZWYSqkCVGl8aYuE12SqIS4MVO4PUaxXeO+4+48YpQlNqbc/ndT
# gszRQLF4MjxDPjRDD1M9qvpLTZcTGVzxfViyIToRNxPP6DUiZDU6oXARrGwyP9ag
# lPXwYbkqI2dLuf9fiIzBugCDciOly8TPDgBkJmjAfILNiGcVEzg+40xUdhxNcaC+
# 6r0juPiR7bzXHh7v/3RnlZuT3ZGstxLfmE7fRMAFwbHdDz5gtHLqjSTXDiNF58Ix
# PtvmZPG2rlc+Yq+2B8+5pY+QZn+1vEifI0MDtiA6BxxQuOnj4PnqDaK7NEKwtD1p
# zoA3jJFuoJiwbatwhDkg1PIjYnMDbDW+wAc9FtRN6pUsO405jaBgigoFZCw9hWjL
# NqgFVTo7lMb5rVjJ9aSBVVL2dcqzyFW2LdWk5Xdp65oeeOALod7YIIMv1pbqC15R
# 7QCYLxcK1bCl4/HpBbdE5mjy9JR70BHuYx27n4XNOZbwrXcG3wZf9gEUk7stbPAo
# BQIDAQABo4IBjjCCAYowHwYDVR0jBBgwFoAUX1jtTDF6omFCjVKAurNhlxmiMpsw
# HQYDVR0OBBYEFGjvpDJJabZSOB3qQzks9BRqngyFMA4GA1UdDwEB/wQEAwIGwDAM
# BgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMEoGA1UdIARDMEEw
# NQYMKwYBBAGyMQECAQMIMCUwIwYIKwYBBQUHAgEWF2h0dHBzOi8vc2VjdGlnby5j
# b20vQ1BTMAgGBmeBDAEEAjBKBgNVHR8EQzBBMD+gPaA7hjlodHRwOi8vY3JsLnNl
# Y3RpZ28uY29tL1NlY3RpZ29QdWJsaWNUaW1lU3RhbXBpbmdDQVIzNi5jcmwwegYI
# KwYBBQUHAQEEbjBsMEUGCCsGAQUFBzAChjlodHRwOi8vY3J0LnNlY3RpZ28uY29t
# L1NlY3RpZ29QdWJsaWNUaW1lU3RhbXBpbmdDQVIzNi5jcnQwIwYIKwYBBQUHMAGG
# F2h0dHA6Ly9vY3NwLnNlY3RpZ28uY29tMA0GCSqGSIb3DQEBDAUAA4IBgQCw3C7J
# +k82TIov9slP1e8YTx+fDsa//hJ62Y6SMr2E89rv82y/n8we5W6z5pfBEWozlW7n
# Wp+sdPCdUTFw/YQcqvshH6b9Rvs9qZp5Z+V7nHwPTH8yzKwgKzTTG1I1XEXLAK9f
# HnmXpaDeVeI8K6Lw3iznWZdLQe3zl+Rejdq5l2jU7iUfMkthfhFmi+VVYPkR/BXp
# V7Ub1QyyWebqkjSHJHRmv3lBYbQyk08/S7TlIeOr9iQ+UN57fJg4QI0yqdn6Pyie
# hS1nSgLwKRs46T8A6hXiSn/pCXaASnds0LsM5OVoKYfbgOOlWCvKfwUySWoSgrhn
# cihSBXxH2pAuDV2vr8GOCEaePZc0Dy6O1rYnKjGmqm/IRNkJghSMizr1iIOPN+23
# futBXAhmx8Ji/4NTmyH9K0UvXHiuA2Pa3wZxxR9r9XeIUVb2V8glZay+2ULlc445
# CzCvVSZV01ZB6bgvCuUuBx079gCcepjnZDCcEuIC5Se4F6yFaZ8RvmiJ4hgwggYU
# MIID/KADAgECAhB6I67aU2mWD5HIPlz0x+M/MA0GCSqGSIb3DQEBDAUAMFcxCzAJ
# BgNVBAYTAkdCMRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQxLjAsBgNVBAMTJVNl
# Y3RpZ28gUHVibGljIFRpbWUgU3RhbXBpbmcgUm9vdCBSNDYwHhcNMjEwMzIyMDAw
# MDAwWhcNMzYwMzIxMjM1OTU5WjBVMQswCQYDVQQGEwJHQjEYMBYGA1UEChMPU2Vj
# dGlnbyBMaW1pdGVkMSwwKgYDVQQDEyNTZWN0aWdvIFB1YmxpYyBUaW1lIFN0YW1w
# aW5nIENBIFIzNjCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBAM2Y2ENB
# q26CK+z2M34mNOSJjNPvIhKAVD7vJq+MDoGD46IiM+b83+3ecLvBhStSVjeYXIjf
# a3ajoW3cS3ElcJzkyZlBnwDEJuHlzpbN4kMH2qRBVrjrGJgSlzzUqcGQBaCxpect
# RGhhnOSwcjPMI3G0hedv2eNmGiUbD12OeORN0ADzdpsQ4dDi6M4YhoGE9cbY11Xx
# M2AVZn0GiOUC9+XE0wI7CQKfOUfigLDn7i/WeyxZ43XLj5GVo7LDBExSLnh+va8W
# xTlA+uBvq1KO8RSHUQLgzb1gbL9Ihgzxmkdp2ZWNuLc+XyEmJNbD2OIIq/fWlwBp
# 6KNL19zpHsODLIsgZ+WZ1AzCs1HEK6VWrxmnKyJJg2Lv23DlEdZlQSGdF+z+Gyn9
# /CRezKe7WNyxRf4e4bwUtrYE2F5Q+05yDD68clwnweckKtxRaF0VzN/w76kOLIaF
# Vhf5sMM/caEZLtOYqYadtn034ykSFaZuIBU9uCSrKRKTPJhWvXk4CllgrwIDAQAB
# o4IBXDCCAVgwHwYDVR0jBBgwFoAU9ndq3T/9ARP/FqFsggIv0Ao9FCUwHQYDVR0O
# BBYEFF9Y7UwxeqJhQo1SgLqzYZcZojKbMA4GA1UdDwEB/wQEAwIBhjASBgNVHRMB
# Af8ECDAGAQH/AgEAMBMGA1UdJQQMMAoGCCsGAQUFBwMIMBEGA1UdIAQKMAgwBgYE
# VR0gADBMBgNVHR8ERTBDMEGgP6A9hjtodHRwOi8vY3JsLnNlY3RpZ28uY29tL1Nl
# Y3RpZ29QdWJsaWNUaW1lU3RhbXBpbmdSb290UjQ2LmNybDB8BggrBgEFBQcBAQRw
# MG4wRwYIKwYBBQUHMAKGO2h0dHA6Ly9jcnQuc2VjdGlnby5jb20vU2VjdGlnb1B1
# YmxpY1RpbWVTdGFtcGluZ1Jvb3RSNDYucDdjMCMGCCsGAQUFBzABhhdodHRwOi8v
# b2NzcC5zZWN0aWdvLmNvbTANBgkqhkiG9w0BAQwFAAOCAgEAEtd7IK0ONVgMnoEd
# JVj9TC1ndK/HYiYh9lVUacahRoZ2W2hfiEOyQExnHk1jkvpIJzAMxmEc6ZvIyHI5
# UkPCbXKspioYMdbOnBWQUn733qMooBfIghpR/klUqNxx6/fDXqY0hSU1OSkkSivt
# 51UlmJElUICZYBodzD3M/SFjeCP59anwxs6hwj1mfvzG+b1coYGnqsSz2wSKr+nD
# O+Db8qNcTbJZRAiSazr7KyUJGo1c+MScGfG5QHV+bps8BX5Oyv9Ct36Y4Il6ajTq
# V2ifikkVtB3RNBUgwu/mSiSUice/Jp/q8BMk/gN8+0rNIE+QqU63JoVMCMPY2752
# LmESsRVVoypJVt8/N3qQ1c6FibbcRabo3azZkcIdWGVSAdoLgAIxEKBeNh9AQO1g
# Qrnh1TA8ldXuJzPSuALOz1Ujb0PCyNVkWk7hkhVHfcvBfI8NtgWQupiaAeNHe0pW
# SGH2opXZYKYG4Lbukg7HpNi/KqJhue2Keak6qH9A8CeEOB7Eob0Zf+fU+CCQaL0c
# Jqlmnx9HCDxF+3BLbUufrV64EbTI40zqegPZdA+sXCmbcZy6okx/SjwsusWRItFA
# 3DE8MORZeFb6BmzBtqKJ7l939bbKBy2jvxcJI98Va95Q5JnlKor3m0E7xpMeYRri
# WklUPsetMSf2NvUQa/E5vVyefQIwggaCMIIEaqADAgECAhA2wrC9fBs656Oz3TbL
# yXVoMA0GCSqGSIb3DQEBDAUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMKTmV3
# IEplcnNleTEUMBIGA1UEBxMLSmVyc2V5IENpdHkxHjAcBgNVBAoTFVRoZSBVU0VS
# VFJVU1QgTmV0d29yazEuMCwGA1UEAxMlVVNFUlRydXN0IFJTQSBDZXJ0aWZpY2F0
# aW9uIEF1dGhvcml0eTAeFw0yMTAzMjIwMDAwMDBaFw0zODAxMTgyMzU5NTlaMFcx
# CzAJBgNVBAYTAkdCMRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQxLjAsBgNVBAMT
# JVNlY3RpZ28gUHVibGljIFRpbWUgU3RhbXBpbmcgUm9vdCBSNDYwggIiMA0GCSqG
# SIb3DQEBAQUAA4ICDwAwggIKAoICAQCIndi5RWedHd3ouSaBmlRUwHxJBZvMWhUP
# 2ZQQRLRBQIF3FJmp1OR2LMgIU14g0JIlL6VXWKmdbmKGRDILRxEtZdQnOh2qmcxG
# zjqemIk8et8sE6J+N+Gl1cnZocew8eCAawKLu4TRrCoqCAT8uRjDeypoGJrruH/d
# rCio28aqIVEn45NZiZQI7YYBex48eL78lQ0BrHeSmqy1uXe9xN04aG0pKG9ki+PC
# 6VEfzutu6Q3IcZZfm00r9YAEp/4aeiLhyaKxLuhKKaAdQjRaf/h6U13jQEV1JnUT
# Cm511n5avv4N+jSVwd+Wb8UMOs4netapq5Q/yGyiQOgjsP/JRUj0MAT9YrcmXcLg
# srAimfWY3MzKm1HCxcquinTqbs1Q0d2VMMQyi9cAgMYC9jKc+3mW62/yVl4jnDcw
# 6ULJsBkOkrcPLUwqj7poS0T2+2JMzPP+jZ1h90/QpZnBkhdtixMiWDVgh60KmLmz
# XiqJc6lGwqoUqpq/1HVHm+Pc2B6+wCy/GwCcjw5rmzajLbmqGygEgaj/OLoanEWP
# 6Y52Hflef3XLvYnhEY4kSirMQhtberRvaI+5YsD3XVxHGBjlIli5u+NrLedIxsE8
# 8WzKXqZjj9Zi5ybJL2WjeXuOTbswB7XjkZbErg7ebeAQUQiS/uRGZ58NHs57ZPUf
# ECcgJC+v2wIDAQABo4IBFjCCARIwHwYDVR0jBBgwFoAUU3m/WqorSs9UgOHYm8Cd
# 8rIDZsswHQYDVR0OBBYEFPZ3at0//QET/xahbIICL9AKPRQlMA4GA1UdDwEB/wQE
# AwIBhjAPBgNVHRMBAf8EBTADAQH/MBMGA1UdJQQMMAoGCCsGAQUFBwMIMBEGA1Ud
# IAQKMAgwBgYEVR0gADBQBgNVHR8ESTBHMEWgQ6BBhj9odHRwOi8vY3JsLnVzZXJ0
# cnVzdC5jb20vVVNFUlRydXN0UlNBQ2VydGlmaWNhdGlvbkF1dGhvcml0eS5jcmww
# NQYIKwYBBQUHAQEEKTAnMCUGCCsGAQUFBzABhhlodHRwOi8vb2NzcC51c2VydHJ1
# c3QuY29tMA0GCSqGSIb3DQEBDAUAA4ICAQAOvmVB7WhEuOWhxdQRh+S3OyWM637a
# yBeR7djxQ8SihTnLf2sABFoB0DFR6JfWS0snf6WDG2gtCGflwVvcYXZJJlFfym1D
# oi+4PfDP8s0cqlDmdfyGOwMtGGzJ4iImyaz3IBae91g50QyrVbrUoT0mUGQHbRcF
# 57olpfHhQEStz5i6hJvVLFV/ueQ21SM99zG4W2tB1ExGL98idX8ChsTwbD/zIExA
# opoe3l6JrzJtPxj8V9rocAnLP2C8Q5wXVVZcbw4x4ztXLsGzqZIiRh5i111TW7HV
# 1AtsQa6vXy633vCAbAOIaKcLAo/IU7sClyZUk62XD0VUnHD+YvVNvIGezjM6CRpc
# Wed/ODiptK+evDKPU2K6synimYBaNH49v9Ih24+eYXNtI38byt5kIvh+8aW88WTh
# Rpv8lUJKaPn37+YHYafob9Rg7LyTrSYpyZoBmwRWSE4W6iPjB7wJjJpH29308Zkp
# KKdpkiS9WNsf/eeUtvRrtIEiSJHN899L1P4l6zKVsdrUu1FX1T/ubSrsxrYJD+3f
# 3aKg6yxdbugot06YwGXXiy5UUGZvOu3lXlxA+fC13dQ5OlL2gIb5lmF6Ii8+CQOY
# DwXM+yd9dbmocQsHjcRPsccUd5E9FiswEqORvz8g3s+jR3SFCgXhN4wz7NgAnOgp
# CdUo4uDyllU9PzGCBJEwggSNAgEBMGkwVTELMAkGA1UEBhMCR0IxGDAWBgNVBAoT
# D1NlY3RpZ28gTGltaXRlZDEsMCoGA1UEAxMjU2VjdGlnbyBQdWJsaWMgVGltZSBT
# dGFtcGluZyBDQSBSMzYCEDpSaiyEzlXmHWX8zBLY6YkwDQYJYIZIAWUDBAICBQCg
# ggH5MBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAcBgkqhkiG9w0BCQUxDxcN
# MjQwODE0MTgxOTQ2WjA/BgkqhkiG9w0BCQQxMgQwQvaOD61xZdJkbosIXqEUt/uv
# Gw0DDbu4VLM/D1GH0d5QuOPprL/Xq4/0qukV2x3NMIIBegYLKoZIhvcNAQkQAgwx
# ggFpMIIBZTCCAWEwFgQU+GCYGab7iCz36FKX8qEZUhoWd18wgYcEFMauVOR4hvF8
# PVUSSIxpw0p6+cLdMG8wW6RZMFcxCzAJBgNVBAYTAkdCMRgwFgYDVQQKEw9TZWN0
# aWdvIExpbWl0ZWQxLjAsBgNVBAMTJVNlY3RpZ28gUHVibGljIFRpbWUgU3RhbXBp
# bmcgUm9vdCBSNDYCEHojrtpTaZYPkcg+XPTH4z8wgbwEFIU9Yy2TgoJhfNCQNcSR
# 3pLBQtrHMIGjMIGOpIGLMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMKTmV3IEpl
# cnNleTEUMBIGA1UEBxMLSmVyc2V5IENpdHkxHjAcBgNVBAoTFVRoZSBVU0VSVFJV
# U1QgTmV0d29yazEuMCwGA1UEAxMlVVNFUlRydXN0IFJTQSBDZXJ0aWZpY2F0aW9u
# IEF1dGhvcml0eQIQNsKwvXwbOuejs902y8l1aDANBgkqhkiG9w0BAQEFAASCAgBJ
# PgT5bHKHQeDELgIU5C0jh89gzzcFv59tp0+zMAI30xw8zaJWk/YIX5UVoeMAuxoz
# nxPl1JqHEwLpnypuk8mzwl0CBKQG+cFe4MuCimNYvBb5lQv+k+Ge2VEGh09Ul/To
# JqxQe0rryds0NyvYr7/L4wVmEdgag3uu5Ar1YyvTrIWbmJgw9ps+LJLOciIuZ/31
# bSni3/1w2n4QUVhblfT31sGgsCiJYZiMCL1sv8z7mVN8q6BomiHdhmV+TzgtERTM
# l5ZJOgcj9n2ctLD6FSYIS2ZutXHTmOW2FIQn3vqytbzao+MdvuCwwe/TWed4YA01
# Nx/aEMCxrmzUr9OtDcsBZ2Al0qcPPCrLCG04hKFM9p9l23grD+bnN2RXjvbbmH1N
# iEcRf8wRWfMEvnAP0JcYh3UPeWwRw15H7tN5YQN3QAtDfwcTNwpcTxXgaCIr+oEF
# sZSWfL04JzF//eXtiqbUTOUmFKOwx9whYOqCOT0Kk0NabGbFRd8VW6jhm31p3Ln4
# SJVcBQESI2qjOL64LmsVfwwyZG9jDLQBxEG/ldq0Wh+RoSbUzb+slgdeBGci8xY2
# yQDuTnb5k2SnmYGh/plQJaAPuB9Z+jJPvZ6ThQxGTqkuCHFzB2yfeI54SxIIn3lk
# R0Hi8O0SW6iBWnVyia6GqKctC5movgaDIq6QDx6GTQ==
# SIG # End signature block
