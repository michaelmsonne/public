<#	
	.NOTES
	===========================================================================
	 Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2022 v5.8.213
	 Created on:   	26-01-2025 21:37
	 Created by:   	Michael Morten Sonne
	 Organization: 	Sonne´s Cloud
	 Blog:          https://blog.sonnes.cloud
	 Filename:     	BackupEntraIDConnectConfigFiles.ps1
	===========================================================================
	.SYNOPSIS
		PowerShell script to copy the Entra ID Conect config files to a backup location. The script can get and set the configuration settings for Microsoft Entra ID Connect.

    .DESCRIPTION
        This script copies the Applied-SynchronizationPolicy and Exported-SynchronizationPolicy files from the source directory to the destination directories.
        The source directory is defined as "C:\ProgramData\AADConnect" and the destination directories are defined as "C:\Destination\Applied-SynchronizationPolicy" and "C:\Destination\Exported-SynchronizationPolicy".
        The script first verifies if the destination directories exist and creates them if they do not. It then copies the files from the source directory to the destination directories.
        
        The script uses the following parameters:
        - SOURCEFOLDER: The source directory where the files are located.
        - BackupFolder: The destination directory where the files will be copied.
        - OverWriteFiles: A boolean value that determines whether to overwrite existing files in the destination directory.
        - EntraIDConnectConfigFolder: The default source directory where the files are located. This parameter is optional and has a default value of "C:\ProgramData\AADConnect".

    .INPUTS
        The script takes the following input parameters:
        - BackupFolder: The destination directory where the files will be copied.
        - OverWriteFiles: A boolean value that determines whether to overwrite existing files in the destination directory.
        - EntraIDConnectConfigFolder: The default source directory where the files are located. This parameter is optional and has a default value of "C:\ProgramData\AADConnect".

    .OUTPUTS
        The script outputs the following:
        - Destination directories verified/created successfully.
        - Applied-SynchronizationPolicy files copied successfully to backup folder
        - Exported-SynchronizationPolicy files copied successfully to backup folder

    .REQUREMENT
        - Administrator rights on the machine

    .CHANGELOG
        27-01-2025 - Michael Morten Sonne - Initial release

	.EXAMPLE
        .\EntraIDConnectConfigExporter.ps1 -BackupFolder "C:\Destination" -EntraIDConnectConfigFolder "C:\ProgramData\AADConnect" -OverWriteFiles $true

#>

#----------------------------------------------------------[Initializations]-------------------------------------------------------
[CmdletBinding(DefaultParametersetName = "default")]
Param(
    [Parameter()][string]$EntraIDConnectConfigFolder = "C:\ProgramData\AADConnect", # Define default source directory of Entra ID Connect config files
    [Parameter(Mandatory)][string]$BackupFolder, # Define destination directory where the files will be copied
    [Parameter()][bool]$OverWriteFiles = $true # Define whether to overwrite existing files in the destination directory if they exist
)

#----------------------------------------------------------[Declarations]---------------------------------------------------------

# Get current date in dd-MM-yyyy-HH-mm format
$currentDate = Get-Date -Format "dd-MM-yyyy-HH-mm"

# Get the current hostname
$hostname = $env:COMPUTERNAME

# Replace any characters in the hostname that are not valid in a directory name
$folderName = $hostname -replace '[\\/:*?"<>|]', '_'

# Define destination directories with current date and hostname in the folder name
$destDirApplied = Join-Path -Path $BackupFolder -ChildPath ($currentDate + "\From_" + $folderName + "\Applied-SynchronizationPolicy")
$destDirExported = Join-Path -Path $BackupFolder -ChildPath ($currentDate + "\From_" + $folderName + "\Exported-SynchronizationPolicy")
$destDirSyncConfigBase = Join-Path -Path $BackupFolder -ChildPath ($currentDate + "\From_" + $folderName + "\SyncConfig")

# Initialize counters
$appliedFilesCopied = 0
$exportedFilesCopied = 0

#----------------------------------------------------------[Functions]-----------------------------------------------------------

# Function to create destination directories
function CreateBackupFolders {
    param (
        [string]$destDirApplied,
        [string]$destDirExported,
        [string]$destDirSyncConfigBase
    )
    try {
        if (-Not (Test-Path -Path $destDirApplied)) {
            New-Item -ItemType Directory -Path $destDirApplied -Force -ErrorAction Stop > $null
            Write-Output "Created destination directory for Applied configs: '$destDirApplied'"
        }
        if (-Not (Test-Path -Path $destDirExported)) {
            New-Item -ItemType Directory -Path $destDirExported -Force -ErrorAction Stop > $null
            Write-Output "Created destination directory for Exported configs: '$destDirExported'"
        }
        if (-Not (Test-Path -Path $destDirSyncConfigBase)) {
            New-Item -ItemType Directory -Path $destDirSyncConfigBase -Force -ErrorAction Stop > $null
            Write-Output "Created destination directory for SyncConfig folders: '$destDirSyncConfigBase'"
        }
        Write-Output "Backup destination directories verified/created successfully."
    }
    catch {
        Write-Error "Failed to create destination directories: $_"
        exit 1
    }
}

# Function to copy SyncConfig folders
function Copy-SyncConfig {
    param (
        [string]$sourceDir,
        [string]$destinationDir
    )
    try {
        Get-ChildItem -Path $sourceDir -Directory -Filter "SyncConfig-*" -ErrorAction Stop | ForEach-Object {
            $destDir = Join-Path -Path $destinationDir -ChildPath $_.Name
            Copy-Item -Path $_.FullName -Destination $destDir -Recurse -Force:$OverWriteFiles -ErrorAction Stop
            Write-Output "Copied SyncConfig folder: $_.FullName to $destDir"
        }
    }
    catch {
        Write-Error "Failed to copy SyncConfig folders: $_"
        exit 1
    }
}

# Function to copy Applied-SynchronizationPolicy files
function Copy-AppliedSynchronizationPolicyFiles {
    param (
        [string]$sourceDir,
        [string]$destinationDir,
        [ref]$filesCopiedCount
    )
    try {
        Get-ChildItem -Path $sourceDir -Filter "Applied-SynchronizationPolicy-*.json" -ErrorAction Stop | ForEach-Object {
            # Read the JSON file
            $jsonContent = Get-Content -Path $_.FullName | ConvertFrom-Json

            # Extract the hostname
            $hostname = $jsonContent.deploymentMetadata.hostName

            # Replace any characters in the hostname that are not valid in a directory name
            $folderName = $hostname -replace '[\\/:*?"<>|]', '_'

            # Create the new directory
            $newDestinationDir = Join-Path -Path $destinationDir -ChildPath $folderName
            New-Item -ItemType Directory -Path $newDestinationDir -Force -ErrorAction Stop > $null

            # Copy the file
            Copy-Item -Path $_.FullName -Destination $newDestinationDir -Force:$OverWriteFiles -ErrorAction Stop
            $filesCopiedCount.Value++
        }
        Write-Output "Applied-SynchronizationPolicy files copied successfully to backup folder: '$newDestinationDir'."
        Write-Output "Applied-SynchronizationPolicy files copied: '$($filesCopiedCount.Value)'"
    }
    catch {
        Write-Error "Failed to copy Applied-SynchronizationPolicy files to: '$destinationDir' : $_"
        exit 1
    }
}

# Function to copy Exported-SynchronizationPolicy files
function Copy-ExportedSynchronizationPolicyFiles {
    param (
        [string]$sourceDir,
        [string]$destinationDir,
        [ref]$filesCopiedCount
    )
    try {
        Get-ChildItem -Path $sourceDir -Filter "Exported-SynchronizationPolicy-*.json" -ErrorAction Stop | ForEach-Object {
            # Read the JSON file
            $jsonContent = Get-Content -Path $_.FullName | ConvertFrom-Json

            # Extract the hostname
            $hostname = $jsonContent.deploymentMetadata.hostName

            # Replace any characters in the hostname that are not valid in a directory name
            $folderName = $hostname -replace '[\\/:*?"<>|]', '_'

            # Create the new directory
            $newDestinationDir = Join-Path -Path $destinationDir -ChildPath $folderName
            New-Item -ItemType Directory -Path $newDestinationDir -Force -ErrorAction Stop > $null

            # Copy the file
            Copy-Item -Path $_.FullName -Destination $newDestinationDir -Force:$OverWriteFiles -ErrorAction Stop
            $filesCopiedCount.Value++
        }
        Write-Output "Exported-SynchronizationPolicy files copied successfully to backup folder: '$newDestinationDir'."
        Write-Output "Exported-SynchronizationPolicy files copied: '$($filesCopiedCount.Value)'"
    }
    catch {
        Write-Error "Failed to copy Exported-SynchronizationPolicy files to: '$destinationDir' : $_"
        exit 1
    }
}

#----------------------------------------------------------[Execution]-----------------------------------------------------------

# Create destination directories
CreateBackupFolders -destDirApplied $destDirApplied -destDirExported $destDirExported -destDirSyncConfigBase $destDirSyncConfigBase

# Copy Applied-SynchronizationPolicy files
Copy-AppliedSynchronizationPolicyFiles -sourceDir $EntraIDConnectConfigFolder -destinationDir $destDirApplied -filesCopiedCount ([ref]$appliedFilesCopied)

# Copy Exported-SynchronizationPolicy files
Copy-ExportedSynchronizationPolicyFiles -sourceDir $EntraIDConnectConfigFolder -destinationDir $destDirExported -filesCopiedCount ([ref]$exportedFilesCopied)

# Copy SyncConfig folders and their content
Copy-SyncConfig -sourceDir $EntraIDConnectConfigFolder -destinationDir $destDirSyncConfigBase

# Calculate total files copied
$totalFilesCopied = $appliedFilesCopied + $exportedFilesCopied

# Check if there were files copied
if ($totalFilesCopied -gt 0) {
    # Output total files copied and job is completed
    Write-Output "Config files copied successfully. Total number of files is: '$totalFilesCopied'"
} else {
    Write-Output "No files were copied."
}

# End of script
Write-Output "End of script."
# SIG # Begin signature block
# MIIuawYJKoZIhvcNAQcCoIIuXDCCLlgCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC4L2ucO895WAof
# JZbcO+MfOJJJ+CH0Ex5TEankW1EeFaCCEd8wggVvMIIEV6ADAgECAhBI/JO0YFWU
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
# KwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQg6CUDLnUKjYpU2MCrklnrgiN4qVva
# hv7znCjY43ZgbjowDQYJKoZIhvcNAQEBBQAEggIALN0iZCSmHWSUOix3r24G2cIW
# OXjq00nCrkHc/kx20OnRdpbq2nbChn3IM1mv6sJT/SLoJmwV4v9l9DCN20QVLzHU
# HBjWt9HkYA4k5onBf0HHGSRGM3s+Jc/i6RZmikASyh49amnBH9ggkH0Yka4qxlpg
# 8E7POZoZv6Sua8Vk1lUjXg/8gmOy3tFwRyJdMkgXugW+6UNKpOFY7SHhU1qhYuhn
# iEfz7U121skb/KNTRJqW5ARpJuVmw/Gi79mziOfXIIR6oneFLVzR3IkGfnXT/C1T
# rLHstPuLoBBfHN5DkqtQjm8nvlRlQ9Oc+ThIr3dC1gzHKfKSSLYhzCAetAjpqeME
# N/jvwl/zeejMmFWttpIFudY9Z7qwQkdprDncv2UumacjwAUib2CYlztdnXHV8Z2+
# k25LpqJ/xFrlZe8omB72NtplFXnbGfE8beQ3Tui5F+7ny4EVTZcFt/ExOydijGB3
# 6XcnqXOgLD41q2168ZszZG4myyJsvndPHTr9xh2D9XcvQCMKTaqdQcOisnV+E9qv
# 90+9ulV3K4VNI/1CC5d5fGduiCFI0qmfliZVgLglyyc3y1u2Lskd4yCJ4D+Kg2B2
# KuyaQ/6QQSU9tWrCShQ0nO+NXkewvHlpP3zJBAwzT06Fs+6/cdfvxYqI6T4q0pe9
# YI0gYQiZ0TC6SWhdQvKhghjNMIIYyQYKKwYBBAGCNwMDATGCGLkwghi1BgkqhkiG
# 9w0BBwKgghimMIIYogIBAzEPMA0GCWCGSAFlAwQCAgUAMIHzBgsqhkiG9w0BCRAB
# BKCB4wSB4DCB3QIBAQYKKwYBBAGyMQIBATAxMA0GCWCGSAFlAwQCAQUABCAOh4S1
# ddJi6e2t7BFwPb3FupN3tBwIy7pGqVo4CEaAKQIUdmqNPf67eRsjOmxYrJKYGV78
# 2JAYDzIwMjUwMTI4MTUxNTA4WqBypHAwbjELMAkGA1UEBhMCR0IxEzARBgNVBAgT
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
# MjUwMTI4MTUxNTA4WjA/BgkqhkiG9w0BCQQxMgQwqd2r0QBmG9JdSqXunlLZiFCZ
# hXIjzdWmAyYLpYoNlo46Bb9IpQaaBR/Lvguz+YfUMIIBegYLKoZIhvcNAQkQAgwx
# ggFpMIIBZTCCAWEwFgQU+GCYGab7iCz36FKX8qEZUhoWd18wgYcEFMauVOR4hvF8
# PVUSSIxpw0p6+cLdMG8wW6RZMFcxCzAJBgNVBAYTAkdCMRgwFgYDVQQKEw9TZWN0
# aWdvIExpbWl0ZWQxLjAsBgNVBAMTJVNlY3RpZ28gUHVibGljIFRpbWUgU3RhbXBp
# bmcgUm9vdCBSNDYCEHojrtpTaZYPkcg+XPTH4z8wgbwEFIU9Yy2TgoJhfNCQNcSR
# 3pLBQtrHMIGjMIGOpIGLMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMKTmV3IEpl
# cnNleTEUMBIGA1UEBxMLSmVyc2V5IENpdHkxHjAcBgNVBAoTFVRoZSBVU0VSVFJV
# U1QgTmV0d29yazEuMCwGA1UEAxMlVVNFUlRydXN0IFJTQSBDZXJ0aWZpY2F0aW9u
# IEF1dGhvcml0eQIQNsKwvXwbOuejs902y8l1aDANBgkqhkiG9w0BAQEFAASCAgAJ
# 6aBrQPqRrByKAWruMQ+COB+Z/lgA9oC1YLxUUFT4d06M+limWQmWrQVXmAKYdd20
# VxY1DG1XJxk2fFKOAcjjg5Zav6NufWF39bPBZWAVX9Bv8ofgEaG6OJ+9U+9gNAeF
# WIoEBAaqB7FxDAqPIiU1AVM8+kSkoN1PRFF9p6rjHmUQulS1tPx9+8hJmjpJGe22
# l49/6aYFjvWSzzI/JFtnepWeSNEXpd2Gh/GBnb/CXbsKzAUSb8TZpah/PHE5ZtD7
# sduYzIRI4spYiOxpd1BsFvdCAiq7AzvfboqOr5+45m8tbT4ipFv2s3WMp/o+T00i
# +oeR0RmNyUOcJlGnzxy2pWyurq/A9v/Cr1QcVY10gVhKrQulgJ8vHgBx3yySepZv
# WRK8rmkXts6Xd/J9X5f9RKRsWd6XmJWJX9FwWfiUz3RfZoTJ7aNVFelq0NHhM2bJ
# hsFpZwgaFZz0WkEWA+sCQ1fDqlooCuEDtQmfzQ5uDJJ4VOhSk6AxCRSomu9iTLfv
# h38zqCI2BV44eVhQi5Ta2AdJg1cY4I7xN2JdckZnpyfo6UQWqxAegev0izmbGuAB
# 6WRksFrbCc70Zd79Eeo4ASCA4tzBrXPpco2ByWsd2FD9LWH6Bv4Z4QPw+3vs30XL
# cBnZZ1W+JTLrbUfHonsoaCjj1ZuGY1lB+FZZ/sga7Q==
# SIG # End signature block
