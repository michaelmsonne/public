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
        27-02-2024 - Michael Morten Sonne - Initial release

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
# MIIubAYJKoZIhvcNAQcCoIIuXTCCLlkCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCSqO63eoiQhx1Z
# DMpxm2KgZJLRTsyAtlluFf/gPcyTx6CCEd8wggVvMIIEV6ADAgECAhBI/JO0YFWU
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
# KwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQg67uI8jUze/Sspg42sctLhklFlJct
# 9scgXnXmuzXjHeYwDQYJKoZIhvcNAQEBBQAEggIAbLxZkwXYFw8Iw4KavtiQ48RV
# zitTUUMWsoSFgcDNeGTK5nUMFH+iOxpZXDg7eu/hu+jAAgydsoAJ3gBit24HaufJ
# NO9GUr2XqDA4FH4RO0wkVI8Ab5lSOqdR2+bwpIdiisOMT134ok9+5MMx4UIotRIg
# e/HqtzXXs3/cukXBDWmfu9M84F9GEgrTJ39GIknwVp57M20E6UiZ3yEJYmJdWqa8
# wYx5ul1lqmTi9q7jr/AgiA2Rpw8Xu+0fDvz5fKSsyJ4DQ8dcMfsWlsrU9phOygLr
# kxqZ65hy2k5b1OLiNic0NwwJr5ohJQeh9rp5QLSzNRTF76T2ZPKANCFlqADVgyh7
# 8mHXQpDtu6tHGHTV4t/w9PzPVjL/6YYcQ6PHJAHSWJMzBqwnyZvFV4d05Jn/rwDQ
# NpEiy7R3vEpoi/0439R3JiqEzx8bCyXEa1cjJt8WmGMQ0MqL2GmPsQK9EnNrmdYa
# UQbMLnp0kgwG3MAU2e/dnLQBD/XL5ZtlofYXTKiO1YDGsyJl/tu28IiErEzD8zcr
# dB90XudIiCWMpxE7Y1sZANFc/k8/ou84BJFiTRBCqdMoq16Y4oxt72N2PQcu83VE
# DLNS4d1avlP2RYNyx9BF08ZMdZkUpn1hNFfuBrKeQ3hy4HggLFfMBiLvo4Xuscf2
# HBkfSTnrLfo9wNvHUUmhghjOMIIYygYKKwYBBAGCNwMDATGCGLowghi2BgkqhkiG
# 9w0BBwKgghinMIIYowIBAzEPMA0GCWCGSAFlAwQCAgUAMIH0BgsqhkiG9w0BCRAB
# BKCB5ASB4TCB3gIBAQYKKwYBBAGyMQIBATAxMA0GCWCGSAFlAwQCAQUABCAWX6uL
# /agytihYGpD48aMF95zkQZR7t25XWIsoX7T78wIVALlERgluqNcZblTZcuPB0HZe
# JTNuGA8yMDI1MDEyODE1MDgwMFqgcqRwMG4xCzAJBgNVBAYTAkdCMRMwEQYDVQQI
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
# DTI1MDEyODE1MDgwMFowPwYJKoZIhvcNAQkEMTIEMACnC9MT4FVJd0w57jfOFVhI
# Vk/gUCouTYgqHTloc7MVvoFFMVdxLbWVTYDaccMdeDCCAXoGCyqGSIb3DQEJEAIM
# MYIBaTCCAWUwggFhMBYEFPhgmBmm+4gs9+hSl/KhGVIaFndfMIGHBBTGrlTkeIbx
# fD1VEkiMacNKevnC3TBvMFukWTBXMQswCQYDVQQGEwJHQjEYMBYGA1UEChMPU2Vj
# dGlnbyBMaW1pdGVkMS4wLAYDVQQDEyVTZWN0aWdvIFB1YmxpYyBUaW1lIFN0YW1w
# aW5nIFJvb3QgUjQ2AhB6I67aU2mWD5HIPlz0x+M/MIG8BBSFPWMtk4KCYXzQkDXE
# kd6SwULaxzCBozCBjqSBizCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCk5ldyBK
# ZXJzZXkxFDASBgNVBAcTC0plcnNleSBDaXR5MR4wHAYDVQQKExVUaGUgVVNFUlRS
# VVNUIE5ldHdvcmsxLjAsBgNVBAMTJVVTRVJUcnVzdCBSU0EgQ2VydGlmaWNhdGlv
# biBBdXRob3JpdHkCEDbCsL18Gzrno7PdNsvJdWgwDQYJKoZIhvcNAQEBBQAEggIA
# jRFqHsNaHTAuMOVdAfyl10nEkXIWvsVy8/naFJojCsZtgJyriwI5MDY8H5DzEeOz
# 05M6SPKX0fCGfbUqq7GAieG90deTWt+iNJKh64k0tWbKK0/hFPbKIIV1sDsm26OA
# xR5zD6YkjTPez7rhmzURDZxBDFVZcicU42Ds3lytw0TZ7JwOz1RcSN0ik/QT2cml
# QQ1qPmamsspidrlp0FVXsFcN38sMYy8KLQnR3gzxTr4pFSVXxr+vQyex1T6pLUuJ
# Pzjm4E0PuR4C9rjD/qa+TEzKb2Uzfyl065ygsJFWuyLsyg3hPYpRoBuR/bPPmvwc
# dZgtJfbbGaOHXsqvgscOElm3iqHtM91vHqtHWNPGcoymZGot3ebHvL9j/wphxMHX
# Ducr5bUSvhua61psi7ogV+K9AaOyFPUVq7kXSZdhUp7NC84L20TC4T1A+f3I6XFG
# hlBKoKUJuunlW7J/aq7I+cWgdLfreATWWbqFDg+kFiP8EbMJ2NA5iEMZgyCiZjbp
# j9xCPSXXscFjKaj1PPm5nfoHQU9KwgEGx2qjVes2eeZ8qzaeZnrE0OOwXVBlvmTf
# kanv1JImhoStqoowrIu6VpNEw5pLRtxPNu9px45Rb0md417W0DyLgLqKCDfPOvFU
# 6nXu4nlLcnS6HdKPlDeZ/uPDzP0pgZeNl8Dgi9w0qug=
# SIG # End signature block
