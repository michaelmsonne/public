﻿<#	
	.NOTES
	===========================================================================
	 Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2022 v5.8.213
	 Created on:   	25-04-2023 17:41
	 Created by:   	Michael Morten Sonne
	 Organization: 	Sonne´s Cloud
	 Filename:     	PowerShell-UpdateModules.ps1
	===========================================================================
	.DESCRIPTION
		Update PowerShell Modules

        If you look for a quick way to update, please keep in mind Microsoft has a built-in cmdlet to update ALL the PowerShell modules installed:
        Update-Module [-Verbose]

        This script is intended as a replacement of the Update-Module:
        - to provide more human readable output than the -Verbose option of Update-Module
        - to force install with -SkipPublisherCheck (Authenticode change) because Update-Module has not this option
        - to exclude some modules from the update process
        - to remove older versions because Update-Module does not remove older versions (it only installs a new version in the $env:PSModulePath\<moduleName> and keep the old module)

        This script provides informations about the module version (current and the latest available on PowerShell Gallery) and update to the latest version
        If you have a module with two or more versions, the script delete them and reinstall only the latest.

	.EXAMPLE
		.\PowerShell-UpdateModules.ps1

        Update installed modules automaticly

        .\PowerShell-UpdateModules.ps1 -SimulationMode

        Simulate the update process of installed modules - nothing is installed / removed / updated

    .NOTES
        Updated at:	18-06-2023
#>

[CmdletBinding()]
param (
    [Parameter()]
    # To exclude modules from the update process
    [String[]]$ExcludedModules,
    # To include only these modules for the update process
    [String[]]$IncludedModules,
    [switch]$SkipPublisherCheck,
    [switch]$SimulationMode
)

#Requires -Version 5.0
#Requires -RunAsAdministrator

$MessageColor = "Green"
$AssessmentColor = "Yellow"
$ErrorColor = "Red"

#Start logging
Start-Transcript -Path "C:\Temp\Sonnes\Logs\PowerShell Modules\UpdateModules - $(((get-date).ToUniversalTime()).ToString("ddMMyyyyThhmmssZ")).log" -Force

Write-Host -ForegroundColor cyan 'Define PowerShell to add TLS1.2 in this session, needed since 1st April 2020 (https://devblogs.microsoft.com/powershell/powershell-gallery-tls-support/)'
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

# if needed, register PSGallery
# Register PSGallery PSprovider and set as Trusted source
# Register-PSRepository -Default -ErrorAction SilentlyContinue
# Set-PSRepository -Name PSGallery -InstallationPolicy trusted -ErrorAction SilentlyContinue

# Set simulation mode if need to test
if ($SimulationMode) {
    Write-Host -ForegroundColor yellow 'Simulation mode is ON, nothing will be installed / removed / updated'
}
else {
    Write-Host -ForegroundColor red 'Simulation mode is OFF, modules will be installed / removed / updated'
}

# Start script - getting all modules
Write-Host -ForegroundColor Cyan 'Getting all PowerShell modules...'

# Uninstall modules
function Remove-OldPowerShellModules {
    param (
        [string]$ModuleName,
        [string]$GalleryVersion
    )

    if (-not($SimulationMode)) {
        # Check and remove older versions of the modules from the PC
        Write-Host -ForegroundColor Cyan "Beginning clean-up phase for $ModuleName older than $GalleryVersion..."
    }

    try {
        $oldVersions = Get-InstalledModule -Name $ModuleName -AllVersions -ErrorAction Stop | Where-Object { $_.Version -ne $GalleryVersion }

        foreach ($oldVersion in $oldVersions) {
            Write-Host -ForegroundColor Cyan "$ModuleName - Uninstall previous version ($($oldVersion.Version))"
            if (-not($SimulationMode)) {
                Remove-Module $ModuleName -ErrorAction SilentlyContinue
                Uninstall-Module $oldVersion -Force  -ErrorAction Stop
                Write-Host -ForegroundColor Green "$module is uninstalled, version: $oldVersion"
            }
        }
    }
    catch {
        Write-Host -ForegroundColor $ErrorColor "Something went wrong with uninstall $module. Details:"
        Write-Warning "$module - $($_.Exception.Message)"
    }
}

if ($IncludedModules) {
    $modules = Get-InstalledModule | Where-Object { $IncludedModules -contains $_.Name }
}
else {
    $modules = Get-InstalledModule
}

foreach ($module in $modules.Name) {
    if ($ExcludedModules -contains $module) {
        Write-Host -ForegroundColor Yellow "Module $module is excluded from the update process"
        continue
    }
    elseif ($module -like "$excludedModules") {
        Write-Host -ForegroundColor Yellow "Module $module is excluded from the update process (match $excludeModules)"
        continue
    }

    $currentVersion = $null
	
    try {
        $currentVersion = (Get-InstalledModule -Name $module -AllVersions -ErrorAction Stop).Version
    }
    catch {
        Write-Host -ForegroundColor $AssessmentColor "Something went wrong with finding $module. Details:"
        Write-Warning "$module - $($_.Exception.Message)"
        continue
    }
	
    try {
        $moduleGalleryInfo = Find-Module -Name $module -ErrorAction Stop
    }
    catch {
        Write-Warning "$module not found in the PowerShell Gallery. Details:"
        Write-Warning "$($_.Exception.Message)"
    }
	
    if ($null -eq $currentVersion) {
        Write-Host -ForegroundColor Cyan "$module - Install from PowerShellGallery version $($moduleGalleryInfo.Version) - Release date: $($moduleGalleryInfo.PublishedDate)"
		
        if (-not($SimulationMode)) {
            try {
                Install-Module -Name $module -Force -SkipPublisherCheck -ErrorAction Stop
                Write-Host -ForegroundColor Green "$module is installed, version: $($moduleGalleryInfo.Version)"
            }
            catch {
                Write-Host -ForegroundColor $ErrorColor "Something went wrong with installing $module. Details:"
                Write-Warning "$module - $($_.Exception.Message)"
            }
        }
    }
    elseif ($moduleGalleryInfo.Version -eq $currentVersion) {
        Write-Host -ForegroundColor Green "$module already in latest version: $currentVersion - Release date: $($moduleGalleryInfo.PublishedDate)"
    }
    elseif ($currentVersion.count -gt 1) {
        Write-Host -ForegroundColor Yellow "$module is installed in $($currentVersion.count) versions (versions: $($currentVersion -join ' | '))"
        Write-Host -ForegroundColor Cyan "$module - Uninstall previous $module version(s) below the latest version ($($moduleGalleryInfo.Version))"
        
        Remove-OldPowerShellModules -ModuleName $module -GalleryVersion $moduleGalleryInfo.Version

        # Check again the current Version as we uninstalled some old versions
        $currentVersion = (Get-InstalledModule -Name $module).Version

        if ($moduleGalleryInfo.Version -ne $currentVersion) {
            Write-Host -ForegroundColor Cyan "$module - Install from PowerShellGallery version $($moduleGalleryInfo.Version) - Release date: $($moduleGalleryInfo.PublishedDate)"  
            if (-not($SimulationMode)) {
                try {
                    Install-Module -Name $module -Force -ErrorAction Stop

                    Write-Host -ForegroundColor Green "$module is installed, version: $($moduleGalleryInfo.Version)"

                    Remove-OldPowerShellModules -ModuleName $module -GalleryVersion $moduleGalleryInfo.Version
                }
                catch {
                    Write-Host -ForegroundColor $ErrorColor "Something went wrong with install new version of $module. Details:"
                    Write-Warning "$module - $($_.Exception.Message)"
                }
            }
        }
    }
    elseif ([version]$currentVersion -gt [version]$moduleGalleryInfo.Version) {   
        Write-Host -ForegroundColor Yellow "$module - the current version $currentVersion is newer than the version available on PowerShell Gallery $($moduleGalleryInfo.Version) (Release date: $($moduleGalleryInfo.PublishedDate)). Sometimes happens when you install a module from another repository or via .exe/.msi or if you change the version number manually."
    }
    elseif ([version]$currentVersion -lt [version]$moduleGalleryInfo.Version) {
        Write-Host -ForegroundColor Cyan "$module - Update from PowerShellGallery version " -NoNewline
        Write-Host -ForegroundColor White "$currentVersion -> $($moduleGalleryInfo.Version) " -NoNewline 
        Write-Host -ForegroundColor Cyan "- Release date: $($moduleGalleryInfo.PublishedDate)"
        
        if (-not($SimulationMode)) {
            try {
                Update-Module -Name $module -Force -ErrorAction Stop
                Remove-OldPowerShellModules -ModuleName $module -GalleryVersion $moduleGalleryInfo.Version
            }
            catch {
                if ($_.Exception.Message -match 'Authenticode') {
                    Write-Host -ForegroundColor Yellow "$module - The module certificate used by the creator is either changed since the last module install or the module sign status has changed." 
                
                    if ($SkipPublisherCheck.IsPresent) {
                        Write-Host -ForegroundColor Cyan "$module - SkipPublisherCheck Parameter is present, so install will run without Authenticode check"
                        Write-Host -ForegroundColor Cyan "$module - Install from PowerShellGallery version $($moduleGalleryInfo.Version) - Release date: $($moduleGalleryInfo.PublishedDate)"  
                        try {
                            Install-Module -Name $module -Force -SkipPublisherCheck

                            Write-Host -ForegroundColor Green "$module is installed (SkipPublisherCheck), version: $($moduleGalleryInfo.Version)"
                        }
                        catch {
                            Write-Host -ForegroundColor $ErrorColor "Something went wrong when install $module. Details:"
                            Write-Warning "$module - $($_.Exception.Message)"
                        }
                    
                        Remove-OldPowerShellModules -ModuleName $module -GalleryVersion $moduleGalleryInfo.Version
                    }
                    else {
                        Write-Warning "$module - If you want to update this module, run again with -SkipPublisherCheck switch, but please keep in mind the security risk"
                    }
                }
                else {
                    Write-Warning "$module - $($_.Exception.Message)"
                }
            }
        }
    }
}

# Stop Logging
Stop-Transcript
# SIG # Begin signature block
# MIIo7AYJKoZIhvcNAQcCoIIo3TCCKNkCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDpTzn5dYdEesul
# +9TH/0BolGLxb1bHnSMbpykAeuvqGKCCEd8wggVvMIIEV6ADAgECAhBI/JO0YFWU
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
# gf9SsIAod1Dx9THs2qkXIwyf5lTJBvPHLRqxs/k+Mn70AUiyj50/JYMxghZjMIIW
# XwIBATBoMFQxCzAJBgNVBAYTAkdCMRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQx
# KzApBgNVBAMTIlNlY3RpZ28gUHVibGljIENvZGUgU2lnbmluZyBDQSBSMzYCEBHh
# oIZkh66CYIKNKPBResYwDQYJYIZIAWUDBAIBBQCgfDAQBgorBgEEAYI3AgEMMQIw
# ADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYK
# KwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgu415ZO05kwztEj54LBNyL45f8N+s
# 1KqVQZVFw4RcUBgwDQYJKoZIhvcNAQEBBQAEggIAFMjo7aU86k+hoS51AWWcJc3G
# nF0WFguAuLs0X281S60AnfhxNxCiGQN7pwfDaFV+fHf835UT0GF4I5Nt4UqC8UtU
# r0kOR4hG3D/tEDoN0ZzqgOXeZXGHJfF8Rnws6LvGtwsntsk05YI2p3cOXpfM9Hlv
# 8KVHpiE9cgKLItFwIQThcI71auPssojv/JoJkGoz15mXZFco3KpjYR1Xj+v8+4yP
# aRjLHAMEVx1KuEkeRGmI68ujcxJRHyusz2tl4SpzVYkhSnKdUGvJTFLpfPwv8PMX
# nHF20JRHg4KYIcvLrR0uUJ/sVXLa8lOPGgCObMJaxgfCl2TmetrBzZYBYYu1ylvc
# lLc3EQNpdYRHpR+MsqXw8AGLfz3Rw+w6em2t31gBxjOvb4g/J1hZZd2NauXfi87K
# 7rpy7gXTv9+Yfl9Ls09to8Sha8CDImViglZ6wPXjsPpNzGAQQpxDLT1tM5EtHieU
# TTRizT9xTflvXr7bvRbDUHEdX23nbND8jFfbPxf+8Fkp2wCF0R8aP2HXxZO1SMH2
# DcEURDSbdjrW/XYIkVxg1I4H+k2bbjSRibIn7kCUJ2TCWL8/bCIIhyKHUyR4g3FV
# Ke8y5B1xDSrhjPGiBjA836hMc6AVetkexXjpMobQMmlbrw/daFgA1v7Gt4VaDtOj
# Lr0AJ4Y+SO8q/u3ciUihghNOMIITSgYKKwYBBAGCNwMDATGCEzowghM2BgkqhkiG
# 9w0BBwKgghMnMIITIwIBAzEPMA0GCWCGSAFlAwQCAgUAMIHvBgsqhkiG9w0BCRAB
# BKCB3wSB3DCB2QIBAQYKKwYBBAGyMQIBATAxMA0GCWCGSAFlAwQCAQUABCBSuIxN
# UAiq5PuMrQ9aQDh5L44QOMQsV2wgB8q8XdQ80AIUGssB3ARtqbS/hr0Y+cZFa7mS
# O8MYDzIwMjMwOTExMTQ1MzIyWqBupGwwajELMAkGA1UEBhMCR0IxEzARBgNVBAgT
# Ck1hbmNoZXN0ZXIxGDAWBgNVBAoTD1NlY3RpZ28gTGltaXRlZDEsMCoGA1UEAwwj
# U2VjdGlnbyBSU0EgVGltZSBTdGFtcGluZyBTaWduZXIgIzSggg3pMIIG9TCCBN2g
# AwIBAgIQOUwl4XygbSeoZeI72R0i1DANBgkqhkiG9w0BAQwFADB9MQswCQYDVQQG
# EwJHQjEbMBkGA1UECBMSR3JlYXRlciBNYW5jaGVzdGVyMRAwDgYDVQQHEwdTYWxm
# b3JkMRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQxJTAjBgNVBAMTHFNlY3RpZ28g
# UlNBIFRpbWUgU3RhbXBpbmcgQ0EwHhcNMjMwNTAzMDAwMDAwWhcNMzQwODAyMjM1
# OTU5WjBqMQswCQYDVQQGEwJHQjETMBEGA1UECBMKTWFuY2hlc3RlcjEYMBYGA1UE
# ChMPU2VjdGlnbyBMaW1pdGVkMSwwKgYDVQQDDCNTZWN0aWdvIFJTQSBUaW1lIFN0
# YW1waW5nIFNpZ25lciAjNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB
# AKSTKFJLzyeHdqQpHJk4wOcO1NEc7GjLAWTkis13sHFlgryf/Iu7u5WY+yURjlqI
# CWYRFFiyuiJb5vYy8V0twHqiDuDgVmTtoeWBIHIgZEFsx8MI+vN9Xe8hmsJ+1yzD
# uhGYHvzTIAhCs1+/f4hYMqsws9iMepZKGRNcrPznq+kcFi6wsDiVSs+FUKtnAyWh
# uzjpD2+pWpqRKBM1uR/zPeEkyGuxmegN77tN5T2MVAOR0Pwtz1UzOHoJHAfRIuBj
# hqe+/dKDcxIUm5pMCUa9NLzhS1B7cuBb/Rm7HzxqGXtuuy1EKr48TMysigSTxleG
# oHM2K4GX+hubfoiH2FJ5if5udzfXu1Cf+hglTxPyXnypsSBaKaujQod34PRMAkjd
# WKVTpqOg7RmWZRUpxe0zMCXmloOBmvZgZpBYB4DNQnWs+7SR0MXdAUBqtqgQ7vaN
# ereeda/TpUsYoQyfV7BeJUeRdM11EtGcb+ReDZvsdSbu/tP1ki9ShejaRFEqoswA
# yodmQ6MbAO+itZadYq0nC/IbSsnDlEI3iCCEqIeuw7ojcnv4VO/4ayewhfWnQ4XY
# Kzl021p3AtGk+vXNnD3MH65R0Hts2B0tEUJTcXTC5TWqLVIS2SXP8NPQkUMS1zJ9
# mGzjd0HI/x8kVO9urcY+VXvxXIc6ZPFgSwVP77kv7AkTAgMBAAGjggGCMIIBfjAf
# BgNVHSMEGDAWgBQaofhhGSAPw0F3RSiO0TVfBhIEVTAdBgNVHQ4EFgQUAw8xyJEq
# k71j89FdTaQ0D9KVARgwDgYDVR0PAQH/BAQDAgbAMAwGA1UdEwEB/wQCMAAwFgYD
# VR0lAQH/BAwwCgYIKwYBBQUHAwgwSgYDVR0gBEMwQTA1BgwrBgEEAbIxAQIBAwgw
# JTAjBggrBgEFBQcCARYXaHR0cHM6Ly9zZWN0aWdvLmNvbS9DUFMwCAYGZ4EMAQQC
# MEQGA1UdHwQ9MDswOaA3oDWGM2h0dHA6Ly9jcmwuc2VjdGlnby5jb20vU2VjdGln
# b1JTQVRpbWVTdGFtcGluZ0NBLmNybDB0BggrBgEFBQcBAQRoMGYwPwYIKwYBBQUH
# MAKGM2h0dHA6Ly9jcnQuc2VjdGlnby5jb20vU2VjdGlnb1JTQVRpbWVTdGFtcGlu
# Z0NBLmNydDAjBggrBgEFBQcwAYYXaHR0cDovL29jc3Auc2VjdGlnby5jb20wDQYJ
# KoZIhvcNAQEMBQADggIBAEybZVj64HnP7xXDMm3eM5Hrd1ji673LSjx13n6UbcMi
# xwSV32VpYRMM9gye9YkgXsGHxwMkysel8Cbf+PgxZQ3g621RV6aMhFIIRhwqwt7y
# 2opF87739i7Efu347Wi/elZI6WHlmjl3vL66kWSIdf9dhRY0J9Ipy//tLdr/vpMM
# 7G2iDczD8W69IZEaIwBSrZfUYngqhHmo1z2sIY9wwyR5OpfxDaOjW1PYqwC6WPs1
# gE9fKHFsGV7Cg3KQruDG2PKZ++q0kmV8B3w1RB2tWBhrYvvebMQKqWzTIUZw3C+N
# dUwjwkHQepY7w0vdzZImdHZcN6CaJJ5OX07Tjw/lE09ZRGVLQ2TPSPhnZ7lNv8wN
# sTow0KE9SK16ZeTs3+AB8LMqSjmswaT5qX010DJAoLEZKhghssh9BXEaSyc2quCY
# HIN158d+S4RDzUP7kJd2KhKsQMFwW5kKQPqAbZRhe8huuchnZyRcUI0BIN4H9wHU
# +C4RzZ2D5fjKJRxEPSflsIZHKgsbhHZ9e2hPjbf3E7TtoC3ucw/ZELqdmSx813Uf
# jxDElOZ+JOWVSoiMJ9aFZh35rmR2kehI/shVCu0pwx/eOKbAFPsyPfipg2I2yMO+
# AIccq/pKQhyJA9z1XHxw2V14Tu6fXiDmCWp8KwijSPUV/ARP380hHHrl9Y4a1LlA
# MIIG7DCCBNSgAwIBAgIQMA9vrN1mmHR8qUY2p3gtuTANBgkqhkiG9w0BAQwFADCB
# iDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCk5ldyBKZXJzZXkxFDASBgNVBAcTC0pl
# cnNleSBDaXR5MR4wHAYDVQQKExVUaGUgVVNFUlRSVVNUIE5ldHdvcmsxLjAsBgNV
# BAMTJVVTRVJUcnVzdCBSU0EgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMTkw
# NTAyMDAwMDAwWhcNMzgwMTE4MjM1OTU5WjB9MQswCQYDVQQGEwJHQjEbMBkGA1UE
# CBMSR3JlYXRlciBNYW5jaGVzdGVyMRAwDgYDVQQHEwdTYWxmb3JkMRgwFgYDVQQK
# Ew9TZWN0aWdvIExpbWl0ZWQxJTAjBgNVBAMTHFNlY3RpZ28gUlNBIFRpbWUgU3Rh
# bXBpbmcgQ0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDIGwGv2Sx+
# iJl9AZg/IJC9nIAhVJO5z6A+U++zWsB21hoEpc5Hg7XrxMxJNMvzRWW5+adkFiYJ
# +9UyUnkuyWPCE5u2hj8BBZJmbyGr1XEQeYf0RirNxFrJ29ddSU1yVg/cyeNTmDoq
# HvzOWEnTv/M5u7mkI0Ks0BXDf56iXNc48RaycNOjxN+zxXKsLgp3/A2UUrf8H5Vz
# JD0BKLwPDU+zkQGObp0ndVXRFzs0IXuXAZSvf4DP0REKV4TJf1bgvUacgr6Unb+0
# ILBgfrhN9Q0/29DqhYyKVnHRLZRMyIw80xSinL0m/9NTIMdgaZtYClT0Bef9Maz5
# yIUXx7gpGaQpL0bj3duRX58/Nj4OMGcrRrc1r5a+2kxgzKi7nw0U1BjEMJh0giHP
# Yla1IXMSHv2qyghYh3ekFesZVf/QOVQtJu5FGjpvzdeE8NfwKMVPZIMC1Pvi3vG8
# Aij0bdonigbSlofe6GsO8Ft96XZpkyAcSpcsdxkrk5WYnJee647BeFbGRCXfBhKa
# Bi2fA179g6JTZ8qx+o2hZMmIklnLqEbAyfKm/31X2xJ2+opBJNQb/HKlFKLUrUMc
# pEmLQTkUAx4p+hulIq6lw02C0I3aa7fb9xhAV3PwcaP7Sn1FNsH3jYL6uckNU4B9
# +rY5WDLvbxhQiddPnTO9GrWdod6VQXqngwIDAQABo4IBWjCCAVYwHwYDVR0jBBgw
# FoAUU3m/WqorSs9UgOHYm8Cd8rIDZsswHQYDVR0OBBYEFBqh+GEZIA/DQXdFKI7R
# NV8GEgRVMA4GA1UdDwEB/wQEAwIBhjASBgNVHRMBAf8ECDAGAQH/AgEAMBMGA1Ud
# JQQMMAoGCCsGAQUFBwMIMBEGA1UdIAQKMAgwBgYEVR0gADBQBgNVHR8ESTBHMEWg
# Q6BBhj9odHRwOi8vY3JsLnVzZXJ0cnVzdC5jb20vVVNFUlRydXN0UlNBQ2VydGlm
# aWNhdGlvbkF1dGhvcml0eS5jcmwwdgYIKwYBBQUHAQEEajBoMD8GCCsGAQUFBzAC
# hjNodHRwOi8vY3J0LnVzZXJ0cnVzdC5jb20vVVNFUlRydXN0UlNBQWRkVHJ1c3RD
# QS5jcnQwJQYIKwYBBQUHMAGGGWh0dHA6Ly9vY3NwLnVzZXJ0cnVzdC5jb20wDQYJ
# KoZIhvcNAQEMBQADggIBAG1UgaUzXRbhtVOBkXXfA3oyCy0lhBGysNsqfSoF9bw7
# J/RaoLlJWZApbGHLtVDb4n35nwDvQMOt0+LkVvlYQc/xQuUQff+wdB+PxlwJ+TNe
# 6qAcJlhc87QRD9XVw+K81Vh4v0h24URnbY+wQxAPjeT5OGK/EwHFhaNMxcyyUzCV
# pNb0llYIuM1cfwGWvnJSajtCN3wWeDmTk5SbsdyybUFtZ83Jb5A9f0VywRsj1sJV
# hGbks8VmBvbz1kteraMrQoohkv6ob1olcGKBc2NeoLvY3NdK0z2vgwY4Eh0khy3k
# /ALWPncEvAQ2ted3y5wujSMYuaPCRx3wXdahc1cFaJqnyTdlHb7qvNhCg0MFpYum
# Cf/RoZSmTqo9CfUFbLfSZFrYKiLCS53xOV5M3kg9mzSWmglfjv33sVKRzj+J9hyh
# tal1H3G/W0NdZT1QgW6r8NDT/LKzH7aZlib0PHmLXGTMze4nmuWgwAxyh8FuTVrT
# HurwROYybxzrF06Uw3hlIDsPQaof6aFBnf6xuKBlKjTg3qj5PObBMLvAoGMs/FwW
# AKjQxH/qEZ0eBsambTJdtDgJK0kHqv3sMNrxpy/Pt/360KOE2See+wFmd7lWEOEg
# bsausfm2usg1XTN2jvF8IAwqd661ogKGuinutFoAsYyr4/kKyVRd1LlqdJ69SK6Y
# MYIELDCCBCgCAQEwgZEwfTELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIg
# TWFuY2hlc3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEYMBYGA1UEChMPU2VjdGlnbyBM
# aW1pdGVkMSUwIwYDVQQDExxTZWN0aWdvIFJTQSBUaW1lIFN0YW1waW5nIENBAhA5
# TCXhfKBtJ6hl4jvZHSLUMA0GCWCGSAFlAwQCAgUAoIIBazAaBgkqhkiG9w0BCQMx
# DQYLKoZIhvcNAQkQAQQwHAYJKoZIhvcNAQkFMQ8XDTIzMDkxMTE0NTMyMlowPwYJ
# KoZIhvcNAQkEMTIEMLnjy3DO3VACFojhbbbxiV8tFxLmd1a857uOzOEW9dTGu+CI
# mzuVL1YxsKd6qrTiYDCB7QYLKoZIhvcNAQkQAgwxgd0wgdowgdcwFgQUrmKvdQoM
# vUfWRh91aOK8jOfKT5QwgbwEFALWW5Xig3DBVwCV+oj5I92Tf62PMIGjMIGOpIGL
# MIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMKTmV3IEplcnNleTEUMBIGA1UEBxML
# SmVyc2V5IENpdHkxHjAcBgNVBAoTFVRoZSBVU0VSVFJVU1QgTmV0d29yazEuMCwG
# A1UEAxMlVVNFUlRydXN0IFJTQSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eQIQMA9v
# rN1mmHR8qUY2p3gtuTANBgkqhkiG9w0BAQEFAASCAgCDXzpzIm4Du4vI5sp0mA4d
# yYTYJJTe0V6064r2frqD4FDk5ufsNY2EHcuBZzWdx+3wOULu2485slXJH8de3uor
# JIdv/vvNIuJZHMQk8jaWS6exVq1S82+uQSrIe49xOScfeimp/GP7+A3EP8lLnrYa
# G0jqJDSFAXFxoyIe6dTHXUfgeNUJP22gp2d1QCXi8muTj0Nm4vMT3gLEprWjfAsg
# wa3txagj7ZRW8Ux4SlRee50OWHFRcgHlMuOAI2eOzFehdF70NYlFhRpql9X7MsUf
# 1U0mbprqJIaPFa6N+u/Nq5g1X0cTdlj+Wwk9ci4ywcjI2AnRO79eakL9LF76HpXA
# wORBNrPdP7QCXhOaW67Mn0FaNgqfg0PUMC8AqM3QJ8F17olNewTXpwkkCdcBaK0Q
# zaOOCWx18LlfMA7/m+U4lgLWmm9W6KoctKpHdOJQE6Dt1QEzrsIhCAJPEOS1kaZl
# SXFDrfxWv2y+yZp74uC1WhEpgGvbhurTAKInlrs0Kn5Rx8UxtB06KK/AO/paHmu6
# uDi5vcwsxZjyBoDQEg/9ZnShUrCh9oEpqQ7GuAnWNj37uK5DffT+p/h9Ykyn2KwD
# eyd9RKOze7eBtdiOS3ak9hJkk76r+eiOLdjZ25HaPFnPcEGZ3XFB/8n4waEjbYg4
# 9bw0iZpVfiazKFjgB3p6Aw==
# SIG # End signature block
