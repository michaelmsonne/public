<#	
	.NOTES
	===========================================================================
	 Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2022 v5.8.213
	 Created on:   	14-02-2024 21:37
	 Created by:   	Michael Morten Sonne
	 Organization: 	Sonne´s Cloud
	 Blog:          https://blog.sonnes.cloud
	 Filename:     	Enable-TLS1.2.ps1
	===========================================================================
	.DESCRIPTION
		PowerShell script to enable TLS 1.2 on Windows. The script sets the registry keys to enable TLS 1.2 on the machine and displays a message to restart the machine for the changes to take effect.
        Is a need for Azure AD Connect V2.x

    .REQUREMENT
        - Administrator rights on the machine

    .CHANGELOG
        14-02-2024 - Michael Morten Sonne - Initial release

	.EXAMPLE
        .\Enable-TLS1.2.ps1
#>

# Check if running as administrator
$adminRights = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $adminRights) {
    Write-Host "Please run this script as an administrator."
    Start-Sleep -Seconds 3
    Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`"" -Verb RunAs
    Exit
}

# Function to get the current hostname
function Get-CurrentHostname {
    $hostname = (Get-WmiObject Win32_ComputerSystem).Name
    return $hostname
}

# Function to prompt for user confirmation
function Get-Confirmation {
    $currentHostname = Get-CurrentHostname
    $confirmation = Read-Host "Do you want to enable TLS 1.2 on the host '$currentHostname'? (Y/N)"
    return $confirmation -eq 'Y' -or $confirmation -eq 'y'
}

try {
    # Check if user wants to enable TLS 1.2
    if (Get-Confirmation) {
        # Enable TLS 1.2 on the Azure AD Connect server

        # .NET Framework settings
        if (-Not (Test-Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319')) {
            New-Item 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319' -Force | Out-Null
        }
        New-ItemProperty -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319' -Name 'SystemDefaultTlsVersions' -Value '1' -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value '1' -PropertyType 'DWord' -Force | Out-Null

        if (-Not (Test-Path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319')) {
            New-Item 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' -Force | Out-Null
        }
        New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' -Name 'SystemDefaultTlsVersions' -Value '1' -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value '1' -PropertyType 'DWord' -Force | Out-Null

        # SCHANNEL settings for TLS 1.2
        if (-Not (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server')) {
            New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Force | Out-Null
        }
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Name 'Enabled' -Value '1' -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Name 'DisabledByDefault' -Value '0' -PropertyType 'DWord' -Force | Out-Null

        if (-Not (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client')) {
            New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Force | Out-Null
        }
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Name 'Enabled' -Value '1' -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Name 'DisabledByDefault' -Value '0' -PropertyType 'DWord' -Force | Out-Null

        Write-Host 'TLS 1.2 has been enabled. You must restart the Windows Server for the changes to take effect.' -ForegroundColor Green
    }
    else {
        Write-Host 'TLS 1.2 has not been enabled. No changes were made.' -ForegroundColor Yellow
    }
}
catch {
    Write-Host "An error occurred: $_" -ForegroundColor Red
}