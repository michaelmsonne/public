<#	
	.NOTES
	===========================================================================
	 Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2022 v5.8.213
	 Created on:   	20-01-2024 10:58
	 Created by:   	Michael Morten Sonne
	 Organization: 	Sonne´s Cloud
	 Filename:     	"1 - Install the Sensor - arguments.ps1"
	 Version:		1.0
	===========================================================================
	.DESCRIPTION
        This script will install the sensor on the host and ask for the access key.

    .EXAMPLE
        .\"1 - Install the Sensor - arguments.ps1" -AccessKey 'YourAccessKey' -UseProxy -ProxyUrl 'YourProxyUrl' -ProxyUserName 'YourProxyUsername' -ProxyUserPassword 'YourProxyPassword'
#>

param (
    [string]$InstallerPath = ".\Azure ATP sensor Setup.exe",
    [string]$AccessKey,
    [switch]$UseProxy,
    [string]$ProxyUrl,
    [string]$ProxyUserName,
    [string]$ProxyUserPassword # Needs to be a SecureString, but fails when using [SecureString]$ProxyUserPassword... TODO: Fix this
)

# Check if the installer exists
Write-Host "Checking if '$InstallerPath' exists in the current folder..." -ForegroundColor Yellow
if (Test-Path $InstallerPath -PathType Leaf) {
    # Confirm that the installer exists
    Write-Host "'$InstallerPath' found in the current folder." -ForegroundColor Green

    # Make AccessKey mandatory
    if (-not $AccessKey) {
        throw "Error: AccessKey is mandatory. Please provide a valid AccessKey."
    }

    # Check if the user wants to use a proxy
    if ($UseProxy) {
        # Check if the proxy settings are complete and not empty
        if ([string]::IsNullOrWhiteSpace($ProxyUrl) -or [string]::IsNullOrWhiteSpace($ProxyUserName) -or -not $ProxyUserPassword) {
            Write-Host "Error: Proxy settings are incomplete. Please provide all proxy details (ProxyUrl, ProxyUsername, and ProxyPassword)." -ForegroundColor Red
            return
        }
        else {
            # Convert the plain text password to a SecureString
            $SecureProxyUserPassword = ConvertTo-SecureString -String $ProxyUserPassword -AsPlainText -Force
            # Clear the plain text password from memory
            $ProxyUserPassword = $null

            # Confirm the entered proxy settings
            Write-Host "Entered Proxy Settings:" -ForegroundColor Yellow
            Write-Host "Proxy URL: $ProxyUrl"
            Write-Host "Proxy Username: $ProxyUserName"
            Write-Host "Proxy Password: Not shown for security reasons."

            # Proxy arguments for the installer confirmed by the user
            Write-Host "Proxy settings confirmed. Continuing with the installation process." -ForegroundColor Green

            # Construct the proxy arguments
            $ProxyArguments = "/ProxyUrl=`"$ProxyUrl`" /ProxyUserName=`"$ProxyUserName`" /ProxyUserPassword=`"$SecureProxyUserPassword`""
        }
    }

    # Construct the argument list dynamically based on whether a proxy is used
    $ArgumentList = @('/quiet', 'NetFrameworkCommandLineArguments="/q"', "AccessKey=`"$AccessKey`"")
    if ($ProxyArguments) {
        $ArgumentList += $ProxyArguments
    }

    # Start the installation process
    Write-Host "Starting installation process..."  -ForegroundColor Yellow
    $Process = Start-Process -FilePath $InstallerPath -ArgumentList $ArgumentList -PassThru -Wait

    if ($Process.ExitCode -eq 0) {
        Write-Host "Installation completed successfully." -ForegroundColor Green
    } else {
        Write-Host "Installation failed with exit code $($Process.ExitCode)." -ForegroundColor Red
    }
} else {
    Write-Host "Error: '$InstallerPath' not found in the current folder." -ForegroundColor Red
}

# Script completed
Write-host "Script completed."