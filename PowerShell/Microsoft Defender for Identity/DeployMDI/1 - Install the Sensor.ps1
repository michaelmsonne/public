<#	
	.NOTES
	===========================================================================
	 Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2022 v5.8.213
	 Created on:   	18-01-2024 19:23
	 Created by:   	Michael Morten Sonne
	 Organization: 	Sonne´s Cloud
	 Filename:     	"1 - Install the Sensor.ps1"
	 Version:		1.0
	===========================================================================
	.DESCRIPTION
        This script will install the sensor on the host and ask for the access key.

    .EXAMPLE
        .\"1 - Install the Sensor.ps1"
#>

# Install MDI sensor:
$InstallerPath = ".\Azure ATP sensor Setup.exe"

# Check if the installer exists
Write-Host "Checking if 'Azure ATP sensor Setup.exe' exists in the current folder..." -ForegroundColor Yellow
if (Test-Path $InstallerPath -PathType Leaf) {
    # Confirm that the installer exists
    Write-Host "'Azure ATP sensor Setup.exe' found in the current folder." -ForegroundColor Green

    # Ask the user if they want to use a proxy
    $UseProxy = Read-Host "Do you want to use a proxy? (Enter 'Y' for Yes, 'N' for No)"
    
    # Check if the user wants to use a proxy
    if ($UseProxy -eq 'Y' -or $UseProxy -eq 'y') {
        # Get the proxy settings from the user
        $ProxyUrl = Read-Host "Enter the Proxy URL"
        $ProxyUserName = Read-Host "Enter the Proxy Username"
        $ProxyUserPassword = Read-Host "Enter the Proxy Password" -AsSecureString

        # Confirm the entered proxy settings
        Write-Host "Entered Proxy Settings:" -ForegroundColor Yellow
        Write-Host "Proxy URL: $ProxyUrl"
        Write-Host "Proxy Username: $ProxyUserName"
        Write-Host "Proxy Password: Not shown for security reasons."

        # Confirm the proxy settings
        $ConfirmProxy = Read-Host "Are these proxy settings correct? (Enter 'Y' for Yes, 'N' for No)" -ForegroundColor Yellow
        if ($ConfirmProxy -eq 'N' -or $ConfirmProxy -eq 'n') {
            Write-Host "Proxy settings not confirmed. Exiting script." -ForegroundColor Red
            
            # Exit the script if the proxy settings are not confirmed by the user
            exit
        }

        # Proxy arguments for the installer confirmed by the user
        Write-Host "Proxy settings confirmed. Continuing with the installation process." -ForegroundColor Green

        # Construct the proxy arguments
        $ProxyArguments = "/ProxyUrl=`"$ProxyUrl`" /ProxyUserName=`"$ProxyUserName`" /ProxyUserPassword=`"$ProxyUserPassword`""
    } else {
        # Set the proxy arguments to empty if the user does not want to use a proxy
        $ProxyArguments = ""
    }

    # Check if Access Key is not empty
    do {
        $AccessKey = Read-Host "Enter the Access Key"
    } while ([string]::IsNullOrWhiteSpace($AccessKey))

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
    Write-Host "Error: 'Azure ATP sensor Setup.exe' not found in the current folder." -ForegroundColor Red
}

# Script completed
Write-host "Script completed."