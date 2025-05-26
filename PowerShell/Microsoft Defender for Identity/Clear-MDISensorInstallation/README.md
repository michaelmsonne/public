# Clear-MDISensorInstallation.ps1

## Overview

`Clear-MDISensorInstallation.ps1` is a PowerShell script designed to **completely remove the Microsoft Defender for Identity (MDI) sensor** from a Windows host. It performs a thorough cleanup, including services, processes, files, folders, registry keys, and certificates related to the MDI sensor.

## Features

- Disables, stops, and removes MDI sensor services
- Terminates running sensor processes and named pipes
- Uninstalls NPCAP (unless ADCS or ADFS is detected)
- Removes sensor installation folders and files
- Cleans up all related registry keys
- Deletes the Azure ATP Sensor certificate from the local machine store
- Displays risk and confirmation banners before proceeding

## Usage

1. **Run PowerShell as Administrator:**
   - Right-click PowerShell and select "Run as administrator".

2. **Set Execution Policy (if required):**
   ```powershell
   Set-ExecutionPolicy RemoteSigned
3. Navigate to the Script Directory:
    ```powershell
   cd "C:\Path\To\Clear-MDISensorInstallation"
4. Execute the Script:
   ```powershell
    .\Clear-MDISensorInstallation.ps1
5. Follow Prompts:

The script will display warnings and require confirmation before making any changes.

## Important Notes
**Irreversible Action:** This script will permanently remove the MDI sensor and all related components from the host.
Manual Portal Cleanup: After running the script, remove the sensor entry from the Microsoft Defender for Identity portal:
https://security.microsoft.com/securitysettings/identities?tabid=sensor