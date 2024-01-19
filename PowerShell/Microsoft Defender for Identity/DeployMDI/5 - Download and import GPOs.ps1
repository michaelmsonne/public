<#	
	.NOTES
	===========================================================================
	 Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2022 v5.8.213
	 Created on:   	19-01-2024 19:04
	 Created by:   	Michael Morten Sonne
	 Organization: 	Sonne´s Cloud
	 Filename:     	"5 - Download and import GPOs.ps1"
	 Version:		1.0
	===========================================================================
	.DESCRIPTION
        This script will download and extract the MDI GPOs.
#>

# Function to create and import GPOs
function CreateAndImportGPO {
    param (
        [string]$GPOName,
        [string]$BackupId
    )

    try {
        $GPO = New-GPO -Name $GPOName

        try {
            Import-GPO -Path C:\Temp\MDI-GPOs -BackupId $BackupId -TargetGuid $GPO.Id -Domain $localdomain.Forest

            # Uncomment the following line to automatically link GPO to the Domain Controllers OU
            # New-GPLink -Name $GPO.DisplayName -Target "OU=Domain Controllers,DC=lab,DC=sonnes,DC=cloud"
            Write-Host "GPO '$GPOName' created and imported successfully." -ForegroundColor Green
        } catch {
            Write-Host "Error importing GPO '$GPOName': $_" -ForegroundColor Red
            # Handle the import error as needed
        }
    } catch {
        Write-Host "Error creating GPO '$GPOName': $_" -ForegroundColor Red
        # Handle the creation error as needed
    }
}

# Set the source URL and destination paths
$SourceUrl = "https://raw.githubusercontent.com/michaelmsonne/public/main/PowerShell/Microsoft%20Defender%20for%20Identity/DeployMDI/MDI-GPO-Import.zip"
$DestinationFolder = "C:\Temp"

# Download the file using BITS
try {
	Write-Host "Downloading the GPO file from $SourceUrl to $DestinationFolder..."
    Start-BitsTransfer -Source $SourceUrl -Destination $DestinationFolder -DisplayName "Downloading MDI-GPO-Import.zip"
    Write-Host "Download completed successfully." -ForegroundColor Green
} catch {
    Write-Host "Error downloading the file: $_" -ForegroundColor Red
    exit
}

# Extract MDI GPOs
try {
    $ZipFilePath = Join-Path -Path $DestinationFolder -ChildPath "MDI-GPO-Import.zip"
    $DestinationPath = Join-Path -Path $DestinationFolder -ChildPath "MDI-GPO"

	Write-Host "Extracting the contents of $ZipFilePath to $DestinationPath..." -ForegroundColor Yellow
    Expand-Archive -Path $ZipFilePath -DestinationPath $DestinationPath
    Write-Host "Extraction completed successfully." -ForegroundColor Green
} catch {
    Write-Host "Error extracting the contents: $_" -ForegroundColor Red
    exit
}

# Import the GPOs
Write-Host "Importing the GPOs..." -ForegroundColor Yellow

# Create GPOs for domain controllers
CreateAndImportGPO -GPOName "Microsoft Defender for Identity - Advanced Audit Policy for CAs" -BackupId "10C96B19-99E5-47FB-8D91-7A08255553B2"
CreateAndImportGPO -GPOName "Microsoft Defender for Identity - Advanced Audit Policy for DCs" -BackupId "E445CE28-CF1E-4FEB-945C-1AF76E2DF490"

# Create other GPOs (Modify as needed)
CreateAndImportGPO -GPOName "Microsoft Defender for Identity - Auditing for CAs" -BackupId "BD4C8B67-86A9-4AE1-8A56-DC7170E3A530"
CreateAndImportGPO -GPOName "Microsoft Defender for Identity - NTLM Auditing for DCs" -BackupId "E633D0F2-7726-4707-84E6-992BC2E1426F"
CreateAndImportGPO -GPOName "Microsoft Defender for Identity - Processor Performance" -BackupId "FEF8FAFF-A207-45FD-BB90-7530365A0062"

# Ask the user if they want to delete the file
$DeleteFile = Read-Host "Do you want to delete the file $ZipFilePath (downloaded GPO files)? (Enter 'Y' for Yes, 'N' for No)"

try {
    # Process user input
    if ($DeleteFile -eq 'Y' -or $DeleteFile -eq 'y') {
        # Delete the file
        Remove-Item -Path $ZipFilePath -Force

        # Show a confirmation that the file has been deleted
        Write-Host "File $ZipFilePath deleted successfully." -ForegroundColor Green
    } else {
        # Show a warning that the file was not deleted
        Write-Host "File deletion canceled. The file $ZipFilePath was not deleted." -ForegroundColor Red
    }
}
catch {
    # Show an error if the file could not be deleted
    Write-Host "An error occurred: $_" -ForegroundColor Red
}

# Script completed
Write-host "Script completed."