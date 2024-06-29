<#	
	.NOTES
	===========================================================================
	 Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2022 v5.8.213
	 Created on:   	17-05-2024 19:21
	 Created by:   	Michael Morten Sonne
	 Organization: 	Sonne´s Cloud
	 Blog:          https://blog.sonnes.cloud
	 GitHub:        https://github.com/michaelmsonne
	 Filename:     	'Veeam-FixTeamsBackupError.ps1'
	===========================================================================
	.DESCRIPTION
		PowerShell script to fix Veeam Backup for Microsoft 365 error "Processing mailbox user@domain.com failed with error: Failed to get folder properties. Not allowed to access Non IPM folder."
        by adding the SkipTeamsMessagesDataFolders setting to the Config.xml file and restarting the Veeam Archiver Service.

    .REQUREMENT
        - Veeam Backup for Microsoft 365 v6 or later
        - PowerShell 5.1 or later
        - Run script with elevated privileges
        - Backup original Config.xml file before running the script

    .CHANGELOG
        17-05-2024 - Michael Morten Sonne - Initial release

    .EXAMPLE
        PS> Veeam-FixTeamsBackupError.ps1

    .CHANGELOG
        17-05-2024 - Michael Morten Sonne - Initial release
#>

$configFilePath = "C:\ProgramData\Veeam\Backup365\Config.xml"

try {
    # Load XML content from Config.xml
    $xmlContent = [xml](Get-Content $configFilePath)

    # Check if SkipTeamsMessagesDataFolders setting already exists
    if ($xmlContent.SelectSingleNode("//Archiver/Proxy[@SkipTeamsMessagesDataFolders='True']")) {
        Write-Output "The 'SkipTeamsMessagesDataFolders' setting already exists. No changes were made!"
    } else {
        # Backup the original Config.xml file
        $backupFilePath = "$configFilePath$($(Get-Date -Format '.ddMMyyyy')).old"
        Copy-Item -Path $configFilePath -Destination $backupFilePath -ErrorAction Stop

        # Verify that the backup was created successfully
        if (Test-Path -Path $backupFilePath) {
            Write-Output "Backup created successfully at $backupFilePath."

            # Create a new Proxy element and set attributes
            $newElement = $xmlContent.CreateElement("Proxy")
            $newElement.SetAttribute("SkipTeamsMessagesDataFolders", "True")

            # Append the new element to the Archiver node
            $archiverNode = $xmlContent.SelectSingleNode("//Archiver")
            $archiverNode.AppendChild($newElement)

            # Save changes to Config.xml
            $xmlContent.Save($configFilePath)
            Write-Output "The 'SkipTeamsMessagesDataFolders' setting has been added."

            # Restart the Veeam Archiver Service
            Restart-Service -Name "Veeam.Archiver.Service" -ErrorAction Stop
        } else {
            Write-Error "Failed to create a backup of the Config.xml file. Changes will not be made."
        }
    }
}
catch {
    Write-Error "An error occurred: $_"
}
finally {
    Write-Output "Process completed. Please verify the changes and ensure services are ready for backup again."
}