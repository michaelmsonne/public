<#
	.NOTES
	===========================================================================
	 Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2022 v5.8.213
	 Created on:   	14-01-2023 10:25
	 Created by:   	Michael Morten Sonne
	 Organization: 	Sonne´s Cloud
	 Blog:          https://blog.sonnes.cloud
	 Filename:     	'DownloadNewestMicrosoftEvalSoftware.ps1'
	===========================================================================

	.DESCRIPTION
        This PowerShell script retrieves download links for the latest Microsoft Evaluation Center software releases.
        It scans a predefined list of URLs, extracts relevant information such as software title, name, tag, format, and download link, and exports the details to a CSV file.
        The exported CSV file serves as a convenient reference for users to access the latest Microsoft evaluation software downloads from the Evaluation Center for testing and evaluation purposes faster.

    .CHANGELOG
        14-01-2023 - first version of the script.
        
    .PARAMETER outputfile
        The path to the CSV file where the download links will be exported. If not specified, the default path is C:\Temp\EvalCenterDownloads.csv.
         
      EXAMPLE
         PS > .\DownloadNewestMicrosoftEvalSoftware.ps1 -outputfile 'C:\Folder\EvalCenterDownloads.csv'
#>

param (
    [string]$outputfile = 'C:\Temp\EvalCenterDownloads.csv'
)

# Reset totalcount to null
$totalDownloadCount = $null
 
# List of Evalution Center links with downloadable content
$urls = @(
    'https://www.microsoft.com/en-us/evalcenter/download-host-integration-server-2020',
    'https://www.microsoft.com/en-us/evalcenter/download-hyper-v-server-2016',
    'https://www.microsoft.com/en-us/evalcenter/download-hyper-v-server-2019',
    'https://www.microsoft.com/en-us/evalcenter/download-lab-kit',
    'https://www.microsoft.com/en-us/evalcenter/download-mem-evaluation-lab-kit',
    'https://www.microsoft.com/en-us/evalcenter/download-microsoft-endpoint-configuration-manager',
    'https://www.microsoft.com/en-us/evalcenter/download-microsoft-endpoint-configuration-manager-technical-preview',
    'https://www.microsoft.com/en-us/evalcenter/download-microsoft-identity-manager-2016',
    'https://www.microsoft.com/en-us/evalcenter/download-sharepoint-server-2013',
    'https://www.microsoft.com/en-us/evalcenter/download-sharepoint-server-2016',
    'https://www.microsoft.com/en-us/evalcenter/download-sharepoint-server-2019',
    'https://www.microsoft.com/en-us/evalcenter/download-sql-server-2016',
    'https://www.microsoft.com/en-us/evalcenter/download-sql-server-2017-rtm',
    'https://www.microsoft.com/en-us/evalcenter/download-sql-server-2019',
    'https://www.microsoft.com/en-us/evalcenter/download-sql-server-2022',
    'https://www.microsoft.com/en-us/evalcenter/download-system-center-2019',
    'https://www.microsoft.com/en-us/evalcenter/download-system-center-2022',
    'https://www.microsoft.com/en-us/evalcenter/download-windows-10-enterprise',
    'https://www.microsoft.com/en-us/evalcenter/download-windows-11-enterprise',
    'https://www.microsoft.com/en-us/evalcenter/download-windows-11-office-365-lab-kit',
    'https://www.microsoft.com/en-us/evalcenter/download-windows-server-2012-r2',
    'https://www.microsoft.com/en-us/evalcenter/download-windows-server-2012-r2-essentials',
    'https://www.microsoft.com/en-us/evalcenter/download-windows-server-2012-r2-essentials',
    'https://www.microsoft.com/en-us/evalcenter/download-windows-server-2016',
    'https://www.microsoft.com/en-us/evalcenter/download-windows-server-2016-essentials',
    'https://www.microsoft.com/en-us/evalcenter/download-windows-server-2019',
    'https://www.microsoft.com/en-us/evalcenter/download-windows-server-2019-essentials',
    'https://www.microsoft.com/en-us/evalcenter/download-windows-server-2022'
)

# Loop through the URLs, search for download links, and add to totalfound array
$ProgressPreference = "SilentlyContinue"

# Loop through the URLs and search for download links and add to totalfound array
$totalfound = foreach ($url in $urls) {
    try {
        # Get the content of the URL
        $content = Invoke-WebRequest -Uri $url -ErrorAction Stop

        # Search for download links and add to totalfound array
        $downloadLinks = $content.links | Where-Object { `
                $_.'aria-label' -match 'Download' `
                -and $_.outerHTML -match 'fwlink' `
                -or $_.'aria-label' -match '64-bit edition' }
        # Count the number of download links found and add to totalDownloadCount  
        $count = $downloadLinks.href.Count
        $totalDownloadCount += $count

        # Output the URL and the number of download links found to the console
        Write-host ("Processing {0}, Found {1} Download(s)..." -f $url, $count) -ForegroundColor Green
        if ($count -gt 0) {
            # Output the download links found to the console if any
            foreach ($downloadLink in $downloadLinks) {
                # Create a custom object to store the download details
                $downloadDetails = [PSCustomObject]@{
                    Title  = $url.split('/')[5].replace('-', ' ').replace('download ', '')
                    Name   = $downloadLink.'aria-label'.Replace('Download ', '')
                    Tag    = $downloadLink.'data-bi-tags'.Split('&')[3].split(';')[1]
                    Format = $downloadLink.'data-bi-tags'.Split('-')[1].ToUpper()
                    Link   = $downloadLink.href
                }
                # Output the download details to the console
                Write-Host ("  Title: {0}, Name: {1}, Tag: {2}, Format: {3}, Link: {4}" -f `
                $downloadDetails.Title, $downloadDetails.Name, $downloadDetails.Tag, $downloadDetails.Format, $downloadDetails.Link) -ForegroundColor Yellow
                $downloadDetails # Output the custom object
            }
        } else {
            # Output a message if no download links are found
            Write-Host ("No download links found.") -ForegroundColor Red
        }        
    }
    catch {
        # Output a warning if the URL is not accessible
        Write-Warning ("{0} is not accessible" -f $url)
    }
}

if ($null -eq $totalDownloadCount) {
    # Output a message if no download links are found
    Write-Host "No download links found." -ForegroundColor Red
    exit
}
else {
    # Output total downloads found and export result to the $outputfile path specified
    Write-Host ("Found a total of {0} Downloads there is collected links to you can download." -f $totalDownloadCount) -ForegroundColor Green

    # Export the totalfound array to a CSV file
    $totalfound | Sort-Object Title, Name, Tag, Format | Export-Csv -NoTypeInformation -Encoding UTF8 -Delimiter ';' -Path $outputfile

    # Output the path to the CSV file
    Write-Host ("The download links have been exported to {0}" -f $outputfile) -ForegroundColor Green
}