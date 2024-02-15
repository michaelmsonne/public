<#	
	.NOTES
	===========================================================================
	 Created on:    14-01-2023 10:25
	 Created by:    Michael Morten Sonne
	 Organization: 	
	 Filename:     	Download_Microsoft_Eval_Software.ps1
	===========================================================================
	.DESCRIPTION
        Get Microsoft Evaluation Center Download Links and export to CSV file.
         
      EXAMPLE
         PS > .\Download_Microsoft_Eval_Software.ps1 -outputfile 'C:\Folder\EvalCenterDownloads.csv'
#>

param (
    [string]$outputfile = 'C:\Temp\EvalCenterDownloads.csv'
)

#Reset totalcount to null
$totalcount = $null
 
#List of Evalution Center links with downloadable content
$urls = @(
    'https://www.microsoft.com/en-us/evalcenter/download-biztalk-server-2016',
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
    'https://www.microsoft.com/en-us/evalcenter/download-skype-business-server-2019',
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
$totalfound = foreach ($url in $urls) {
    try {
        $content = Invoke-WebRequest -Uri $url -ErrorAction Stop
        $downloadlinks = $content.links | Where-Object { `
                $_.'aria-label' -match 'Download' `
                -and $_.outerHTML -match 'fwlink' `
                -or $_.'aria-label' -match '64-bit edition' }    
        $count = $downloadlinks.href.Count
        $totalcount += $count
        Write-host ("Processing {0}, Found {1} Download(s)..." -f $url, $count) -ForegroundColor Green
        if ($count -gt 0) {
            foreach ($downloadlink in $downloadlinks) { # Fix variable name here
                $downloadDetails = [PSCustomObject]@{
                    Title  = $url.split('/')[5].replace('-', ' ').replace('download ', '')
                    Name   = $downloadlink.'aria-label'.Replace('Download ', '')
                    Tag    = $downloadlink.'data-bi-tags'.Split('&')[3].split(';')[1]
                    Format = $downloadlink.'data-bi-tags'.Split('-')[1].ToUpper()
                    Link   = $downloadlink.href
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

if ($null -eq $totalcount) {
    Write-Host "No download links found." -ForegroundColor Red
    exit
}
else {
    # Output total downloads found and export result to the $outputfile path specified
    Write-Host ("Found a total of {0} Downloads there is collected links to you can download." -f $totalcount) -ForegroundColor Green

    # Export the totalfound array to a CSV file
    $totalfound | Sort-Object Title, Name, Tag, Format | Export-Csv -NoTypeInformation -Encoding UTF8 -Delimiter ';' -Path $outputfile

    # Output the path to the CSV file
    Write-Host ("The download links have been exported to {0}" -f $outputfile) -ForegroundColor Green
}