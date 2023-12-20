<#	
	.NOTES
	===========================================================================
	 Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2022 v5.8.213
	 Created on:   	06-12-2023 15:41
	 Created by:   	Michael Morten Sonne
	 Organization: 	Sonne´s Cloud
	 Filename:     	EntraID-QuotaAndNotification.ps1
	===========================================================================
	.DESCRIPTION
		PowerShell script to check the Entra ID Directory Size Quota and send a Microsoft Teams notification if the threshold is exceeded.

    .REQUREMENT
        - Microsoft Graph PowerShell SDK
        - Microsoft Teams Webhook URL
        - Microsoft Graph API Application with the following permissions: Organization.Read.All

	.EXAMPLE
		.\EntraID-QuotaAndNotification.ps1
        
        Connect whit a certificate
        .\EntraID-QuotaAndNotification.ps1 -ClientId "YOUR_APP_ID" -TenantId "YOUR_TENANT_ID" -CertificateThumbprint "YOUR_CERT_THUMBPRINT" -WebhookUrl "YOUR_WEBHOOK_URL"

        Connect whit a client secret
        .\EntraID-QuotaAndNotification.ps1 -ClientId "YOUR_APP_ID" -TenantId "YOUR_TENANT_ID" -ClientSecret "YOUR_CLIENT_SECRET" -WebhookUrl "YOUR_WEBHOOK_URL"
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$ClientId,

    [Parameter(Mandatory=$true)]
    [string]$TenantId,

    [Parameter(Mandatory=$false)]
    [string]$CertificateThumbprint,

    [Parameter(Mandatory=$false)]
    [string]$ClientSecret,

    [Parameter(Mandatory=$true)]
    [string]$WebhookUrl
)

# Check if either CertificateThumbprint or ClientSecret was provided as a parameter to the script and exit if not
if (-not ($CertificateThumbprint -or $ClientSecret)) {
    Write-Host "At least one of CertificateThumbprint or ClientSecret should be provided." -ForegroundColor Red
    Write-Host "Exiting..." -ForegroundColor Red
    Exit
}

# Function to connect to Microsoft Graph API
function ConnectToMSGraph {
    # Connect to Microsoft Graph API based on provided parameters (CertificateThumbprint or ClientSecret) and webhookUrl, TenantId and ClientId parameters are mandatory!
    if ($CertificateThumbprint) {
        # Connect to Microsoft Graph API using a certificate
        Write-Host "Connecting to Microsoft Graph API using a certificate..." -ForegroundColor Yellow
        Connect-MgGraph -ClientId $ClientId -TenantId $TenantId -CertificateThumbprint $CertificateThumbprint -Scopes "Organization.Read.All"
    } else {
        # Connect to Microsoft Graph API using a client secret
        Write-Host "Connecting to Microsoft Graph API using a client secret..." -ForegroundColor Yellow

        # Create a PSCredential object based on the provided ClientId and ClientSecret
        $ApplicationId = $ClientId
        $SecuredPassword = $ClientSecret   
        $SecuredPasswordPassword = ConvertTo-SecureString -String $SecuredPassword -AsPlainText -Force    
        $ClientSecretCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $ApplicationId, $SecuredPasswordPassword

        # Connect to Microsoft Graph API using the PSCredential object
        Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $ClientSecretCredential -NoWelcome
    }
}

# Function to fetch data from Microsoft Graph API
function Get-MgGraphData {
    param (
        [string]$Resource
    )

    # Setting up Graph API URL
    $graphApiVersion = "beta"
    $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"

    # Initiate query via Graph API
    $data = Invoke-MgGraphRequest -Method GET $uri

    # Return data from Graph API query
    return $data
}

# Function to handle webhook call to Microsoft Teams
function InvokeWebhookCall($webhookUrl, $webhookJSON) {
    $webhookCall = @{
        "URI"         = $webhookUrl
        "Method"      = 'POST'
        "Body"        = $webhookJSON
        "ContentType" = 'application/json'
    }

    # Invoke Microsoft Teams webhook call
    Invoke-RestMethod @webhookCall
}

# Function to create message payload for Microsoft Teams webhook call
function CreateWebhookMessage($title, $text) {
    $webhookMessage = [PSCustomObject][Ordered]@{
        "@type"      = "MessageCard"
        "@context"   = "http://schema.org/extensions"
        "themeColor" = 'FF0000'
        "title"      = $title
        "text"       = $text
    }
    
    # Return message payload
    return ConvertTo-Json $webhookMessage -Depth 50
}

# Connect to Microsoft Graph API using the provided parameters
ConnectToMSGraph

# Fetch directory size quota data
$graphData = Get-MgGraphData -Resource "organization?$select=directorysizequota"

# Check if data was fetched successfully
if ($null -ne $graphData -and $null -ne $graphData.value)
{
    # Fetch used and total directory size quota
    $directorySizeQuota = $graphData.value[0].directorySizeQuota

    # Check if used and total directory size quota was fetched successfully
    $used = $directorySizeQuota.used
    $total = $directorySizeQuota.total

    # Calculate used percentage of total directory size quota
    $usedPercentage = ($used / $total) * 100

    # Fetch maximum directory size quota
    $maxSizeResource = "organization?$select=directorysizequota"
    $maxSizeGraphData = Get-MgGraphData -Resource $maxSizeResource

    # Check if maximum size data was fetched successfully
    if ($null -ne $maxSizeGraphData -and $null -ne $maxSizeGraphData.value)
    {
        # Fetch maximum directory size quota
        $maxSize = $maxSizeGraphData.value[0].directorySizeQuota.total

        # Check if the used percentage is within the maximum size
        if ($usedPercentage -le 90)
        {
            $title = "Entra ID Directory size quota is within threshold - all is okay!"
            $text = "Entra ID Directory size is: $used objects, size is within threshold - no action needed! Percentage used now is $($usedPercentage)%<br><br><strong>Information:</strong><br>Used: $used objects of $total objects.<br>Maximum size: $maxSize objects."

            # Create message payload
            $webhookJSON = CreateWebhookMessage -title $title -text $text

            # Invoke webhook call using the function
            InvokeWebhookCall -webhookUrl $webhookUrl -webhookJSON $webhookJSON

            # Write output to console
            Write-Output "Entra ID Directory Size is within threshold: Used $used objects of $total objects and percentage used is $($usedpercentage)%"
        }

        # Check if the used percentage is over 90% of the maximum size
        if ($usedPercentage -gt 90 -and $usedPercentage -le 95) {
            $title = "Entra ID Directory size quota will soon be exceeded!"
            $text = "Entra ID Directory size is: $used objects, size threshold exceeded! Percentage used now is $($usedPercentage)%<br><br><strong>Information:</strong><br>Used: $used objects of $total objects.<br>Maximum size: $maxSize objects."

            # Create message payload
            $webhookJSON = CreateWebhookMessage -title $title -text $text

            # Invoke webhook call using the function
            InvokeWebhookCall -webhookUrl $webhookUrl -webhookJSON $webhookJSON

            # Write output to console
            Write-Output "Entra ID Directory Size is: $used objects of $total objects, Size Threshold exceeded! Percentage used now is $($usedpercentage)%"
        }

        # Check if the used percentage is over 95% of the maximum size
        elseif ($usedPercentage -gt 95 -and $usedPercentage -le 100) {
            $title = "Entra ID Directory size quota will soon be exceeded - take action NOW!"
            $text = "Entra ID Directory size is: $used objects, size threshold exceeded! Percentage used now is $($usedPercentage)%<br><br><strong>Information:</strong><br>Used: $used objects of $total objects.<br>Maximum size: $maxSize objects."

            # Create message payload
            $webhookJSON = CreateWebhookMessage -title $title -text $text

            # Invoke webhook call using the function
            InvokeWebhookCall -webhookUrl $webhookUrl -webhookJSON $webhookJSON

            # Write output to console
            Write-Output "Entra ID Directory Size is: $used objects of $total objects, Size Threshold exceeded! Percentage used now is $($usedpercentage)%"
        }
        
        # Check if the used percentage is over of the maximum size
        if ($usedPercentage -gt 100)
        {
            $title = "Entra ID Directory size quota IS exceeded - take action NOW as noting new can be created!"
            $text = "Entra ID Directory size is: $used objects, size threshold exceeded! Percentage used now is $($usedPercentage)%<br><br><strong>Information:</strong><br>Used: $used objects of $total objects.<br>Maximum size: $maxSize objects."

            # Create message payload
            $webhookJSON = CreateWebhookMessage -title $title -text $text

            # Invoke webhook call using the function
            InvokeWebhookCall -webhookUrl $webhookUrl -webhookJSON $webhookJSON

            # Write output to console
            Write-Output "Entra ID Directory Size is: $used objects of $total objects, which is greater than the maximum size and percentage used is $($usedpercentage)%."
        }
    }
    else
    {
        Write-Output "Failed to retrieve or parse maximum size data from Microsoft Graph API."
    }
}
else
{
    Write-Output "Failed to retrieve or parse data from Microsoft Graph API."
}