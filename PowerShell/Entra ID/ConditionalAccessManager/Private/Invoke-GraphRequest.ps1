function Invoke-GraphRequest {
    <#
    .SYNOPSIS
    Internal helper function to make Microsoft Graph API requests
    
    .DESCRIPTION
    Wraps Invoke-MgGraphRequest with error handling and beta endpoint support
    
    .PARAMETER Uri
    The Graph API endpoint URI
    
    .PARAMETER Method
    HTTP method (GET, POST, DELETE, etc.)
    
    .PARAMETER Body
    Request body for POST/PUT operations
    
    .PARAMETER Beta
    Use beta endpoint instead of v1.0
    
    .EXAMPLE
    Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/me" -Method GET
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Uri,
        
        [string]$Method = 'GET',
        
        [object]$Body,
        
        [switch]$Beta
    )
    
    # Ensure beta endpoint if requested
    if ($Beta -and $Uri -notmatch '/beta/') {
        $Uri = $Uri -replace '/v1\.0/', '/beta/'
        if ($Uri -notmatch '/beta/') {
            $Uri = $Uri -replace 'https://graph\.microsoft\.com/', 'https://graph.microsoft.com/beta/'
        }
    }
    
    try {
        $requestParams = @{
            Method = $Method
            Uri = $Uri
        }
        
        if ($Body) {
            $requestParams.Body = $Body | ConvertTo-Json -Depth 20
        }
        
        $response = Invoke-MgGraphRequest @requestParams
        return $response
    }
    catch {
        Write-Error "Graph API request failed for $Method $Uri : $($_.Exception.Message)"
        throw
    }
}