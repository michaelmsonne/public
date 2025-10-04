function Export-ConditionalAccessPolicies {
    <#
    .SYNOPSIS
    Exports Conditional Access policies to JSON file
    
    .DESCRIPTION
    Exports active or deleted Conditional Access policies to a JSON file for backup or analysis
    
    .PARAMETER OutputPath
    Path where the JSON file will be saved
    
    .PARAMETER IncludeDeleted
    Include deleted policies in the export
    
    .PARAMETER IncludeActive
    Include active policies in the export (default: true)
    
    .EXAMPLE
    Export-ConditionalAccessPolicies -OutputPath "C:\temp\ca-policies.json"
    
    .EXAMPLE
    Export-ConditionalAccessPolicies -OutputPath "C:\temp\all-policies.json" -IncludeDeleted -IncludeActive
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$OutputPath,
        
        [switch]$IncludeDeleted,
        
        [switch]$IncludeActive
    )
    
    try {
        $exportData = @{
            ExportDate      = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            ActivePolicies  = @()
            DeletedPolicies = @()
        }
        
        # Default to including active policies if neither is specified
        if (-not $IncludeDeleted -and -not $IncludeActive) {
            $IncludeActive = $true
        }
        
        if ($IncludeActive) {
            Write-Host "Retrieving active Conditional Access policies..." -ForegroundColor Yellow
            $activeUri = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
            $activeResponse = Invoke-MgGraphRequest -Uri $activeUri -Method GET
            
            if ($activeResponse.value) {
                $exportData.ActivePolicies = $activeResponse.value
                Write-Host "Found $($activeResponse.value.Count) active policies" -ForegroundColor Green
            }
        }
        
        if ($IncludeDeleted) {
            Write-Host "Retrieving deleted Conditional Access policies..." -ForegroundColor Yellow
            $deletedPolicies = Get-DeletedConditionalAccessPolicies -IncludeDetails
            
            if ($deletedPolicies) {
                $exportData.DeletedPolicies = $deletedPolicies
                Write-Host "Found $($deletedPolicies.Count) deleted policies" -ForegroundColor Green
            }
        }
        
        # Ensure directory exists
        $directory = Split-Path -Path $OutputPath -Parent
        if (-not (Test-Path -Path $directory)) {
            New-Item -ItemType Directory -Path $directory -Force | Out-Null
        }
        
        $jsonOutput = $exportData | ConvertTo-Json -Depth 20
        $jsonOutput | Out-File -FilePath $OutputPath -Encoding UTF8
        
        Write-Host "Policies exported successfully to: $OutputPath" -ForegroundColor Green
        
        return @{
            FilePath             = $OutputPath
            ActivePoliciesCount  = $exportData.ActivePolicies.Count
            DeletedPoliciesCount = $exportData.DeletedPolicies.Count
            ExportDate           = $exportData.ExportDate
        }
    }
    catch {
        Write-Error "Failed to export policies: $($_.Exception.Message)"
        throw
    }
}