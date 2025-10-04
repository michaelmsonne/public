function Get-DeletedConditionalAccessPolicies {
    <#
    .SYNOPSIS
    Retrieves deleted Conditional Access policies from Microsoft Graph
    
    .DESCRIPTION
    Gets a list of deleted Conditional Access policies that can potentially be restored
    
    .PARAMETER IncludeDetails
    Include full policy details in the output
    
    .EXAMPLE
    Get-DeletedConditionalAccessPolicies
    
    .EXAMPLE
    Get-DeletedConditionalAccessPolicies -IncludeDetails
    #>
    [CmdletBinding()]
    param(
        [switch]$IncludeDetails
    )
    
    try {
        Write-Verbose "Retrieving deleted Conditional Access policies..."
        
        $uri = "https://graph.microsoft.com/beta/identity/conditionalAccess/deletedItems/policies"
        $response = Invoke-MgGraphRequest -Uri $uri -Method GET
        
        if ($response.value) {
            $policies = $response.value
            Write-Host "Found $($policies.Count) deleted Conditional Access policies" -ForegroundColor Green
            
            if ($IncludeDetails) {
                return $policies
            }
            else {
                return $policies | Select-Object id, displayName, deletedDateTime, 
                @{Name = 'State'; Expression = { $_.state } },
                @{Name = 'CreatedBy'; Expression = { $_.createdBy.displayName } },
                @{Name = 'ModifiedBy'; Expression = { $_.modifiedBy.displayName } }
            }
        }
        else {
            Write-Host "No deleted Conditional Access policies found" -ForegroundColor Yellow
            return @()
        }
    }
    catch {
        Write-Error "Failed to retrieve deleted policies: $($_.Exception.Message)"
        throw
    }
}