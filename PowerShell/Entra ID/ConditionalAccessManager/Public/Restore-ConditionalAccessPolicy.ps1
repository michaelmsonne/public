function Restore-ConditionalAccessPolicy {
    <#
    .SYNOPSIS
    Restores a deleted Conditional Access policy
    
    .DESCRIPTION
    Restores a deleted Conditional Access policy by its ID from the deleted items collection
    
    .PARAMETER PolicyId
    The ID of the deleted policy to restore
    
    .EXAMPLE
    Restore-ConditionalAccessPolicy -PolicyId "12345678-1234-1234-1234-123456789012"
    
    .EXAMPLE
    Restore-ConditionalAccessPolicy -PolicyId "12345678-1234-1234-1234-123456789012" -WhatIf
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$PolicyId
    )
    
    try {
        # First verify the policy exists in deleted items
        $uri = "https://graph.microsoft.com/beta/identity/conditionalAccess/deletedItems/policies/$PolicyId"
        $deletedPolicy = Invoke-MgGraphRequest -Uri $uri -Method GET
        
        if (-not $deletedPolicy) {
            Write-Error "Policy with ID $PolicyId not found in deleted items"
            return
        }
        
        Write-Host "Policy found: $($deletedPolicy.displayName)" -ForegroundColor Green
        
        if ($WhatIfPreference) {
            Write-Host "Would restore policy: $($deletedPolicy.displayName) (ID: $PolicyId)" -ForegroundColor Yellow
            return
        }
        
        if ($PSCmdlet.ShouldProcess($deletedPolicy.displayName, "Restore Conditional Access Policy")) {
            # Use the correct restore endpoint from Microsoft Graph documentation
            $restoreUri = "https://graph.microsoft.com/beta/identity/conditionalAccess/deletedItems/policies/$PolicyId/restore"
            
            # No request body required according to documentation
            $response = Invoke-MgGraphRequest -Uri $restoreUri -Method POST
            
            Write-Host "Successfully restored policy: $($deletedPolicy.displayName)" -ForegroundColor Green
            return $response
        }
    }
    catch {
        Write-Error "Failed to restore policy $PolicyId : $($_.Exception.Message)"
        throw
    }
}