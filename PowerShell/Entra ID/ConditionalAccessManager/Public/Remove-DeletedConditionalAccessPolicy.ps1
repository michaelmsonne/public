function Remove-DeletedConditionalAccessPolicy {
    <#
    .SYNOPSIS
    Permanently removes a deleted Conditional Access policy
    
    .DESCRIPTION
    Permanently removes a deleted Conditional Access policy from the deleted items collection.
    This action cannot be undone.
    
    .PARAMETER PolicyId
    The ID of the deleted policy to permanently remove
    
    .PARAMETER Force
    Skip confirmation prompt
    
    .EXAMPLE
    Remove-DeletedConditionalAccessPolicy -PolicyId "12345678-1234-1234-1234-123456789012"
    
    .EXAMPLE
    Remove-DeletedConditionalAccessPolicy -PolicyId "12345678-1234-1234-1234-123456789012" -Force
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$PolicyId,
        
        [switch]$Force
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
            Write-Host "Would permanently remove policy: $($deletedPolicy.displayName) (ID: $PolicyId)" -ForegroundColor Yellow
            return
        }
        
        if ($Force -or $PSCmdlet.ShouldProcess($deletedPolicy.displayName, "Permanently Remove Conditional Access Policy")) {
            $response = Invoke-MgGraphRequest -Uri $uri -Method DELETE
            
            Write-Host "Successfully removed policy: $($deletedPolicy.displayName)" -ForegroundColor Green
            return $response
        }
    }
    catch {
        Write-Error "Failed to remove policy $PolicyId : $($_.Exception.Message)"
        throw
    }
}