function Start-ConditionalAccessManagerConsole {
    <#
    .SYNOPSIS
    Starts an interactive console for managing Conditional Access policies
    
    .DESCRIPTION
    Provides an interactive menu-driven interface for listing, restoring, and managing 
    deleted Conditional Access policies
    
    .EXAMPLE
    Start-ConditionalAccessManagerConsole
    #>
    [CmdletBinding()]
    param()
    
    Write-Host "=== Conditional Access Policy Recovery Console ===" -ForegroundColor Cyan
    Write-Host ""
    
    do {
        Write-Host "`n--- Main Menu ---" -ForegroundColor Yellow
        Write-Host "1. List deleted policies"
        Write-Host "2. List deleted policies (detailed)"
        Write-Host "3. Restore a policy"
        Write-Host "4. Permanently remove a deleted policy"
        Write-Host "5. Export policies to JSON"
        Write-Host "6. Show authentication status"
        Write-Host "0. Exit"
        Write-Host ""
        
        $choice = Read-Host "Select an option (0-6)"
        
        switch ($choice) {
            "1" {
                Write-Host "`nRetrieving deleted policies..." -ForegroundColor Yellow
                try {
                    $policies = Get-DeletedConditionalAccessPolicies
                    if ($policies) {
                        $policies | Format-Table -AutoSize
                    }
                }
                catch {
                    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
                }
            }
            
            "2" {
                Write-Host "`nRetrieving deleted policies with details..." -ForegroundColor Yellow
                try {
                    $policies = Get-DeletedConditionalAccessPolicies -IncludeDetails
                    if ($policies) {
                        foreach ($policy in $policies) {
                            Write-Host "`n--- $($policy.displayName) ---" -ForegroundColor Green
                            Write-Host "ID: $($policy.id)"
                            Write-Host "State: $($policy.state)"
                            Write-Host "Deleted: $($policy.deletedDateTime)"
                            Write-Host "Created: $($policy.createdDateTime)"
                            Write-Host "Modified: $($policy.modifiedDateTime)"
                        }
                    }
                }
                catch {
                    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
                }
            }
            
            "3" {
                Write-Host "`nRestore Policy" -ForegroundColor Yellow
                try {
                    $policies = Get-DeletedConditionalAccessPolicies
                    if ($policies -and $policies.Count -gt 0) {
                        Write-Host "`nAvailable policies to restore:"
                        for ($i = 0; $i -lt $policies.Count; $i++) {
                            Write-Host "$($i + 1). $($policies[$i].displayName) (ID: $($policies[$i].id))"
                        }
                        
                        $selection = Read-Host "`nEnter policy number to restore (or 'c' to cancel)"
                        if ($selection -eq 'c') {
                            Write-Host "Cancelled" -ForegroundColor Yellow
                        }
                        elseif ($selection -match '^\d+$' -and [int]$selection -le $policies.Count -and [int]$selection -gt 0) {
                            $selectedPolicy = $policies[[int]$selection - 1]
                            $confirm = Read-Host "Restore policy '$($selectedPolicy.displayName)'? (y/N)"
                            if ($confirm -eq 'y') {
                                Restore-ConditionalAccessPolicy -PolicyId $selectedPolicy.id
                            }
                            else {
                                Write-Host "Cancelled" -ForegroundColor Yellow
                            }
                        }
                        else {
                            Write-Host "Invalid selection" -ForegroundColor Red
                        }
                    }
                    else {
                        Write-Host "No deleted policies available to restore" -ForegroundColor Yellow
                    }
                }
                catch {
                    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
                }
            }
            
            "4" {
                Write-Host "`nPermanently Remove Policy" -ForegroundColor Yellow
                try {
                    $policies = Get-DeletedConditionalAccessPolicies
                    if ($policies -and $policies.Count -gt 0) {
                        Write-Host "`nAvailable policies to remove:"
                        for ($i = 0; $i -lt $policies.Count; $i++) {
                            Write-Host "$($i + 1). $($policies[$i].displayName) (ID: $($policies[$i].id))"
                        }
                        
                        $selection = Read-Host "`nEnter policy number to remove (or 'c' to cancel)"
                        if ($selection -eq 'c') {
                            Write-Host "Cancelled" -ForegroundColor Yellow
                        }
                        elseif ($selection -match '^\d+$' -and [int]$selection -le $policies.Count -and [int]$selection -gt 0) {
                            $selectedPolicy = $policies[[int]$selection - 1]
                            Write-Host "WARNING: This will permanently remove the policy and cannot be undone!" -ForegroundColor Red
                            $confirm = Read-Host "Permanently remove policy '$($selectedPolicy.displayName)'? Type 'DELETE' to confirm"
                            if ($confirm -eq 'DELETE') {
                                Remove-DeletedConditionalAccessPolicy -PolicyId $selectedPolicy.id -Force
                            }
                            else {
                                Write-Host "Cancelled" -ForegroundColor Yellow
                            }
                        }
                        else {
                            Write-Host "Invalid selection" -ForegroundColor Red
                        }
                    }
                    else {
                        Write-Host "No deleted policies available to remove" -ForegroundColor Yellow
                    }
                }
                catch {
                    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
                }
            }
            
            "5" {
                Write-Host "`nExport Policies" -ForegroundColor Yellow
                try {
                    $defaultPath = ".\CA-Policies-Export-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
                    $outputPath = Read-Host "Enter export path (default: $defaultPath)"
                    if ([string]::IsNullOrWhiteSpace($outputPath)) {
                        $outputPath = $defaultPath
                    }
                    
                    $includeActive = Read-Host "Include active policies? (Y/n)"
                    $includeDeleted = Read-Host "Include deleted policies? (Y/n)"
                    
                    $params = @{ OutputPath = $outputPath }
                    if ($includeActive -ne 'n') { $params.IncludeActive = $true }
                    if ($includeDeleted -ne 'n') { $params.IncludeDeleted = $true }
                    
                    $result = Export-ConditionalAccessPolicies @params
                    Write-Host "Export completed:" -ForegroundColor Green
                    Write-Host "  File: $($result.FilePath)"
                    Write-Host "  Active policies: $($result.ActivePoliciesCount)"
                    Write-Host "  Deleted policies: $($result.DeletedPoliciesCount)"
                }
                catch {
                    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
                }
            }
            
            "6" {
                Write-Host "`nAuthentication Status" -ForegroundColor Yellow
                try {
                    $context = Get-MgContext
                    if ($context) {
                        Write-Host "Connected to Microsoft Graph" -ForegroundColor Green
                        Write-Host "Account: $($context.Account)"
                        Write-Host "Tenant: $($context.TenantId)"
                        Write-Host "Scopes: $($context.Scopes -join ', ')"
                    }
                    else {
                        Write-Host "Not connected to Microsoft Graph" -ForegroundColor Red
                        Write-Host "Use Connect-MgGraph to authenticate"
                    }
                }
                catch {
                    Write-Host "Error checking authentication: $($_.Exception.Message)" -ForegroundColor Red
                }
            }
            
            "0" {
                Write-Host "Exiting..." -ForegroundColor Green
                return
            }
            
            default {
                Write-Host "Invalid option. Please select 0-6." -ForegroundColor Red
            }
        }
        
        if ($choice -ne "0") {
            Read-Host "`nPress Enter to continue"
        }
        
    } while ($choice -ne "0")
}