# ConditionalAccessManager PowerShell Module
# Version 2.0.0 - Organized folder structure

# Get public and private function definition files
$Public = @(Get-ChildItem -Path $PSScriptRoot\Public\*.ps1 -ErrorAction SilentlyContinue)
$Private = @(Get-ChildItem -Path $PSScriptRoot\Private\*.ps1 -ErrorAction SilentlyContinue)

# Dot source the files
foreach ($import in @($Public + $Private)) {
    try {
        . $import.FullName
    }
    catch {
        Write-Error -Message "Failed to import function $($import.FullName): $_"
    }
}

# Check required modules on import (silent check)
try {
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
        Write-Warning "Microsoft.Graph.Authentication module is missing. Please install it with: Install-Module Microsoft.Graph.Authentication"
    }
}
catch {
    Write-Verbose "Module check skipped during import: $($_.Exception.Message)"
}

# Export public functions
Export-ModuleMember -Function Get-DeletedConditionalAccessPolicies, Restore-ConditionalAccessPolicy, Remove-DeletedConditionalAccessPolicy, Export-ConditionalAccessPolicies, Start-ConditionalAccessManagerConsole