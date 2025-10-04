# Example: Basic Usage

Import-Module .\ConditionalAccessManager.psm1

# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Policy.Read.All", "Policy.ReadWrite.ConditionalAccess"

# List deleted policies
$deletedPolicies = Get-DeletedConditionalAccessPolicies
$deletedPolicies | Format-Table

# Restore a specific policy
# Restore-ConditionalAccessPolicy -PolicyId "12345678-1234-1234-1234-123456789012"

# Export all policies
# Export-ConditionalAccessPolicies -Path ".\backup.json" -IncludeActive

# Start interactive console
# Start-ConditionalAccessManagerConsole