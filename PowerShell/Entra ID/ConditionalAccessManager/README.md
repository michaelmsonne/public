# ConditionalAccessManager PowerShell Module

A PowerShell module for managing deleted Conditional Access policies in Microsoft Entra ID using Microsoft Graph API.

## Features

- **List deleted policies** - View all deleted Conditional Access policies
- **Restore policies** - Restore deleted policies back to active state
- **Permanently remove policies** - Clean up deleted policies permanently
- **Export policies** - Backup active and/or deleted policies to JSON
- **Interactive console** - Menu-driven interface for easy management

## Prerequisites

- PowerShell 5.1 or higher
- Microsoft.Graph PowerShell module
- Appropriate permissions in Microsoft Entra ID:
  - `Policy.Read.All` (to read policies)
  - `Policy.ReadWrite.ConditionalAccess` (to restore/delete policies)

## Installation

1. Clone or download the module to your PowerShell modules directory
2. Import the module:

```powershell
Import-Module .\ConditionalAccessManager
```

3. Connect to Microsoft Graph:

```powershell
Connect-MgGraph -Scopes "Policy.Read.All", "Policy.ReadWrite.ConditionalAccess"
```

## Usage

### Interactive Console

Start the interactive menu-driven console:

```powershell
Start-ConditionalAccessManagerConsole
```

### Individual Commands

```powershell
# List deleted policies
Get-DeletedConditionalAccessPolicies

# List with full details
Get-DeletedConditionalAccessPolicies -IncludeDetails

# Restore a specific policy
Restore-ConditionalAccessPolicy -PolicyId "12345678-1234-1234-1234-123456789012"

# Permanently remove a deleted policy
Remove-DeletedConditionalAccessPolicy -PolicyId "12345678-1234-1234-1234-123456789012" -Force

# Export policies to JSON
Export-ConditionalAccessPolicies -OutputPath "C:\backup\ca-policies.json" -IncludeActive -IncludeDeleted
```

### Export and Backup

```powershell
# Create comprehensive backup
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
Export-ConditionalAccessPolicies -OutputPath ".\CA-Backup-$timestamp.json" -IncludeActive -IncludeDeleted
```

## Error Handling

The module includes comprehensive error handling:

- **Authentication errors** - Clear messages when not connected to Graph
- **Permission errors** - Specific guidance on required scopes
- **API errors** - Detailed error messages from Graph API
- **Validation** - Input validation for policy IDs and file paths

## Security Considerations

- Always use least-privilege permissions
- Regularly audit restored policies
- Keep backups of policy configurations

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## License

This project is licensed under the MIT License.

## Support

For issues and questions:
- Check the documentation first
- Review existing GitHub issues
- Create a new issue with detailed information

## Version History

See CHANGELOG.MD

## License

MIT License