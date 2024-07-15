# Check if already connected to Azure
try {
    # Check if already connected to Azure
    $azureContext = Get-AzContext
    if (-not $azureContext) {
        # Login to Azure
        Connect-AzAccount
    }
}
catch {
    # Display an error message if an exception occurred
    Write-Error "An error occurred when connecting to Azure: $_"
}

try {
    # Prompt for the Azure subscription and set the context with no output
    $subscriptionNameOrId = Read-Host "Please enter your Subscription Name or ID"
    Set-AzContext -Subscription $subscriptionNameOrId | Out-Null

    # Prompt for the Azure Arc machine details
    $resourceGroupName = Read-Host "Please enter your Resource Group Name"
    $arcMachinePattern = Read-Host "Please enter your Azure Arc Machine Name or pattern"

    # Retrieve all machines in the resource group
    $allArcMachines = Get-AzResource -ResourceGroupName $resourceGroupName -ResourceType "Microsoft.HybridCompute/machines"
    # Automatically append a wildcard to the pattern for broader matching
    $arcMachinePatternWithWildcard = $arcMachinePattern + '*'
    # Filter the machines based on the modified pattern
    $arcMachines = $allArcMachines | Where-Object { $_.Name -like $arcMachinePatternWithWildcard }

    # Check if any machines were found
    if ($null -eq $arcMachines -or $arcMachines.Count -eq 0) {
        # Display an error message if no machines were found
        Write-Error "No Azure Arc machines found matching the pattern '$arcMachinePatternWithWildcard' in resource group '$resourceGroupName'. Please check the name/pattern and resource group."
    } else {
        # Loop through all Azure Arc machines and display the details
        foreach ($arcMachine in $arcMachines) {
            # Get the Azure Arc machine details
            $hostname = $arcMachine.Name
            $principalId = $arcMachine.Identity.PrincipalId

            # Display the Azure Arc machine details
            Write-Host "`nAzure Arc machine found: $hostname" -ForegroundColor Green
            Write-Host "Principal ID: $principalId" -ForegroundColor Yellow
            Write-Host "`nTo be able to connect, DNS record " -NoNewline; Write-Host "$principalId.arc.waconazure.com" -NoNewline -ForegroundColor Yellow; Write-Host " need to return IP 127.0.0.1!"
        }
    }
}
catch {
    # Display an error message if an exception occurred
    Write-Error "An error occurred: $_"
}
# Display a message indicating the script has finished
Write-Host "`nFinished." -BackgroundColor "Black" -ForegroundColor "Green"