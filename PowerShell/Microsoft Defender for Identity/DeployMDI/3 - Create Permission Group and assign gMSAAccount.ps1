<#	
	.NOTES
	===========================================================================
	 Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2022 v5.8.213
	 Created on:   	18-01-2024 20:45
	 Created by:   	Michael Morten Sonne
	 Organization: 	Sonne´s Cloud
	 Filename:     	"3 - Create Permission Group and assign gMSAAccount.ps1"
	 Version:		1.0
	===========================================================================
	.DESCRIPTION
        This script will create a group and add the gMSA account to it. It will also grant the group read access to the deleted objects container in AD.
#>

# Make sure AD Recycle bin is enabled. This can be done from Administrative center also.

# Import the required PowerShell module for Active Directory:
Import-Module ActiveDirectory

# Check if AD Recycle Bin is enabled
Write-host "Checking if AD Recycle Bin is enabled..."

# Enable AD Recycle Bin if not already enabled
if (-not (Get-ADOptionalFeature -Filter {name -eq 'Recycle Bin Feature'} -ErrorAction SilentlyContinue)) {
    #Enable-ADOptionalFeature 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target (Get-ADDomain).DistinguishedName

    # Show a warning that AD Recycle Bin is not enabled and that it will be enabled now
    Write-Host "AD Recycle Bin is not enabled. Enabling it now..." -ForegroundColor Yellow

    # Find the correct server in Active Directory to install the feature on (DomainNamingMaster)
    Write-Host "Finding the correct server in Active Directory to install the feature on (DomainNamingMaster)..." -ForegroundColor Yellow
    $ServerDomainNamingMaster = (Get-ADDomainController -Filter { OperationMasterRoles -like 'DomainNamingMaster' } | Select-Object -ExpandProperty name)

    # Enable AD Recycle Bin via try catch
    try {
        # Enable AD Recycle Bin
        Enable-ADOptionalFeature -Identity 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target $env:USERDNSDOMAIN -Server $ServerDomainNamingMaster #-Confirm:$false

        # Show a confirmation that AD Recycle Bin has been enabled
        Write-Host "AD Recycle Bin enabled." -ForegroundColor Green
    } catch {
        # Show an error if AD Recycle Bin could not be enabled
        Write-Host "Error enabling AD Recycle Bin: $_" -ForegroundColor Red
    }
}
else {
    # Show a confirmation that AD Recycle Bin is already enabled
    Write-Host "AD Recycle Bin is already enabled." -ForegroundColor Green
}

# Declare the identity that you want to add read access to the deleted objects container:
$gMSA_AccountName = 'gMSAMDI'

# If the identity is a gMSA, first to create a group and add the gMSA to it:
$gMSA_PermissionGroupName = 'mdigmsapermissiongroup'
$gMSA_PermissionGroupDescription = 'Members of this group are allowed to read the objects in the Deleted Objects container in AD'
if(Get-ADServiceAccount -Identity $gMSA_AccountName -ErrorAction SilentlyContinue) {
    $groupParamsSettings = @{
        Name           = $gMSA_PermissionGroupName
        SamAccountName = $gMSA_PermissionGroupName
        DisplayName    = $gMSA_PermissionGroupName
        GroupCategory  = 'Security'
        GroupScope     = 'Universal'
        Description    = $gMSA_PermissionGroupDescription
    }
    $group = New-ADGroup $groupParamsSettings -PassThru
    Add-ADGroupMember -Identity $group -Members ('{0}$' -f $gMSA_AccountName)
    $gMSA_AccountName = $group.Name
}

# Get the deleted objects container's distinguished name:
$distinguishedName = ([adsi]'').distinguishedName.Value
$deletedObjectsDN = 'CN=Deleted Objects,{0}' -f $distinguishedName

# Take ownership on the deleted objects container:
$params = @("$deletedObjectsDN", '/takeOwnership')
C:\Windows\System32\dsacls.exe $params

# Grant the "List Contents" and "Read Property" permissions to the user or group:
$params = @("$deletedObjectsDN", '/G', ('{0}\{1}:LCRP' -f ([adsi]'').name.Value, $gMSA_AccountName))
C:\Windows\System32\dsacls.exe $params
  
# To revoke the permissions, uncomment the following two lines and execute them in place of the preceding two lines:
# $params = @("$deletedObjectsDN", '/R', ('{0}\{1}' -f ([adsi]'').name.Value, $gMSA_AccountName))
# C:\Windows\System32\dsacls.exe $params