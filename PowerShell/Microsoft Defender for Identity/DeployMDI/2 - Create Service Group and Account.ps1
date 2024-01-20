<#	
	.NOTES
	===========================================================================
	 Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2022 v5.8.213
	 Created on:   	18-01-2024 21:29
	 Created by:   	Michael Morten Sonne
	 Organization: 	Sonne´s Cloud
	 Filename:     	"2 - Create Service Group and Account.ps1"
	 Version:		1.0
	===========================================================================
	.DESCRIPTION
        This script will create a gMSA account and a group for the gMSA account to be a member of.

    .EXAMPLE
        .\"2 - Create Service Group and Account.ps1"
#>

# Please set the variables below to match your environment:
$gMSA_AccountName = 'gMSAMDI'
$gMSA_HostsGroupName = 'gMSAMDIGroup'
$gMSA_HostNames = 'ADDC01', 'ADDC02', 'ADCS', 'ADFS01', 'ADFS02'

# Alternatively, you may opt to utilize the built-in 'Domain Controllers' group if the environment consists of a single forest and exclusively features domain controller sensors (although this is not recommended)

# Import the required PowerShell module for Active Directory
Import-Module ActiveDirectory

# Create the group for the gMSA account to be a member of (if it does not already exist):
try {
    # Create the group
    New-ADGroup -Name $gMSA_HostsGroupName -GroupScope Global -PassThru -ErrorAction Stop

    # Show a confirmation that the group has been created
    Write-Host "Group '$gMSA_HostsGroupName' created." -ForegroundColor Green
} catch {
    # Show an error if the group could not be created
    Write-Host "Error creating group: $_" -ForegroundColor Red
}

# Add the members to it:
try {
    $gMSA_HostNames | ForEach-Object {
        $computer = Get-ADComputer -Identity $_ -ErrorAction Stop
        try {
            Add-ADGroupMember -Identity $gMSA_HostsGroupName -Members $computer -ErrorAction Stop
        } catch {
            Write-Host "Error adding member to group: $_" -ForegroundColor Red
        }
    }
    # Show a confirmation that the members have been added to the group
    Write-Host "Member(s) added to group '$gMSA_HostsGroupName'." -ForegroundColor Green
} catch {
    # Show an error if the members could not be added to the group
    Write-Host "Error when add member(s) to the group: $_" -ForegroundColor Red
}

# if ad kds key not exists in AD, create it
if (-not (Get-ADObject -Filter {objectclass -eq 'msDS-KeyCredentialLink'} -SearchBase (Get-ADRootDSE).configurationNamingContext -ErrorAction SilentlyContinue)) {
    # Create the KDS root key
    Add-KdsRootKey -EffectiveTime ((get-date).addhours(-10))
}
  
# Create the gMSA account for MDI:
Write-Host "Creating gMSA account '$gMSA_AccountName'..." -ForegroundColor Yellow
try {
    # Create the gMSA account
    New-ADServiceAccount -Name $gMSA_AccountName -DNSHostName "$gMSA_AccountName.$env:USERDNSDOMAIN" -Description "Microsoft Defender for Identity service account" -KerberosEncryptionType AES256 -ManagedPasswordIntervalInDays 30 -PrincipalsAllowedToRetrieveManagedPassword $gMSA_HostsGroupName -ErrorAction Stop

    # Show a confirmation that the gMSA account has been created
    Write-Host "gMSA account '$gMSA_AccountName' created." -ForegroundColor Green
} catch {
    Write-Host "Error creating gMSA service account: $_" -ForegroundColor Red
}

# Show a warning that the gMSA account password needs to be changed
Write-Host "gMSA account password needs to be changed. Changing it now..." -ForegroundColor Yellow

# Change the gMSA account password
try {
    Set-ADServiceAccount -Identity $gMSA_AccountName -Reset -Credential (Get-Credential) -ErrorAction Stop

    # Show a confirmation that the gMSA account password has been changed
    Write-Host "gMSA account password changed." -ForegroundColor Green
} catch {
    # Show an error if the gMSA account password could not be changed
    Write-Host "Error changing service account password: $_" -ForegroundColor Red
}

# Show a warning that the gMSA account needs to be validated
Write-Host "gMSA account needs to be validated. Validating it now..." -ForegroundColor Yellow

# Validate the gMSA account
try {
    Test-ADServiceAccount -Identity $gMSA_AccountName -ErrorAction Stop

    # Show a confirmation that the gMSA account has been validated
    Write-Host "gMSA account validated." -ForegroundColor Green
} catch {
    # Show an error if the gMSA account could not be validated
    Write-Host "Error validating service account: $_" -ForegroundColor Red
}

# Show a warning that the gMSA account needs to be installed on the hosts
Write-Host "gMSA account needs to be installed on the hosts. Installing it now..." -ForegroundColor Yellow

# Install the gMSA account on the hosts
try {
    Install-ADServiceAccount -Identity $gMSA_AccountName -ErrorAction Stop

    # Show a confirmation that the gMSA account has been installed on the host
    Write-Host "gMSA account installed on the host." -ForegroundColor Green
} catch {
    # Show an error if the gMSA account could not be installed on the host
    Write-Host "Error installing service account on the host: $_" -ForegroundColor Red
}

# Script completed
Write-host "Script completed."