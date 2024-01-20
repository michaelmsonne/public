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
    New-ADGroup -Name $gMSA_HostsGroupName -GroupCategory Security -GroupScope DomainLocal -PassThru #-ErrorAction Stop

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
            # Add the member to the group
            Add-ADGroupMember -Identity $gMSA_HostsGroupName -Members $computer #-ErrorAction Stop

            # Show a confirmation that the member has been added to the group
            Write-Host "Added $computer to the group: $gMSA_HostsGroupName" -ForegroundColor Yellow

        } catch {
            # Show an error if the member could not be added to the group
            Write-Host "Error adding member to group: $_" -ForegroundColor Red
        }
    }
    # Show a confirmation that the members have been added to the group
    Write-Host "Member(s) added to group '$gMSA_HostsGroupName'." -ForegroundColor Green
} catch {
    # Show an error if the members could not be added to the group
    Write-Host "Error when add member(s) to the group: $_" -ForegroundColor Red
}

# Check if a Kds Root Key exists in your domain
Write-Host "Checking if a Kds Root key exists in your domain $env:USERDNSDOMAIN ..." -ForegroundColor Yellow
try {
    if (-not (Get-KdsRootKey).Count) {
        # Create a Kds Root Key if it does not exist
        Write-Host "Creating a Kds Root Key as non exist..." -ForegroundColor Yellow

        # Create a Kds Root Key
        Add-KdsRootKey -EffectiveTime ((get-date).addhours(-10)) | Out-Null

        # Show a confirmation that the Kds Root Key has been created
        Write-Host "Created a Kds Root Key ..." -ForegroundColor Green
    }
    else {
        # Show a warning that a Kds Root Key already exists
        Write-Host "A Kds Root Key already exists so no need to create one in your domain $env:USERDNSDOMAIN" -ForegroundColor Green
    }
}
catch {
    # Show an error if the Kds Root Key could not be created
    Write-Host "Error when creating Root Key: $_" -ForegroundColor Red
    exit
}

# Create the gMSA account for MDI:
Write-Host "Creating gMSA account '$gMSA_AccountName' if a gMSA account with the name $gMSA_AccountName not exists..." -ForegroundColor Yellow
try {
    if (!([bool](Get-ADServiceAccount -Filter { Name -eq $gMSA_AccountName }))) {
        # Create the gMSA account
        New-ADServiceAccount -Name $gMSA_AccountName -DNSHostName "$gMSA_AccountName.$env:USERDNSDOMAIN" -Description "Microsoft Defender for Identity service account" -KerberosEncryptionType AES256 -ManagedPasswordIntervalInDays 30 -PrincipalsAllowedToRetrieveManagedPassword $gMSA_HostsGroupName

        # Show a confirmation that the gMSA account has been created
        Write-Host "Created a gMSA account with the name: $gMSA_AccountName" -ForegroundColor Green
    }
    else {
        # Show a warning that a gMSA account already exists
        Write-Host "  A Group Managed Service Account with the name $gMSA_AccountName already exists" -ForegroundColor Yellow
    }

    # Show a confirmation that the gMSA account has been created
    Write-Host "gMSA account '$gMSA_AccountName' created." -ForegroundColor Green
} catch {
    Write-Host "Error creating gMSA service account: $_" -ForegroundColor Red
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