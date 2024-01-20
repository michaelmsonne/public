<#	
	.NOTES
	===========================================================================
	 Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2022 v5.8.213
	 Created on:   	18-01-2024 21:54
	 Created by:   	Michael Morten Sonne
	 Organization: 	Sonne´s Cloud
	 Filename:     	"4 - Validate gMSA Account.ps1"
	 Version:		1.0
	===========================================================================
	.DESCRIPTION
        This script will validate the gMSA account.

	.EXAMPLE
        .\"4 - Validate gMSA Account.ps1"
#>

# Import the required PowerShell module for Active Directory:
Import-Module ActiveDirectory

# Validate the gMSA account:
Test-ADServiceAccount -Identity 'gMSAMDI'