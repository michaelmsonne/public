<#	
	===========================================================================
	 Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2025 v5.9.259
	 Created on:   	04-10-2025 00:00
	 Created by:   	Michael Morten Sonne
	 Organization: 	Sonne´s Cloud - blog.sonnes.cloud
	 Filename:     	ConditionalAccessManager.psd1
	 -------------------------------------------------------------------------
	 Module Manifest
	-------------------------------------------------------------------------
	 Module Name: ConditionalAccessManager
	===========================================================================
#>

@{
	
	# Script module or binary module file associated with this manifest
	RootModule = 'ConditionalAccessManager.psm1'
	
	# Version number of this module.
	ModuleVersion = '1.0.0.0'
	
	# ID used to uniquely identify this module
	GUID = 'd1e8f3c4-5b6e-4c8b-8c3e-1f2e3d4c5b6a'
	
	# Author of this module
	Author = 'Michael Morten Sonne'
	
	# Company or vendor of this module
	CompanyName = 'Sonne´s Cloud'
	
	# Copyright statement for this module
	Copyright = '(c) 2025 Michael Morten Sonne. All rights reserved.'
	
	# Description of the functionality provided by this module
	Description = 'PowerShell module for managing deleted Conditional Access policies in Microsoft Entra ID using Microsoft Graph API.'
	
	# Supported PSEditions
	# CompatiblePSEditions = @('Core', 'Desktop')
	
	# Minimum version of the Windows PowerShell engine required by this module
	PowerShellVersion = '5.1'
	
	# Name of the Windows PowerShell host required by this module
	PowerShellHostName = ''
	
	# Minimum version of the Windows PowerShell host required by this module
	PowerShellHostVersion = ''
	
	# Minimum version of the .NET Framework required by this module
	DotNetFrameworkVersion = '4.5.2'
	
	# Minimum version of the common language runtime (CLR) required by this module
	# CLRVersion = ''
	
	# Processor architecture (None, X86, Amd64, IA64) required by this module
	ProcessorArchitecture = 'None'
	
	# Modules that must be imported into the global environment prior to importing
	# this module
	RequiredModules = @(
		@{ ModuleName = 'Microsoft.Graph.Authentication'; ModuleVersion = '2.0.0' }
	)
	
	# Assemblies that must be loaded prior to importing this module
	RequiredAssemblies = @()
	
	# Script files (.ps1) that are run in the caller's environment prior to
	# importing this module
	ScriptsToProcess = @()
	
	# Type files (.ps1xml) to be loaded when importing this module
	TypesToProcess = @()
	
	# Format files (.ps1xml) to be loaded when importing this module
	FormatsToProcess = @()
	
	# Modules to import as nested modules of the module specified in
	# ModuleToProcess
	NestedModules = @()
	
	# Functions to export from this module
	FunctionsToExport = @(
		'Get-DeletedConditionalAccessPolicies',
		'Restore-ConditionalAccessPolicy',
		'Remove-DeletedConditionalAccessPolicy',
		'Export-ConditionalAccessPolicies',
		'Start-ConditionalAccessManagerConsole'
	)
	
	# Cmdlets to export from this module
	CmdletsToExport = '*' 
	
	# Variables to export from this module
	VariablesToExport = '*'
	
	# Aliases to export from this module
	AliasesToExport = '*' #For performance, list alias explicitly
	
	# DSC class resources to export from this module.
	#DSCResourcesToExport = ''
	
	# List of all modules packaged with this module
	ModuleList = @()
	
	# List of all files packaged with this module
	FileList = @()
	
	# Private data to pass to the module specified in ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
	PrivateData = @{
		
		#Support for PowerShellGet galleries.
		PSData = @{
			
			# Tags applied to this module. These help with module discovery in online galleries.
			Tags = @('Azure', 'EntraID', 'ConditionalAccess', 'Backup', 'Restore', 'Graph', 'Security')
			
			# A URL to the license for this module.
			LicenseUri = 'https://opensource.org/licenses/MIT'
			
			# A URL to the main website for this project.
			ProjectUri = 'https://github.com/michaelmsonne/Scripts'
			
			# A URL to an icon representing this module.
			# IconUri = ''
			
			# ReleaseNotes of this module
			ReleaseNotes = 'v2.0.0 - Organized folder structure with Private/Public separation, comprehensive testing, and improved Graph API integration'
			
		} # End of PSData hashtable
		
	} # End of PrivateData hashtable
}