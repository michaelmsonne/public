#Requires -Version 5.1
using namespace System.Security.Cryptography.X509Certificates

<#
    .NOTES
    ===========================================================================
     Created with:  Microsoft Visual Studio 2025
     Created on:    20-04-2026 20:34
	 Updated on:    22-04-2026
     Created by:    Michael Morten Sonne
     Organization:  Sonne´s Cloud
     Blog:          https://blog.sonnes.cloud
	 Name:          RDPFileSigner
     Filename:      RDPFileSigner.ps1
     Version:       1.0.0
    ===========================================================================

    .SYNOPSIS
        Comprehensive RDP file signing tool - certificate management, signing,
        unsigning, verification, and shell context menu integration.

    .DESCRIPTION
        RDPFileSigner.ps1 addresses the April 2026 Windows security update
        (CVE-2026-26151) which causes unsigned .rdp files to display a
        "Caution: Unknown remote connection" dialog on every open, and blocks
        drive and clipboard redirections by default.

        Signing an .rdp file with a trusted code-signing certificate:
        • Replaces the red warning with a verified-publisher banner.
        • Re-enables drive and clipboard redirections as configured.
        • Provides tamper detection - any change to a signed file invalidates
            the signature.

        OPERATION MODES
        ---------------
        Default / -Setup
            Creates or reuses a self-signed certificate, installs it into
            LocalMachine\Root and LocalMachine\TrustedPublisher, optionally
            exports the public .cer and/or the .pfx, and registers "Sign RDP" /
            "UnSign RDP" right-click context menu entries on the current machine.

        -Sign  (-RdpFile | -RdpFolder)
            Signs one or more .rdp files using an existing certificate.
            Supply -CertThumbprint to target a specific cert, or -CertSubject to
            look up by subject (default: "CN=<COMPUTERNAME> RDP Signing").
            Combine with -ExportCerPath to export the public certificate at the
            same time.

        -Unsign  (-RdpFile | -RdpFolder)
            Strips the digital signature from one or more .rdp files (removes the
            signature:s: and signscope:s: lines appended by rdpsign.exe).

        -Verify  (-RdpFile | -RdpFolder)
            Checks each file for signature and signscope fields and reports its
            signed/unsigned status.

        -ShellRegister
            Registers or re-registers the "Sign RDP" / "UnSign RDP" right-click
            context menu entries (useful after moving the script to a new path).

        -ShellUnregister
            Removes the "Sign RDP" and "UnSign RDP" context menu entries.

        -TaskRegister  (-WatchFolder, -CertThumbprint | -CertSubject)
            Registers a Windows Scheduled Task named 'RDPFileSigner - Auto Sign'
            that automatically signs .rdp files in -WatchFolder (and subdirectories)
            every 5 minutes. Requires Administrator rights.

        -TaskUnregister
            Removes the 'RDPFileSigner - Auto Sign' scheduled task.
            Requires Administrator rights.

        CERTIFICATE OPTIONS
        -------------------
        Self-signed (default for -Setup)
            Creates a 4096-bit RSA / SHA-256 code-signing certificate valid for
            -CertValidityYears years (default: 3). Suitable for internal or
            testing environments.

        Enterprise CA  (-CertTemplate)
            Requests a code-signing certificate from Active Directory Certificate
            Services using the specified template name. All domain-joined machines
            will trust it automatically.

        Import from PFX  (-ImportPfxPath / -ImportPfxPassword)
            Imports a certificate and private key from a commercial CA .pfx file
            before proceeding. Suitable for public-facing environments.

        Existing certificate  (-CertThumbprint)
            Skips certificate creation and uses the certificate already present in
            Cert:\LocalMachine\My that matches the given SHA-256 thumbprint.

    .PARAMETER ListCerts
        Lists all code-signing certificates available in Cert:\LocalMachine\My and
        Cert:\CurrentUser\My. Useful for finding the thumbprint to pass to -CertThumbprint.

    .PARAMETER Setup
        Explicit flag to run full setup: create/reuse certificate, install to
        trust stores, optionally export, and register context menu entries.
        This is the default mode when no other operation switch is given.

    .PARAMETER Sign
        Sign .rdp files. Requires -RdpFile or -RdpFolder.

    .PARAMETER Unsign
        Remove digital signatures from .rdp files. Requires -RdpFile or
        -RdpFolder.

    .PARAMETER Verify
        Report the signature status of each .rdp file. Requires -RdpFile or
        -RdpFolder.

    .PARAMETER ShellRegister
        Register or re-register the shell context menu entries for .rdp files.

    .PARAMETER ShellUnregister
        Remove the "Sign RDP" and "UnSign RDP" context menu entries.

    .PARAMETER RdpFile
        Path to a single .rdp file (used with -Sign, -Unsign, or -Verify).

    .PARAMETER RdpFolder
        Path to a folder. All .rdp files inside will be processed (used with
        -Sign, -Unsign, or -Verify). Combine with -Recurse for subdirectories.

    .PARAMETER Recurse
        When -RdpFolder is specified, also process .rdp files in subdirectories.

    .PARAMETER CertSubject
        The CN= subject used when creating a new self-signed certificate or when
        looking up an existing certificate by subject in Cert:\LocalMachine\My.
        Default: "CN=<COMPUTERNAME> RDP Signing".

    .PARAMETER CertValidityYears
        How many years the self-signed certificate should be valid (1-10).
        Default: 3. Only used during -Setup when creating a new self-signed cert.

    .PARAMETER CertTemplate
        Active Directory CS template name to request an Enterprise CA certificate
        instead of creating a self-signed certificate. Only used during -Setup.

    .PARAMETER CertThumbprint
        SHA-256 thumbprint of an existing certificate in Cert:\LocalMachine\My
        to use for signing. Removes the need for certificate creation/lookup.

    .PARAMETER ImportPfxPath
        Path to a .pfx file to import into Cert:\LocalMachine\My before signing.
        Only used during -Setup.

    .PARAMETER ImportPfxPassword
        SecureString password for the .pfx file specified by -ImportPfxPath.
        If omitted you will be prompted interactively.

    .PARAMETER ExportCerPath
        Path to export the public certificate (.cer, DER encoded) for distribution
        to client machines. Available in -Setup and -Sign modes.

    .PARAMETER ExportPfxPath
        Path to export the certificate with private key (.pfx) for use on other
        signing machines. Only used during -Setup. Requires -ExportPfxPassword or
        an interactive prompt.

    .PARAMETER ExportPfxPassword
        SecureString password used when exporting the .pfx. If not supplied and
        -ExportPfxPath is specified, you will be prompted interactively.

    .PARAMETER LogPath
        Override the default log file location. Default: RDPFileSigner.log in the
        same folder as this script.

    .PARAMETER SkipShellRegistration
        When running in -Setup mode, skip registering the context menu entries.

    .PARAMETER Version
        Prints the script version and exits. No elevation required.

    .PARAMETER NoLog
        Suppresses transcript logging. Useful for automated or scheduled task
        invocations where logging is handled externally.

    .PARAMETER ExportCsvPath
        When used with -Verify, exports the verification results (file path, status,
        signer thumbprint, checked timestamp) to a CSV file at the specified path.

    .PARAMETER TaskRegister
        Registers a Windows Scheduled Task named 'RDPFileSigner - Auto Sign' that
        periodically signs all .rdp files in -WatchFolder (and subdirectories) every
        5 minutes. Requires -WatchFolder and a certificate identifier
        (-CertThumbprint or -CertSubject). Requires Administrator rights.

    .PARAMETER TaskUnregister
        Removes the 'RDPFileSigner - Auto Sign' scheduled task.
        Requires Administrator rights.

    .PARAMETER WatchFolder
        The folder to monitor for .rdp files when using -TaskRegister. All .rdp files
        in the folder and subdirectories will be signed on each task run.

    .EXAMPLE
        .\RDPFileSigner.ps1 -ListCerts

        List all available code-signing certificates and their thumbprints.

    .EXAMPLE
        .\RDPFileSigner.ps1: creates a self-signed certificate, installs it into the trust
        stores, and registers the "Sign RDP" / "UnSign RDP" right-click context
        menu entries. Run once on the signing machine.

    .EXAMPLE
        .\RDPFileSigner.ps1 -Sign -RdpFile "C:\RDP\MyServer.rdp"

        Sign a single RDP file using the previously set-up certificate.

    .EXAMPLE
        .\RDPFileSigner.ps1 -Sign -RdpFolder "C:\RDP" -Recurse

        Sign all .rdp files in C:\RDP and all subdirectories.

    .EXAMPLE
        .\RDPFileSigner.ps1 -Sign -RdpFolder "C:\RDP" -ExportCerPath "C:\RDP\rdp-signing.cer"

        Sign all .rdp files and export the public certificate for distribution.

    .EXAMPLE
        .\RDPFileSigner.ps1 -Sign -RdpFile "C:\RDP\MyServer.rdp" -CertThumbprint "A1B2C3..."

        Sign using a specific existing certificate identified by its thumbprint.

    .EXAMPLE
        .\RDPFileSigner.ps1 -Setup -CertTemplate "CodeSigning"

        Full setup using a certificate requested from an Enterprise CA.

    .EXAMPLE
        .\RDPFileSigner.ps1 -Setup -ImportPfxPath "C:\Certs\commercial.pfx" -ExportCerPath "C:\Certs\public.cer"

        Full setup importing a commercial CA certificate from a PFX file, and
        exporting the public certificate for distribution to clients.

    .EXAMPLE
        .\RDPFileSigner.ps1 -Setup -ExportPfxPath "C:\Certs\rdp-signing.pfx"

        Full setup with export of the certificate and private key as a PFX so it
        can be used on additional signing machines.

    .EXAMPLE
        .\RDPFileSigner.ps1 -Unsign -RdpFolder "C:\RDP"

        Remove signatures from all .rdp files in a folder.

    .EXAMPLE
        .\RDPFileSigner.ps1 -Verify -RdpFolder "C:\RDP" -Recurse

        Check the signature status of every .rdp file under C:\RDP.

    .EXAMPLE
        .\RDPFileSigner.ps1 -ShellRegister

        Re-register the right-click context menu entries (e.g., after moving the
        script to a new path).

    .EXAMPLE
        .\RDPFileSigner.ps1 -ShellUnregister

        Remove the "Sign RDP" and "UnSign RDP" context menu entries.

    .EXAMPLE
        .\RDPFileSigner.ps1 -Version

        Print the script version and exit.

    .EXAMPLE
        .\RDPFileSigner.ps1 -Verify -RdpFolder "C:\RDP" -ExportCsvPath "C:\Reports\rdp-status.csv"

        Verify all .rdp files and export the signed/unsigned/invalid results to a CSV report.

    .EXAMPLE
        .\RDPFileSigner.ps1 -TaskRegister -WatchFolder "C:\RDP" -CertThumbprint "D6A630B8..."

        Register a scheduled task that auto-signs .rdp files dropped into C:\RDP every 5 minutes.

    .EXAMPLE
        .\RDPFileSigner.ps1 -TaskUnregister

        Remove the 'RDPFileSigner - Auto Sign' auto-sign scheduled task.

    .NOTES
        Requires Administrator rights for certificate store and registry
        operations. Plain sign/unsign/verify of .rdp files does not require
        elevation and the script will only self-elevate when necessary.

        After running -Setup, distribute the exported .cer to client machines and
        import it into:
            Cert:\LocalMachine\Root
            Cert:\LocalMachine\TrustedPublisher

        For enterprise-wide deployment, use Group Policy to distribute the
        certificate (Computer Configuration > Windows Settings > Security
        Settings > Public Key Policies > Trusted Publishers) and add the
        thumbprint to the RDP trusted publishers policy:
            Computer Configuration > Administrative Templates > Windows
            Components > Remote Desktop Services > Remote Desktop Connection
            Client > "Specify SHA1 thumbprints of certificates representing
            trusted .rdp publishers"

        rdpsign.exe appends two fields to signed files:
            signscope:s:  - the set of fields covered by the signature
            signature:s:  - the Base64-encoded PKCS#7 signature blob
        Any modification to a signed file invalidates the signature.

        Relevant CVE: CVE-2026-26151 - Remote Desktop spoofing vulnerability.
        Microsoft's April 2026 updates (KB5083769 for Windows 11 /
        KB5082200 for Windows 10) enforce mandatory signing of .rdp files.

    .CHANGELOG
        2026-04-20: Initial version.
        2026-04-22: Added -Version, -NoLog, -ExportCsvPath (Verify CSV report),
                    -TaskRegister/-TaskUnregister (auto-sign scheduled task),
                    PKCS#7 signature decode + signer cert validity check in -Verify mode.
#>

[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Setup')]
param (
    # Operation mode
    [Parameter(ParameterSetName = 'Setup')]
    [switch] $Setup,

    [Parameter(ParameterSetName = 'ListCerts', Mandatory)]
    [switch] $ListCerts,

    [Parameter(ParameterSetName = 'Sign', Mandatory)]
    [switch] $Sign,

    [Parameter(ParameterSetName = 'Unsign', Mandatory)]
    [switch] $Unsign,

    [Parameter(ParameterSetName = 'Verify', Mandatory)]
    [switch] $Verify,

    [Parameter(ParameterSetName = 'ShellRegister', Mandatory)]
    [switch] $ShellRegister,

    [Parameter(ParameterSetName = 'ShellUnregister', Mandatory)]
    [switch] $ShellUnregister,

    # File targets
    [Parameter(ParameterSetName = 'Sign')]
    [Parameter(ParameterSetName = 'Unsign')]
    [Parameter(ParameterSetName = 'Verify')]
    [string] $RdpFile = '',

    [Parameter(ParameterSetName = 'Sign')]
    [Parameter(ParameterSetName = 'Unsign')]
    [Parameter(ParameterSetName = 'Verify')]
    [string] $RdpFolder = '',

    [Parameter(ParameterSetName = 'Sign')]
    [Parameter(ParameterSetName = 'Unsign')]
    [Parameter(ParameterSetName = 'Verify')]
    [switch] $Recurse,

    # Certificate options
    [Parameter(ParameterSetName = 'Setup')]
    [Parameter(ParameterSetName = 'Sign')]
    [Parameter(ParameterSetName = 'ShellRegister')]
    [Parameter(ParameterSetName = 'TaskRegister')]
    [string] $CertSubject = "CN=$env:COMPUTERNAME RDP Signing",

    [Parameter(ParameterSetName = 'Setup')]
    [ValidateRange(1, 10)]
    [int] $CertValidityYears = 3,

    [Parameter(ParameterSetName = 'Setup')]
    [string] $CertTemplate = '',

    [Parameter(ParameterSetName = 'Setup')]
    [Parameter(ParameterSetName = 'Sign')]
    [Parameter(ParameterSetName = 'TaskRegister')]
    [string] $CertThumbprint = '',

    [Parameter(ParameterSetName = 'Setup')]
    [string] $ImportPfxPath = '',

    [Parameter(ParameterSetName = 'Setup')]
    [System.Security.SecureString] $ImportPfxPassword,

    # Export options
    [Parameter(ParameterSetName = 'Setup')]
    [Parameter(ParameterSetName = 'Sign')]
    [string] $ExportCerPath = '',

    [Parameter(ParameterSetName = 'Setup')]
    [string] $ExportPfxPath = '',

    [Parameter(ParameterSetName = 'Setup')]
    [System.Security.SecureString] $ExportPfxPassword,

    [Parameter(ParameterSetName = 'Verify')]
    [string] $ExportCsvPath = '',

    # Misc
    [string] $LogPath = '',

    [Parameter(ParameterSetName = 'Setup')]
    [switch] $SkipShellRegistration,

    [Parameter(ParameterSetName = 'Version', Mandatory)]
    [switch] $Version,

    [Parameter(ParameterSetName = 'TaskRegister', Mandatory)]
    [switch] $TaskRegister,

    [Parameter(ParameterSetName = 'TaskUnregister', Mandatory)]
    [switch] $TaskUnregister,

    [Parameter(ParameterSetName = 'TaskRegister', Mandatory)]
    [string] $WatchFolder = '',

    [switch] $NoLog
)

$script:ScriptVersion = '1.0.0'

# Mapping from rdpsign.exe signscope display names to .rdp field prefixes.
$script:RdpFieldNameToPrefix = @{
    'Full Address'                       = 'full address:s:'
    'Alternate Full Address'             = 'alternate full address:s:'
    'PCB'                                = 'pcb:s:'
    'Use Redirection Server Name'        = 'use redirection server name:i:'
    'Server Port'                        = 'server port:i:'
    'Negotiate Security Layer'           = 'negotiate security layer:i:'
    'EnableCredSspSupport'               = 'enablecredsspsupport:i:'
    'DisableConnectionSharing'           = 'disableconnectionsharing:i:'
    'AutoReconnection Enabled'           = 'autoreconnection enabled:i:'
    'GatewayHostname'                    = 'gatewayhostname:s:'
    'GatewayUsageMethod'                 = 'gatewayusagemethod:i:'
    'GatewayProfileUsageMethod'          = 'gatewayprofileusagemethod:i:'
    'GatewayCredentialsSource'           = 'gatewaycredentialssource:i:'
    'Support URL'                        = 'support url:s:'
    'PromptCredentialOnce'               = 'promptcredentialonce:i:'
    'Require pre-authentication'         = 'require pre-authentication:i:'
    'Pre-authentication server address'  = 'pre-authentication server address:s:'
    'Alternate Shell'                    = 'alternate shell:s:'
    'Shell Working Directory'            = 'shell working directory:s:'
    'RemoteApplicationProgram'           = 'remoteapplicationprogram:s:'
    'RemoteApplicationExpandWorkingdir'  = 'remoteapplicationexpandworkingdir:s:'
    'RemoteApplicationMode'              = 'remoteapplicationmode:i:'
    'RemoteApplicationGuid'              = 'remoteapplicationguid:s:'
    'RemoteApplicationName'              = 'remoteapplicationname:s:'
    'RemoteApplicationIcon'              = 'remoteapplicationicon:s:'
    'RemoteApplicationFile'              = 'remoteapplicationfile:s:'
    'RemoteApplicationFileExtensions'    = 'remoteapplicationfileextensions:s:'
    'RemoteApplicationCmdLine'           = 'remoteapplicationcmdline:s:'
    'RemoteApplicationExpandCmdLine'     = 'remoteapplicationexpandcmdline:s:'
    'Prompt For Credentials'             = 'prompt for credentials:i:'
    'Authentication Level'               = 'authentication level:i:'
    'AudioMode'                          = 'audiomode:i:'
    'RedirectDrives'                     = 'redirectdrives:i:'
    'RedirectPrinters'                   = 'redirectprinters:i:'
    'RedirectCOMPorts'                   = 'redirectcomports:i:'
    'RedirectSmartCards'                 = 'redirectsmartcards:i:'
    'RedirectPOSDevices'                 = 'redirectposdevices:i:'
    'RedirectClipboard'                  = 'redirectclipboard:i:'
    'DevicesToRedirect'                  = 'devicestoredirect:s:'
    'DrivesToRedirect'                   = 'drivestoredirect:s:'
    'LoadBalanceInfo'                    = 'loadbalanceinfo:s:'
    'RedirectDirectX'                    = 'redirectdirectx:i:'
    'RDGIsKDCProxy'                      = 'rdgiskdcproxy:i:'
    'KDCProxyName'                       = 'kdcproxyname:s:'
    'EventLogUploadAddress'              = 'eventloguploadaddress:s:'
    'EnableRdsAadAuth'                   = 'enablerdsaadauth:i:'
    'RedirectWebAuthn'                   = 'redirectwebauthn:i:'
}

#region RDP signature format notes
#
# *** DISCLAIMER ***************************************************************
# The following is based on reverse-engineering of rdpsign.exe behaviour and
# the open-source Python reimplementation at https://github.com/nfedera/rdpsign
# It is NOT based on official Microsoft documentation. The format may change in
# future Windows versions. Validate this against your own environment before
# relying on it in production.
# ******************************************************************************
#
# OVERVIEW
# --------
# rdpsign.exe signs an .rdp file by appending two lines to it:
#
#   signscope:s:<comma-separated display names>
#   signature:s:<base64-encoded blob>
#
# The "display names" in signscope are NOT the raw .rdp field names. They are
# human-readable labels (e.g. "Full Address", "RedirectDrives") that rdpsign.exe
# maps internally to the actual field prefixes used in the file. The hashtable
# $script:RdpFieldNameToPrefix above contains the known mappings derived from
# the open-source reference.
#
# SIGNED CONTENT (msgblob)
# ------------------------
# The data that is actually signed is constructed as follows (UTF-16 LE):
#
#   <field-line-1>\r\n
#   <field-line-2>\r\n
#   ...
#   <field-line-N>\r\n
#   signscope:s:<scope-value-verbatim>\r\n
#   \x00                               <- single NUL character terminator
#
# Where each <field-line-X> is the raw line from the .rdp file (trimmed of
# leading/trailing whitespace) for the field named by the corresponding
# signscope entry, looked up via $script:RdpFieldNameToPrefix.
# The signscope value is included verbatim (the exact string after
# "signscope:s:") - the display names must NOT be re-joined from the split
# array because rdpsign.exe may include or omit spaces around the commas.
#
# SIGNATURE BLOB FORMAT
# ----------------------
# The base64-decoded signature:s: value is NOT a raw PKCS#7 DER file.
# rdpsign.exe prepends a 12-byte proprietary header:
#
#   Bytes 0-3  : 01 00 01 00  (magic / version marker)
#   Bytes 4-7  : 01 00 00 00  (flags / reserved)
#   Bytes 8-11 : <uint32 LE>  (length of the DER data that follows)
#
# The actual PKCS#7 CMS SignedData DER starts immediately after the header.
# In practice the DER can be located by scanning for the first 0x30 0x82
# byte pair (ASN.1 SEQUENCE with a two-byte length), which is always the
# outermost DER tag for a CMS SignedData structure.
#
# VERIFICATION
# ------------
# The signature is a *detached* CMS SignedData (the signed content is not
# embedded in the PKCS#7 structure itself). To verify:
#
#   1. Reconstruct msgblob (see above) and encode it as UTF-16 LE.
#   2. Strip the 12-byte proprietary header from the blob to get raw DER.
#   3. Peek at the OID in the CMS ContentInfo so we can pass a matching
#      ContentInfo to the SignedCms constructor (avoids OID mismatch errors).
#   4. Construct SignedCms(ContentInfo(oid, msgblob), $true) - the $true
#      flag tells .NET this is a detached signature.
#   5. Call Decode(derBytes) then CheckSignature($true).
#      CheckSignature($true) verifies the cryptographic math only and does
#      NOT require the signing certificate to chain to a trusted root.
#
#endregion

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Ensure the PKCS#7 / CMS types are available (not auto-loaded on all machines).
Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue

#region Self-elevation

$_isAdminSession = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

# Sign, Unsign, and Verify only need write access to the .rdp files themselves;
# Setup, ShellRegister, and ShellUnregister touch cert stores and the registry.
$_sessionNeedsElevation = $PSCmdlet.ParameterSetName -notin @('Sign', 'Unsign', 'Verify', 'ListCerts', 'Version')

if (-not $_isAdminSession -and $_sessionNeedsElevation) {
    Write-Host 'Requesting administrator elevation...' -ForegroundColor Yellow

    $self = if ($PSCommandPath) { $PSCommandPath } else {
        [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    }

    $argParts = @()
    foreach ($key in $PSBoundParameters.Keys) {
        $val = $PSBoundParameters[$key]
        switch ($val.GetType().Name) {
            'SwitchParameter' { if ($val) { $argParts += "-$key" } }
            'SecureString'    { <# Cannot safely pass SecureStrings via CLI #> }
            default           { $argParts += "-$key `"$val`"" }
        }
    }

    Start-Process -FilePath 'powershell.exe' `
        -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$self`" $($argParts -join ' ')" `
        -Verb RunAs -Wait
    exit
}

#endregion

#region Logging

$_scriptDir = if ($PSCommandPath) {
    Split-Path $PSCommandPath -Parent
} else {
    Split-Path ([System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName) -Parent
}

if (-not $LogPath) {
    $LogPath = Join-Path $_scriptDir 'RDPFileSigner.log'
}

if (-not $NoLog) {
    Start-Transcript -Path $LogPath -Append -Force | Out-Null
    Write-Host "Log  : $LogPath"
}
Write-Host "Start: $(Get-Date -Format 'dd-MM-yyyy HH:mm:ss')"
Write-Host "Mode : $($PSCmdlet.ParameterSetName)"
Write-Host ''

#endregion

#region Helper functions

function Write-Step  ([string]$Msg) { Write-Host "`n==> $Msg" -ForegroundColor Cyan }
function Write-Ok    ([string]$Msg) { Write-Host "    [OK]  $Msg" -ForegroundColor Green }
function Write-Warn  ([string]$Msg) { Write-Host "    [!!]  $Msg" -ForegroundColor Yellow }
function Write-Fail  ([string]$Msg) { Write-Host "    [XX]  $Msg" -ForegroundColor Red }
function Write-Info  ([string]$Msg) { Write-Host "          $Msg" -ForegroundColor DarkGray }
function Write-Divider { Write-Host ('=' * 80) -ForegroundColor DarkGray }

# Displays certificate details with colorized output (mirrors Show-CertificateInformation style).
function Show-CertInfo ([X509Certificate2] $Cert, [string] $Label = 'Certificate') {
    $sep = '=' * 80
    Write-Host $sep -ForegroundColor Green
    Write-Host "  $Label" -ForegroundColor Green
    Write-Host $sep -ForegroundColor Green
    Write-Host '  Subject    : ' -NoNewline; Write-Host $Cert.Subject    -ForegroundColor Yellow
    Write-Host '  Issuer     : ' -NoNewline; Write-Host $Cert.Issuer     -ForegroundColor Yellow
    Write-Host '  Thumbprint : ' -NoNewline; Write-Host $Cert.Thumbprint -ForegroundColor Yellow
    Write-Host '  Expires    : ' -NoNewline; Write-Host $Cert.NotAfter.ToString('yyyy-MM-dd') -ForegroundColor Yellow
    Write-Host $sep -ForegroundColor Green
    Write-Host ''
}

# Displays a warning banner if the certificate expires within the threshold (default 30 days).
function Test-CertExpiringSoon ([X509Certificate2] $Cert, [int] $ThresholdDays = 30) {
    $daysLeft = ($Cert.NotAfter - (Get-Date)).Days
    if ($daysLeft -le 0) {
        $sep = '=' * 80
        Write-Host $sep -ForegroundColor Red
        Write-Host '  [!!] CERTIFICATE EXPIRED' -ForegroundColor Red
        Write-Host "  The signing certificate expired $([Math]::Abs($daysLeft)) day(s) ago ($($Cert.NotAfter.ToString('yyyy-MM-dd')))." -ForegroundColor Red
        Write-Host "  Thumbprint : $($Cert.Thumbprint)" -ForegroundColor Red
        Write-Host $sep -ForegroundColor Red
        Write-Host ''
    } elseif ($daysLeft -le $ThresholdDays) {
        $sep = '=' * 80
        Write-Host $sep -ForegroundColor Yellow
        Write-Host '  [!!] CERTIFICATE EXPIRING SOON' -ForegroundColor Yellow
        Write-Host "  The signing certificate expires in $daysLeft day(s) on $($Cert.NotAfter.ToString('yyyy-MM-dd'))." -ForegroundColor Yellow
        Write-Host "  Thumbprint : $($Cert.Thumbprint)" -ForegroundColor Yellow
        Write-Host '  Consider renewing before it expires.' -ForegroundColor Yellow
        Write-Host $sep -ForegroundColor Yellow
        Write-Host ''
    }
}

# Returns the ProgID for .rdp files (typically "RDP.File" or ".rdp").
function Get-RdpProgId {
    $id = (Get-ItemProperty -Path 'Registry::HKEY_CLASSES_ROOT\.rdp' `
               -ErrorAction SilentlyContinue).'(default)'
    if (-not $id) { $id = '.rdp' }
    return $id
}

# Returns the registry key path for a verb under the .rdp shell association.
function Get-RdpVerbKeyPath ([string]$VerbName) {
    return "Registry::HKEY_CLASSES_ROOT\$(Get-RdpProgId)\shell\$VerbName"
}

# Returns localized context menu labels based on the current Windows UI culture.
function Get-LocalizedLabels {
    $lang = (Get-UICulture).TwoLetterISOLanguageName.ToLower()
    switch ($lang) {
        'da'    { return @{ Sign = 'Add sinering til RDP';    Unsign = 'Fjern RDP-signatur'      } }  # Danish
        'de'    { return @{ Sign = 'RDP signieren';           Unsign = 'RDP-Signatur entfernen'  } }  # German
        'fr'    { return @{ Sign = 'Signer RDP';              Unsign = 'Retirer signature RDP'   } }  # French
        'es'    { return @{ Sign = 'Firmar RDP';              Unsign = 'Quitar firma RDP'        } }  # Spanish
        'nl'    { return @{ Sign = 'RDP ondertekenen';        Unsign = 'RDP-handtekening verwijderen' } }  # Dutch
        'sv'    { return @{ Sign = 'Signera RDP';             Unsign = 'Ta bort RDP-signatur'    } }  # Swedish
        'nb'    { return @{ Sign = 'Signer RDP';              Unsign = 'Fjern RDP-signatur'      } }  # Norwegian Bokmål
        'nn'    { return @{ Sign = 'Signer RDP';              Unsign = 'Fjern RDP-signatur'      } }  # Norwegian Nynorsk
        'fi'    { return @{ Sign = 'Allekirjoita RDP';        Unsign = 'Poista RDP-allekirjoitus'} }  # Finnish
        'it'    { return @{ Sign = 'Firma RDP';               Unsign = 'Rimuovi firma RDP'       } }  # Italian
        'pt'    { return @{ Sign = 'Assinar RDP';             Unsign = 'Remover assinatura RDP'  } }  # Portuguese
        default { return @{ Sign = 'Sign RDP';                Unsign = 'UnSign RDP'              } }  # Default (English)
    }
}

# Locates rdpsign.exe, handling the WOW64 redirector when running as a 32-bit process.
function Get-RdpSignPath {
    $sysnative = Join-Path $env:SystemRoot 'Sysnative\rdpsign.exe'
    $system32  = Join-Path $env:SystemRoot 'System32\rdpsign.exe'
    if (Test-Path $sysnative) { return $sysnative }
    if (Test-Path $system32)  { return $system32  }
    throw 'rdpsign.exe not found. Confirm the Remote Desktop client is installed (Windows 10/11 or Server 2016+).'
}

# Collects .rdp file paths from -RdpFile and/or -RdpFolder.
function Get-RdpFileList {
    param(
        [string] $File   = '',
        [string] $Folder = '',
        [switch] $Recurse
    )
    $list = [System.Collections.Generic.List[string]]::new()

    if ($File) {
        if (Test-Path $File -PathType Leaf) {
            $list.Add((Resolve-Path $File).Path)
        } else {
            Write-Warn "File not found, skipping: $File"
        }
    }

    if ($Folder) {
        if (Test-Path $Folder -PathType Container) {
            $gciArgs = @{ Path = $Folder; Filter = '*.rdp'; File = $true }
            if ($Recurse) { $gciArgs['Recurse'] = $true }
            Get-ChildItem @gciArgs | ForEach-Object { $list.Add($_.FullName) }
        } else {
            Write-Warn "Folder not found, skipping: $Folder"
        }
    }

    return $list
}

# Verifies that a certificate carries the Code Signing EKU (OID 1.3.6.1.5.5.7.3.3).
function Test-CodeSigningEku ([X509Certificate2] $Cert) {
    return @($Cert.EnhancedKeyUsageList |
        Where-Object { $_.ObjectId -eq '1.3.6.1.5.5.7.3.3' }).Count -gt 0
}

# Installs the public portion of a certificate into a LocalMachine store.
function Install-CertToStore ([X509Certificate2] $Cert, [string] $StoreName) {
    $store = [X509Store]::new(
        $StoreName,
        [StoreLocation]::LocalMachine)
    $store.Open([OpenFlags]::ReadWrite)
    try {
        $already = $store.Certificates |
            Where-Object { $_.Thumbprint -eq $Cert.Thumbprint }
        if ($already) {
            Write-Warn "Already present in LocalMachine\$StoreName - skipping."
        } else {
            $publicOnly = [X509Certificate2]::new($Cert.RawData)
            $store.Add($publicOnly)
            Write-Ok "Installed into LocalMachine\$StoreName."
        }
    } finally {
        $store.Close()
    }
}

# Grants BUILTIN\Users read access to the certificate's private key file so
# that non-admin processes (e.g., context menu invocations) can sign .rdp files
# without requiring a UAC prompt.
function Grant-PrivateKeyReadToUsers ([X509Certificate2] $Cert) {
    try {
        $rsa     = [RSACertificateExtensions]::GetRSAPrivateKey($Cert)
        $keyName = $rsa.Key.UniqueName

        # CNG keys (modern API) are stored in Crypto\Keys;
        # legacy CAPI keys are in Crypto\RSA\MachineKeys.
        $cngPath  = Join-Path "$env:ProgramData\Microsoft\Crypto\Keys"            $keyName
        $capiPath = Join-Path "$env:ProgramData\Microsoft\Crypto\RSA\MachineKeys" $keyName
        $keyPath  = if   (Test-Path $cngPath)  { $cngPath  } `
                    elseif (Test-Path $capiPath) { $capiPath } `
                    else { $null }

        if (-not $keyPath) {
            Write-Warn "Private key file '$keyName' not found in Crypto\Keys or Crypto\RSA\MachineKeys - skipping ACL grant."
            return
        }

        $acl  = Get-Acl $keyPath
        $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
            'BUILTIN\Users', 'Read',
            [System.Security.AccessControl.AccessControlType]::Allow)
        $acl.AddAccessRule($rule)
        Set-Acl -Path $keyPath -AclObject $acl
        Write-Ok 'Granted BUILTIN\Users read access to the private key (enables non-admin signing via context menu).'
    } catch {
        Write-Warn "Could not set private key ACL: $_"
    }
}

# Registers the "Sign RDP" / "UnSign RDP" shell context menu entries.
function Register-ShellContextMenu {
    [CmdletBinding(SupportsShouldProcess)]
    param ([string] $ScriptPath)

    $labels  = Get-LocalizedLabels
    $entries = @(
        @{ Verb = 'RDPFileSignerSign';   Label = $labels.Sign;   Args = '-Sign -RdpFile'   }
        @{ Verb = 'RDPFileSignerUnsign'; Label = $labels.Unsign; Args = '-Unsign -RdpFile' }
    )

    foreach ($entry in $entries) {
        $shellKey   = Get-RdpVerbKeyPath $entry.Verb
        $commandKey = "$shellKey\command"
        $cmdValue   = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`" $($entry.Args) `"%1`""

        if ($PSCmdlet.ShouldProcess($shellKey, "Register '$($entry.Label)' context menu entry")) {
            New-Item -Path $shellKey   -Force | Out-Null
            New-Item -Path $commandKey -Force | Out-Null
            Set-ItemProperty -Path $shellKey   -Name '(default)' -Value $entry.Label
            Set-ItemProperty -Path $shellKey   -Name 'Icon'      -Value 'mstsc.exe,0'
            Set-ItemProperty -Path $commandKey -Name '(default)' -Value $cmdValue
            Write-Ok "Registered: $($entry.Label)"
        }
    }
}

# Prints Group Policy guidance for deploying the certificate and thumbprint.
function Write-GroupPolicyHints ([string] $Thumbprint, [string] $CerPath) {
    Write-Host ''
    Write-Host '  Group Policy - enterprise-wide deployment' -ForegroundColor Cyan
    Write-Host '  ' + ('-' * 57) -ForegroundColor DarkGray
    Write-Host "  Certificate thumbprint : $Thumbprint" -ForegroundColor White
    Write-Host ''
    Write-Host '  1. Distribute this certificate to all domain machines via GPO:' -ForegroundColor DarkGray
    Write-Host '       gpmc.msc > (your GPO) > Computer Configuration > Windows Settings >' -ForegroundColor DarkGray
    Write-Host '       Security Settings > Public Key Policies > Trusted Publishers' -ForegroundColor DarkGray
    if ($CerPath) {
        Write-Host "       Import: $CerPath" -ForegroundColor DarkGray
    }
    Write-Host '       Repeat for Trusted Root Certification Authorities (self-signed certs).' -ForegroundColor DarkGray
    Write-Host ''
    Write-Host '  2. Add the thumbprint to the RDP trusted publishers policy:' -ForegroundColor DarkGray
    Write-Host '       Computer Configuration > Administrative Templates >' -ForegroundColor DarkGray
    Write-Host '       Windows Components > Remote Desktop Services >' -ForegroundColor DarkGray
    Write-Host '       Remote Desktop Connection Client >' -ForegroundColor DarkGray
    Write-Host '       "Specify SHA1 thumbprints of certificates representing trusted .rdp publishers"' -ForegroundColor DarkGray
    Write-Host ''
}

#endregion

#region Main

try {

    # ListCerts
    if ($PSCmdlet.ParameterSetName -eq 'ListCerts') {
        Write-Step 'Available code-signing certificates'

        $stores = @(
            @{ Path = 'Cert:\LocalMachine\My'; Label = 'LocalMachine\My' }
            @{ Path = 'Cert:\CurrentUser\My';  Label = 'CurrentUser\My'  }
        )

        $found = 0
        foreach ($store in $stores) {
            $certs = @(Get-ChildItem $store.Path -ErrorAction SilentlyContinue |
                Where-Object { Test-CodeSigningEku $_ })

            Write-Host "`n  Store: $($store.Label)" -ForegroundColor Cyan
            Write-Host ('  ' + '-' * 76) -ForegroundColor DarkGray

            if ($certs.Count -eq 0) {
                Write-Host '  (no code-signing certificates found)' -ForegroundColor DarkGray
            } else {
                foreach ($c in $certs) {
                    $daysLeft = ($c.NotAfter - (Get-Date)).Days
                    $expColor = if ($daysLeft -le 0) { 'Red' } elseif ($daysLeft -le 30) { 'Yellow' } else { 'Green' }
                    Write-Host '  Subject    : ' -NoNewline; Write-Host $c.Subject    -ForegroundColor Yellow
                    Write-Host '  Issuer     : ' -NoNewline; Write-Host $c.Issuer     -ForegroundColor Yellow
                    Write-Host '  Thumbprint : ' -NoNewline; Write-Host $c.Thumbprint -ForegroundColor Cyan
                    Write-Host '  Expires    : ' -NoNewline
                    Write-Host "$($c.NotAfter.ToString('yyyy-MM-dd')) ($daysLeft days)" -ForegroundColor $expColor
                    Write-Host ''
                    $found++
                }
            }
        }

        Write-Divider
        if ($found -gt 0) {
            Write-Host " Found $found code-signing certificate(s)." -ForegroundColor White
            Write-Host ' Use the Thumbprint above with: .\RDPFileSigner.ps1 -Sign -RdpFile <path> -CertThumbprint <thumbprint>' -ForegroundColor Cyan
        } else {
            Write-Host ' No code-signing certificates found. Run without parameters to create one.' -ForegroundColor Yellow
        }
        Write-Divider
        return
    }

    # Version
    if ($PSCmdlet.ParameterSetName -eq 'Version') {
        Write-Host "RDPFileSigner v$script:ScriptVersion" -ForegroundColor Cyan
        return
    }

    # TaskUnregister
    if ($PSCmdlet.ParameterSetName -eq 'TaskUnregister') {
        Write-Step 'Removing auto-sign scheduled task'

        $taskName = 'RDPFileSigner - Auto Sign'
        if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
            if ($PSCmdlet.ShouldProcess($taskName, 'Unregister scheduled task')) {
                Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
                Write-Ok "Task '$taskName' removed."
            }
        } else {
            Write-Warn "Task '$taskName' not found - nothing to remove."
        }

        Write-Divider
        Write-Host ' Done.' -ForegroundColor White
        Write-Divider
        return
    }

    # TaskRegister
    if ($PSCmdlet.ParameterSetName -eq 'TaskRegister') {
        Write-Step 'Registering auto-sign scheduled task'

        $scriptPath = if ($PSCommandPath) { $PSCommandPath } else {
            [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
        }
        if (-not $scriptPath) {
            throw 'Cannot determine the script path for task registration.'
        }

        if (-not (Test-Path $WatchFolder -PathType Container)) {
            throw "Watch folder not found: $WatchFolder"
        }

        # Security warning: the watch folder must be access-controlled, because the
        # scheduled task runs as SYSTEM and will sign ANY .rdp file placed there.
        # An attacker with write access could place a malicious .rdp file and have it
        # signed automatically, making it appear trusted to end users.
        $sep = '!' * 80
        Write-Host ''
        Write-Host $sep -ForegroundColor Red
        Write-Host '  [!!] SECURITY WARNING' -ForegroundColor Red
        Write-Host $sep -ForegroundColor Red
        Write-Host ''
        Write-Host '  The scheduled task will run as SYSTEM and sign ALL .rdp files placed' -ForegroundColor Yellow
        Write-Host "  in the watch folder: $WatchFolder" -ForegroundColor Yellow
        Write-Host ''
        Write-Host '  If non-administrators can write to this folder, they could drop a' -ForegroundColor Yellow
        Write-Host '  malicious .rdp file and have it signed automatically, making it appear' -ForegroundColor Yellow
        Write-Host '  trusted to users.' -ForegroundColor Yellow
        Write-Host ''
        Write-Host '  Ensure the watch folder is restricted to Administrators only:' -ForegroundColor Yellow
        Write-Host '    icacls "$WatchFolder" /inheritance:r /grant "BUILTIN\Administrators:(OI)(CI)F" /grant "SYSTEM:(OI)(CI)F"' -ForegroundColor Cyan
        Write-Host ''
        Write-Host $sep -ForegroundColor Red
        Write-Host ''

        $confirm = Read-Host 'Have you secured the folder access controls? Type YES to continue'
        if ($confirm -ne 'YES') {
            Write-Warn 'Task registration cancelled. Secure the watch folder before proceeding.'
            return
        }

        $certArg  = if ($CertThumbprint) { "-CertThumbprint `"$CertThumbprint`"" } `
                    else                  { "-CertSubject `"$CertSubject`"" }
        $taskArgs  = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" -Sign -RdpFolder `"$WatchFolder`" -Recurse $certArg -NoLog"
        $action    = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $taskArgs
        $trigger   = New-ScheduledTaskTrigger -Once -At (Get-Date) `
                         -RepetitionInterval (New-TimeSpan -Minutes 5)
        $settings  = New-ScheduledTaskSettingsSet `
                         -ExecutionTimeLimit (New-TimeSpan -Minutes 10) `
                         -MultipleInstances IgnoreNew
        $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' `
                         -LogonType ServiceAccount -RunLevel Highest
        $taskName  = 'RDPFileSigner - Auto Sign'

        if ($PSCmdlet.ShouldProcess($taskName, 'Register scheduled task')) {
            Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
                -Settings $settings -Principal $principal -Force | Out-Null
            Write-Ok "Task '$taskName' registered."
            Write-Info "Watch folder : $WatchFolder"
            Write-Info "Runs every   : 5 minutes"
            Write-Info "Certificate  : $(if ($CertThumbprint) { $CertThumbprint } else { $CertSubject })"
        }

        Write-Divider
        Write-Host ' Done. RDP files dropped into the folder will be signed automatically.' -ForegroundColor White
        Write-Host ' To remove: .\RDPFileSigner.ps1 -TaskUnregister' -ForegroundColor Cyan
        Write-Divider
        return
    }

    # ShellUnregister
    if ($PSCmdlet.ParameterSetName -eq 'ShellUnregister') {
        Write-Step 'Unregistering RDP context menu entries'

        foreach ($verb in @('RDPFileSignerSign', 'RDPFileSignerUnsign')) {
            $key = Get-RdpVerbKeyPath $verb
            if (Test-Path $key) {
                if ($PSCmdlet.ShouldProcess($key, 'Remove registry key')) {
                    Remove-Item -Path $key -Recurse -Force
                    Write-Ok "Removed: $verb"
                }
            } else {
                Write-Warn "Not found, skipping: $verb"
            }
        }

        Write-Divider
        Write-Host ' Done. Context menu entries removed.' -ForegroundColor White
        Write-Divider
        return
    }

    # Unsign
    if ($PSCmdlet.ParameterSetName -eq 'Unsign') {
        Write-Step 'Collecting RDP files to unsign'
        $files = @(Get-RdpFileList -File $RdpFile -Folder $RdpFolder -Recurse:$Recurse)

        if ($files.Count -eq 0) {
            Write-Warn 'No RDP files found.'
            return
        }
        Write-Ok "Found $($files.Count) file(s)."

        Write-Step 'Removing digital signatures'
        $ok = 0; $fail = 0; $idx = 0
        $enc = [System.Text.Encoding]::UTF8

        foreach ($f in $files) {
            $idx++
            Write-Progress -Activity 'Unsigning RDP files' -Status $f `
                -PercentComplete (($idx / $files.Count) * 100)
            Write-Host "    Unsigning: $f" -NoNewline

            try {
                $lines   = [System.IO.File]::ReadAllLines($f, $enc)
                $cleaned = @($lines | Where-Object {
                    $_ -notmatch '^signscope:s:' -and $_ -notmatch '^signature:s:'
                })

                # Remove trailing blank lines that rdpsign.exe may have added.
                while ($cleaned.Count -gt 0 -and $cleaned[-1].Trim() -eq '') {
                    $cleaned = $cleaned[0..($cleaned.Count - 2)]
                }

                if ($PSCmdlet.ShouldProcess($f, 'Remove signature lines')) {
                    [System.IO.File]::WriteAllLines($f, $cleaned, $enc)
                }

                Write-Host ' ... ' -NoNewline
                Write-Host 'unsigned' -ForegroundColor Green
                $ok++
            } catch {
                Write-Host ' ... ' -NoNewline
                Write-Host "FAILED: $_" -ForegroundColor Red
                $fail++
            }
        }

        Write-Progress -Activity 'Unsigning RDP files' -Completed
        Write-Divider
        Write-Host ' Done.' -ForegroundColor White
        Write-Host "   Unsigned successfully : $ok"   -ForegroundColor Green
        if ($fail -gt 0) {
            Write-Host "   Failed               : $fail" -ForegroundColor Red
        }
        Write-Divider
        return
    }

    # Verify
    if ($PSCmdlet.ParameterSetName -eq 'Verify') {
        Write-Step 'Collecting RDP files to verify'
        $files = @(Get-RdpFileList -File $RdpFile -Folder $RdpFolder -Recurse:$Recurse)

        if ($files.Count -eq 0) {
            Write-Warn 'No RDP files found.'
            return
        }
        Write-Ok "Found $($files.Count) file(s)."

        Write-Step 'Checking signatures'
        $valid = 0; $invalid = 0; $unsigned = 0; $idx = 0
        $csvRows = [System.Collections.Generic.List[pscustomobject]]::new()

        # We have to parse the .rdp file manually to extract the signature and signed fields,
        # because there is no standard API for RDP file signatures and rdpsign.exe uses a proprietary format.
        foreach ($f in $files) {
            $idx++
            Write-Progress -Activity 'Verifying RDP signatures' -Status $f `
                -PercentComplete (($idx / $files.Count) * 100)

            # StreamReader with BOM detection handles both UTF-8 and UTF-16 LE.
            $sr      = [System.IO.StreamReader]::new($f, $true)
            $raw     = $sr.ReadToEnd()
            $sr.Dispose()
            $content = @($raw -split '\r?\n')

            $hasSig       = @($content | Where-Object { $_ -match '^signature:s:'  }).Count -gt 0
            $hasSignscope = @($content | Where-Object { $_ -match '^signscope:s:'  }).Count -gt 0

            $status      = 'UNSIGNED'
            $signerThumb = ''

            if (-not ($hasSig -and $hasSignscope)) {
                $unsigned++
                Write-Host "    [UNSIGNED] $f" -ForegroundColor Yellow
            } else {
                $dbgLines      = [System.Collections.Generic.List[string]]::new()
                $msgBlob       = [byte[]]@()
                $scopeValClean = ''
                $contentOid    = $null
                try {
                    # --- Reconstruct the signed content (msgblob) ---
                    # signscope:s: lists the display names of the signed fields.
                    # We rebuild the same UTF-16LE blob that rdpsign.exe fed to openssl:
                    #   <matching lines joined by CRLF> + CRLF + signscope:s:<names> + CRLF + NUL
                    $scopeVal  = ($content | Where-Object { $_ -match '^signscope:s:' } |
                                  Select-Object -First 1) -replace '^signscope:s:', ''
                    $signNames = $scopeVal -split ','

                    $unmapped  = [System.Collections.Generic.List[string]]::new()
                    $signLines = [System.Collections.Generic.List[string]]::new()
                    $dbgLines  = [System.Collections.Generic.List[string]]::new()
                    foreach ($name in $signNames) {
                        $nameTrimmed = $name.Trim()
                        $prefix = $script:RdpFieldNameToPrefix[$nameTrimmed]
                        if (-not $prefix) {
                            $unmapped.Add($nameTrimmed)
                            continue
                        }
                        $line = ($content | Where-Object { $_ -match "^$([regex]::Escape($prefix))" } |
                                 Select-Object -First 1)
                        if ($line) {
                            $trimmedLine = $line.Trim()
                            $signLines.Add($trimmedLine)
                            $dbgLines.Add("  [$nameTrimmed] $trimmedLine")
                        } else {
                            $dbgLines.Add("  [$nameTrimmed] (NOT FOUND IN FILE)")
                        }
                    }

                    if ($unmapped.Count -gt 0) {
                        throw "Signscope contains field name(s) not in the known mapping table: $($unmapped -join ', '). Add missing entries to `$script:RdpFieldNameToPrefix and retry."
                    }

                    # Use $scopeVal verbatim (trimmed) - don't split+rejoin.
                    $scopeValClean = $scopeVal.TrimEnd()
                    $msgText = ($signLines -join "`r`n") + "`r`n" +
                               "signscope:s:" + $scopeValClean + "`r`n" +
                               [char]0
                    $msgBlob = [System.Text.Encoding]::Unicode.GetBytes($msgText)

                    # --- Decode the signature blob ---
                    # Collect multi-line base64 (rdpsign.exe may indent continuation lines)
                    $sigStartIdx = -1
                    for ($i = 0; $i -lt $content.Count; $i++) {
                        if ($content[$i] -match '^signature:s:') { $sigStartIdx = $i; break }
                    }
                    $b64Parts = @(($content[$sigStartIdx] -replace '^signature:s:', ''))
                    $j = $sigStartIdx + 1
                    while ($j -lt $content.Count -and $content[$j] -match '^\s+\S') {
                        $b64Parts += $content[$j]; $j++
                    }
                    $b64 = ($b64Parts -join '') -replace '[\s\x00]', ''

                    try {
                        $allBytes = [Convert]::FromBase64String($b64)
                    } catch {
                        throw 'Signature data is corrupted (invalid base64).'
                    }

                    # Strip the 12-byte proprietary rdpsign.exe header:
                    #   [01 00 01 00] [01 00 00 00] [DER-size DWORD LE]
                    # Real PKCS#7 DER starts at the first 0x30 0x82 (ASN.1 SEQUENCE).
                    $derStart = 0
                    for ($i = 0; $i -lt [Math]::Min(32, $allBytes.Length - 1); $i++) {
                        if ($allBytes[$i] -eq 0x30 -and $allBytes[$i + 1] -eq 0x82) {
                            $derStart = $i; break
                        }
                    }
                    $derBytes = $allBytes[$derStart..($allBytes.Length - 1)]

                    # --- Full cryptographic verification ---
                    # Peek at the OID the signature was originally made with so we can
                    # pass a matching ContentInfo - avoids OID mismatch on CheckSignature.
                    $cmsPeek = [System.Security.Cryptography.Pkcs.SignedCms]::new(
                        [System.Security.Cryptography.Pkcs.ContentInfo]::new([byte[]]@()), $true)
                    try {
                        $cmsPeek.Decode($derBytes)
                    } catch {
                        throw 'Signature blob is corrupted or has been tampered with (cannot parse PKCS#7 structure).'
                    }
                    $contentOid = $cmsPeek.ContentInfo.ContentType

                    $contentInfo = [System.Security.Cryptography.Pkcs.ContentInfo]::new($contentOid, $msgBlob)
                    $cms = [System.Security.Cryptography.Pkcs.SignedCms]::new($contentInfo, $true)
                    $cms.Decode($derBytes)
                    try {
                        $cms.CheckSignature($true)   # $true = verify math only, skip chain trust
                    } catch {
                        throw 'Signature is invalid - the file has been tampered with after signing.'
                    }

                    $signerCert  = if ($cms.SignerInfos.Count -gt 0) { $cms.SignerInfos[0].Certificate } else { $null }
                    $signerThumb = if ($signerCert) { $signerCert.Thumbprint } else { '' }

                    if ($signerCert -and $signerCert.NotAfter -lt (Get-Date)) {
                        $status = 'INVALID'
                        $invalid++
                        Write-Host "    [INVALID]  $f" -ForegroundColor Red
                        Write-Host "               Signer cert expired: $($signerCert.NotAfter.ToString('yyyy-MM-dd'))  Thumb: $signerThumb" -ForegroundColor DarkRed
                    } else {
                        $status = 'VALID'
                        $valid++
                        Write-Host "    [VALID]    $f" -ForegroundColor Green
                        if ($signerThumb) {
                            Write-Host "               Signer : $signerThumb" -ForegroundColor DarkGray
                        }
                    }
                } catch {
                    $status = 'INVALID'
                    $invalid++
                    Write-Host "    [INVALID]  $f" -ForegroundColor Red
                    Write-Host "               $($_.Exception.Message)" -ForegroundColor DarkRed
                    # Diagnostic: show reconstructed content when signature math fails
                    # (not shown for structural errors like corrupted blobs).
                    if ($dbgLines -and $dbgLines.Count -gt 0 -and $contentOid -and $msgBlob.Length -gt 0) {
                        Write-Host "               --- Reconstructed content ($($msgBlob.Length) bytes, OID: $($contentOid.Value)) ---" -ForegroundColor DarkGray
                        foreach ($dl in $dbgLines) {
                            Write-Host "               $dl" -ForegroundColor DarkGray
                        }
                        Write-Host "               signscope:s:$scopeValClean" -ForegroundColor DarkGray
                        Write-Host "               ---" -ForegroundColor DarkGray
                    }
                }
            }

            $csvRows.Add([pscustomobject]@{
                File        = $f
                Status      = $status
                SignerThumb = $signerThumb
                CheckedAt   = (Get-Date -Format 'dd-MM-yyyy HH:mm:ss')
            })
        }

        Write-Progress -Activity 'Verifying RDP signatures' -Completed
        Write-Divider
        Write-Host ' Done.' -ForegroundColor White
        Write-Host "   Valid     : $valid"    -ForegroundColor Green
        if ($invalid -gt 0) {
            Write-Host "   Invalid   : $invalid" -ForegroundColor Red
        }
        Write-Host "   Unsigned  : $unsigned" -ForegroundColor Yellow
        Write-Divider

        if ($ExportCsvPath) {
            $csvRows | Export-Csv -Path $ExportCsvPath -NoTypeInformation -Encoding UTF8
            Write-Ok "CSV report exported to: $ExportCsvPath"
        }

        if ($invalid -gt 0) { exit 2 }
        return
    }

    # ShellRegister
    if ($PSCmdlet.ParameterSetName -eq 'ShellRegister') {
        Write-Step 'Re-registering shell context menu entries'

        $scriptPath = if ($PSCommandPath) { $PSCommandPath } else {
            [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
        }
        if (-not $scriptPath) {
            throw 'Cannot determine the script path for context menu registration.'
        }

        Register-ShellContextMenu -ScriptPath $scriptPath

        Write-Divider
        Write-Host ' Done. Right-click any .rdp file to see Sign / UnSign options.' -ForegroundColor White
        Write-Divider
        return
    }

    # Setup/Sign - certificate acquisition

    $cert = $null

    # Option 1: Import from PFX (commercial CA or transfer from another machine)
    if ($PSCmdlet.ParameterSetName -eq 'Setup' -and $ImportPfxPath) {
        Write-Step 'Step 1: Importing certificate from PFX (commercial / external CA)'

        if (-not (Test-Path $ImportPfxPath -PathType Leaf)) {
            throw "PFX file not found: $ImportPfxPath"
        }

        $pfxPwd = if ($ImportPfxPassword) {
            $ImportPfxPassword
        } else {
            Read-Host -Prompt 'Enter the PFX password' -AsSecureString
        }

        $cert = Import-PfxCertificate -FilePath $ImportPfxPath `
            -CertStoreLocation 'Cert:\LocalMachine\My' `
            -Password $pfxPwd

        Show-CertInfo $cert 'Imported Certificate'
    }

    # Option 2: Use an existing certificate by thumbprint
    elseif ($CertThumbprint) {
        Write-Step 'Step 1: Looking up certificate by thumbprint'

        $clean = $CertThumbprint -replace '\s', ''
        $cert  = Get-ChildItem 'Cert:\LocalMachine\My' |
            Where-Object { $_.Thumbprint -eq $clean } |
            Select-Object -First 1

        if (-not $cert) {
            $cert = Get-ChildItem 'Cert:\CurrentUser\My' |
                Where-Object { $_.Thumbprint -eq $clean } |
                Select-Object -First 1
        }

        if (-not $cert) {
            throw "No certificate with thumbprint '$clean' found in Cert:\LocalMachine\My or Cert:\CurrentUser\My."
        }

        Show-CertInfo $cert 'Certificate'
    }

    # Option 3: Request from Enterprise CA
    elseif ($PSCmdlet.ParameterSetName -eq 'Setup' -and $CertTemplate) {
        Write-Step "Step 1: Requesting certificate from Enterprise CA (template: $CertTemplate)"

        $result = Get-Certificate -Template $CertTemplate `
            -CertStoreLocation 'Cert:\LocalMachine\My' `
            -ErrorAction Stop

        if (-not $result) { throw 'Certificate enrollment request failed.' }
        $cert = $result.Certificate

        Show-CertInfo $cert 'Enrolled Certificate'
    }

    # Option 4: Self-signed (Setup default) or look up by subject (Sign mode)
    else {
        if ($PSCmdlet.ParameterSetName -eq 'Sign') {
            Write-Step 'Step 1: Looking up existing RDP signing certificate by subject'

            $cert = Get-ChildItem 'Cert:\LocalMachine\My' |
                Where-Object { $_.Subject -eq $CertSubject -and $_.NotAfter -gt (Get-Date) } |
                Sort-Object NotAfter -Descending |
                Select-Object -First 1

            if (-not $cert) {
                $cert = Get-ChildItem 'Cert:\CurrentUser\My' |
                    Where-Object { $_.Subject -eq $CertSubject -and $_.NotAfter -gt (Get-Date) } |
                    Sort-Object NotAfter -Descending |
                    Select-Object -First 1
            }

            if (-not $cert) {
                throw ("No valid certificate with subject '$CertSubject' found in Cert:\LocalMachine\My or Cert:\CurrentUser\My. " +
                    "Run RDPFileSigner.ps1 without parameters to create one, or supply -CertThumbprint.")
            }

            Show-CertInfo $cert 'Signing Certificate'

        } else {
            # Setup mode - create or reuse a self-signed certificate.
            Write-Step 'Step 1: Preparing self-signed code-signing certificate'

            $existing = Get-ChildItem 'Cert:\LocalMachine\My' |
                Where-Object { $_.Subject -eq $CertSubject -and $_.NotAfter -gt (Get-Date) } |
                Sort-Object NotAfter -Descending |
                Select-Object -First 1

            if ($existing) {
                Write-Warn 'A valid certificate already exists - reusing it.'
                $cert = $existing
                Show-CertInfo $cert 'Existing Certificate'
            } else {
                $notAfter = (Get-Date).AddYears($CertValidityYears)

                $cert = New-SelfSignedCertificate `
                    -Subject           $CertSubject `
                    -CertStoreLocation 'Cert:\LocalMachine\My' `
                    -KeyUsage          DigitalSignature `
                    -KeyUsageProperty  Sign `
                    -TextExtension     @('2.5.29.37={text}1.3.6.1.5.5.7.3.3') `
                    -KeyAlgorithm      RSA `
                    -KeyLength         4096 `
                    -HashAlgorithm     SHA256 `
                    -NotAfter          $notAfter `
                    -KeyExportPolicy   Exportable `
                    -FriendlyName      'RDP File Signing Certificate'

                Write-Ok 'Self-signed certificate created.'
                Show-CertInfo $cert 'New Self-Signed Certificate'
                Write-Info "Valid for  : $CertValidityYears year(s)"
            }
        }
    }

    # Warn if the certificate lacks the Code Signing EKU.
    if (-not (Test-CodeSigningEku $cert)) {
        Write-Warn 'This certificate does not carry the Code Signing EKU (OID 1.3.6.1.5.5.7.3.3).'
        Write-Warn 'Signing may fail. Obtain a certificate issued specifically for code signing.'
    }

    # Warn if the certificate is expired or expiring soon.
    Test-CertExpiringSoon -Cert $cert

    # Setup: trust stores, ACL, export, context menu
    if ($PSCmdlet.ParameterSetName -eq 'Setup') {

        Write-Step 'Step 2: Installing certificate into trust stores'
        Install-CertToStore -Cert $cert -StoreName 'Root'
        Install-CertToStore -Cert $cert -StoreName 'TrustedPublisher'
        Write-Ok 'Certificate is trusted on this machine.'
        Write-Warn 'To trust on other machines, distribute the public .cer and import it (see Group Policy section).'

        Write-Step 'Step 3: Setting private key permissions for non-admin signing'
        Grant-PrivateKeyReadToUsers -Cert $cert

        # Export public .cer
        if ($ExportCerPath) {
            Write-Step 'Step 4a: Exporting public certificate (.cer)'
            $certBytes = $cert.Export([X509ContentType]::Cert)
            [System.IO.File]::WriteAllBytes($ExportCerPath, $certBytes)
            Write-Ok "Exported to : $ExportCerPath"
            Write-Info ''
            Write-Info 'Install on a client machine (run as Administrator):'
            Write-Info "    Import-Certificate -FilePath '$ExportCerPath' -CertStoreLocation Cert:\LocalMachine\Root"
            Write-Info "    Import-Certificate -FilePath '$ExportCerPath' -CertStoreLocation Cert:\LocalMachine\TrustedPublisher"
        }

        # Export .pfx with private key
        if ($ExportPfxPath) {
            Write-Step 'Step 4b: Exporting certificate with private key (.pfx)'

            $pfxPwd = if ($ExportPfxPassword) {
                $ExportPfxPassword
            } else {
                Read-Host -Prompt 'Enter a strong password for the PFX export' -AsSecureString
            }

            Export-PfxCertificate -Cert $cert -FilePath $ExportPfxPath `
                -Password $pfxPwd | Out-Null

            Write-Ok "Exported to : '$ExportPfxPath'"
            Write-Warn 'Store the .pfx securely - it contains the private key!'
        }

        # Group Policy deployment hints
        Write-GroupPolicyHints -Thumbprint $cert.Thumbprint -CerPath $ExportCerPath

        # Register context menu (unless explicitly skipped)
        if (-not $SkipShellRegistration) {
            Write-Step 'Step 5: Registering shell context menu entries'

            $scriptPath = if ($PSCommandPath) { $PSCommandPath } else {
                [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
            }
            if (-not $scriptPath) {
                throw 'Cannot determine the script path for context menu registration.'
            }

            Register-ShellContextMenu -ScriptPath $scriptPath
        }

        # If no files were supplied, finish here.
        Write-Divider
        Write-Host ' Setup complete.' -ForegroundColor White
        Write-Host "   Certificate thumbprint : $($cert.Thumbprint)"
        Write-Host ''
        Write-Host ' Right-click any .rdp file to Sign or UnSign it.' -ForegroundColor Cyan
        Write-Host ' To sign files now, run:  .\RDPFileSigner.ps1 -Sign -RdpFile <path>' -ForegroundColor Cyan
        Write-Host ' Or:                      .\RDPFileSigner.ps1 -Sign -RdpFolder <path>' -ForegroundColor Cyan
        Write-Divider
        return
    }

    # Sign
    # Reached from -Sign mode (Setup exits above).

    if (-not $RdpFile -and -not $RdpFolder) {
        Write-Warn 'No target specified. Provide -RdpFile <path> or -RdpFolder <path>.'
        return
    }

    Write-Step 'Step 2: Collecting RDP files to sign'
    $files = @(Get-RdpFileList -File $RdpFile -Folder $RdpFolder -Recurse:$Recurse)

    if ($files.Count -eq 0) {
        Write-Warn 'No RDP files found to sign.'
        return
    }
    Write-Ok "Found $($files.Count) file(s)."

    # Locate rdpsign.exe
    $rdpSignExe = Get-RdpSignPath
    Write-Info "rdpsign.exe : '$rdpSignExe'"

    Write-Step 'Step 3: Signing RDP files with rdpsign.exe'
    $thumbprint = $cert.Thumbprint
    $ok = 0; $fail = 0; $idx = 0

    foreach ($f in $files) {
        $idx++
        Write-Progress -Activity 'Signing RDP files' -Status $f `
            -PercentComplete (($idx / $files.Count) * 100)
        Write-Host "    Signing: $f" -NoNewline

        if ($PSCmdlet.ShouldProcess($f, 'Sign with rdpsign.exe')) {
            $output = & $rdpSignExe /sha256 $thumbprint /v $f 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Host ' ... ' -NoNewline
                Write-Host 'signed' -ForegroundColor Green
                $ok++
            } else {
                Write-Host ' ... ' -NoNewline
                Write-Host 'FAILED' -ForegroundColor Red
                Write-Host "        $output" -ForegroundColor Red
                $fail++
            }
        }
    }

    Write-Progress -Activity 'Signing RDP files' -Completed

    # Export public .cer after signing if requested in -Sign mode.
    if ($ExportCerPath) {
        Write-Step 'Exporting public certificate (.cer)'
        $certBytes = $cert.Export([X509ContentType]::Cert)
        [System.IO.File]::WriteAllBytes($ExportCerPath, $certBytes)
        Write-Ok "Exported to : $ExportCerPath"
        Write-Info ''
        Write-Info 'Install on a client machine (run as Administrator):'
        Write-Info "    Import-Certificate -FilePath '$ExportCerPath' -CertStoreLocation Cert:\LocalMachine\Root"
        Write-Info "    Import-Certificate -FilePath '$ExportCerPath' -CertStoreLocation Cert:\LocalMachine\TrustedPublisher"
    }

    Write-Divider
    Write-Host ' Done.' -ForegroundColor White
    Write-Host "   Signed successfully : $ok"   -ForegroundColor Green
    if ($fail -gt 0) {
        Write-Host "   Failed              : $fail" -ForegroundColor Red
    }
    Write-Host "   Certificate thumbprint : $thumbprint"
    Write-Host ''
    Write-Host ' Users on THIS machine will see a verified-publisher dialog.' -ForegroundColor Cyan
    if (-not $ExportCerPath) {
        Write-Host ' For other machines, run with -ExportCerPath to export the public certificate,' -ForegroundColor Cyan
        Write-Host ' then import it into Cert:\LocalMachine\Root and Cert:\LocalMachine\TrustedPublisher.' -ForegroundColor Cyan
    }
    Write-GroupPolicyHints -Thumbprint $thumbprint -CerPath $ExportCerPath
    Write-Divider

} catch {
    Write-Host ''
    Write-Host "ERROR: $_" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor DarkRed
    exit 1
} finally {
    Write-Host ''
    Write-Host "Finished: $(Get-Date -Format 'dd-MM-yyyy HH:mm:ss')"
    if (-not $NoLog) { Stop-Transcript | Out-Null }
}

#endregion