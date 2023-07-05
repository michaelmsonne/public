<#
    .NOTES
    ===========================================================================
     Created with:  Microsoft Visual Studio 2022
     Created on:    15-03-2022 08:09
	 Updated on:    16-03-2022 10:24 (By: Michael Morten Sonne)
     Created by:    Michael Morten Sonne
     Organization:  
	 Name:          RemoveNTFSPermissions
     Filename:      RemoveNTFSPermissions.ps1
    ===========================================================================
    .SYNOPSIS
    Remove all NTFS permissions for a user/group for a folder (and subfolders) and files

    .DESCRIPTION
    Remove all NTFS permissions for a user/group for a folder (and subfolders) and files

    The valid format is:
    Local:
        Groups: "Users" (local Users group)
        User: "Administrator" (local built in user)
        
    Domain:
        Groups: "Domain Admins" (Domain Admins)
        User: "DOMAIN\user" (user in the domain)

    .EXAMPLE
    PS C:\> .\RemoveNTFSPermissions.ps1 -username "Domain Admins" -path "D:\Test\"

    Removeing all NTFS permissions for Domain Admins for "D:\Test\"

    .NOTES
    ## IMPORTENT: Be sure to remove the RIGHT permissions! ##

    See current permissions for a folder in PowerShell - it will output something like this:

    PS C:\Windows\system32>  Get-Acl -Path 'D:\Private\Username' | fl

    Path   : Microsoft.PowerShell.Core\FileSystem::D:\Private\Username
    Owner  : BUILTIN\Administrators
    Group  : DOMAIN\Domain Users
    Access : CREATOR OWNER Allow  FullControl
             NT AUTHORITY\SYSTEM Allow  FullControl
             BUILTIN\Administrators Allow  FullControl
             DOMAIN\Domain Admins Allow  FullControl
             DOMAIN\It-Administratorer Allow  FullControl
             DOMAIN\ServiceAccount Allow  Modify, Synchronize
             DOMAIN\Username Allow  Modify, Synchronize
    Audit  :
    Sddl   : O:BAG:DUD:PAI(A;OICIIO;FA;;;CO)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;DA)(A;OICI;FA;;;S-1-5-21-72881033-
             756810003-1546849883-37080)(A;OICI;0x1301bf;;;S-1-5-21-72881033-756810003-1546849883-81858)(A;OICI;0x1301bf;;;
             S-1-5-21-72881033-756810003-1546849883-85357)

    .HISTORY
    16-03-2022
        Added information about current permissions

    15-03-2022
        Created
#>

param (   
    [string]$username = $(throw "-username is required."),
    [string]$path = $(throw "-path is required.")
)

#Get time now for start
$starttime = (Get-Date).Second

Write-Host "`nWill you perform removal of ALL NTFS permissiosn for user:" $username "on path:" $path "?`n" -ForegroundColor Red
While($Selection -ne "Y" )
{
    $Selection = read-host "Continue? (Y/N)"
    Switch ($Selection) 
    {
        Y {Write-host "`nContinuing with validation from user!`n" -ForegroundColor Green}
        N {Write-Host "`nBreaking out of script!`n" -ForegroundColor Yellow;exit}
        default {Write-Host "Only Y/N are Valid responses"}
    }
}

$pathdata = $path #"D:\Test\"
$User = $Username #"Users" # Local: "Users" - Domain: "Domain Admins"
$Account = new-object system.security.principal.ntaccount($User)

#$ACL = (Get-Item $pathdata).GetAccessControl('Access')
$ACL = Get-Acl -path $pathdata
$ACL.PurgeAccessRules($Account)
$ACL  | Set-Acl -path $pathdata -Verbose

Get-ChildItem -Recurse -Path $pathdata -Directory | ForEach-Object {
    $ACL = Get-Acl -path $_.FullName
    $ACL.PurgeAccessRules($Account)
    $ACL | Set-Acl -path $_.FullName -Verbose
}

#Get time now for end
$endtime = (Get-Date).Second
$diff = ($endtime - $starttime).ToString()

#Show time script has run
Write-Host "`n`nExecution Time : " $diff " Second" -BackgroundColor DarkCyan