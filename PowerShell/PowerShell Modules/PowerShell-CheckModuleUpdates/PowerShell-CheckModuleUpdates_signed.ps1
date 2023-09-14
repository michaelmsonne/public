<#	
	.NOTES
	===========================================================================
	 Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2022 v5.8.213
	 Created on:   	18-06-2023 17:41
	 Created by:   	Michael Morten Sonne
	 Organization: 	Sonne´s Cloud
	 Filename:     	PowerShell-CheckModuleUpdates.ps1
	===========================================================================
	.DESCRIPTION
		Check for Updates for PowerShell Modules from PowerShell Gallery

        If you look for a quick way to update, please keep in mind Microsoft has a built-in cmdlet to update ALL the PowerShell modules installed:
        Update-Module [-Verbose]

        This script provides informations about the module version (current installed and the latest available on PowerShell Gallery)

	.EXAMPLE
		.\PowerShell-CheckModuleUpdates.ps1
        Show modules there is updates to

        .\PowerShell-CheckModuleUpdates.ps1 -Verbose
        Show modules there is updates to and all running tasks and information provided

    .NOTES
        
#>

[cmdletbinding()]
[outputtype("moduleInfo")]
Param(
    [Parameter(Position = 0, HelpMessage = "Enter a module name or names. Wildcards are allowed.")]
    [ValidateNotNullorEmpty()]
    [string[]]$Name = "*"
)

Write-Host -ForegroundColor Cyan "Getting installed modules..."
Try
{
    $modules = Get-Module -Name $name -ListAvailable -ErrorAction Stop
}
Catch
{
    Throw $_
}

if ($modules)
{
    Write-Verbose "Found $($modules.count) matching modules"
    
    # Group to identify modules with multiple versions installed
    Write-Verbose "Grouping modules"
    $g = $modules | Group-Object name -NoElement | Where-Object count -GT 1

    # Filter modules
    Write-Verbose "Filter to modules from the PowerShellGallery"
    $gallery = $modules.where( { $_.repositorysourcelocation })

    <#Write-Verbose "Comparing to online versions"
    foreach ($module in $gallery) {
        #find the current version in the gallery
        Try {
            Write-Verbose "Looking online for $($module.name)"
            $online = Find-Module -Name $module.name -Repository PSGallery -ErrorAction Stop
            #compare versions
            if (($online.version -as [version]) -gt ($module.version -as [version])) {
                $UpdateAvailable = $True
            }
            else {
                $UpdateAvailable = $False
            }

            #write a custom object to the pipeline
            [pscustomobject]@{
                PSTypeName       = "moduleInfo"
                Name             = $module.name
                MultipleVersions = ($g.name -contains $module.name)
                InstalledVersion = $module.version
                OnlineVersion    = $online.version
                Update           = $UpdateAvailable
                Path             = $module.modulebase
            } | Format-Table -AutoSize 
        }
        Catch {
            Write-Warning "Module $($module.name) was not found in the PSGallery"
        }

    } #foreach#>
    Write-Host -ForegroundColor Cyan "Comparing installed versions to online versions at PowerShellGallery..."
    $moduleInfoList = foreach ($module in $gallery)
    {
        # Find the current version in the gallery
        try
        {
            Write-Verbose "Looking online for $($module.name) version..."
            $online = Find-Module -Name $module.name -Repository PSGallery -ErrorAction Stop
            
            # Compare versions
            if (($online.version -as [version]) -gt ($module.version -as [version])) {
                $UpdateAvailable = $true
            }
            else {
                $UpdateAvailable = $false
            }

            # Create a custom object for each module
            [pscustomobject]@{
                PSTypeName       = "moduleInfo"
                Name             = $module.name
                Update           = $UpdateAvailable
                MultipleVersions = ($g.name -contains $module.name)
                InstalledVersion = $module.version
                OnlineVersion    = $online.version
                #Path             = $module.modulebase
            }
        }
        catch
        {
            # If module not found
            Write-Warning "Module $($module.name) was not found in the PowerShellGallery"
        }
    }

    # Output
    Write-Host -ForegroundColor Cyan "List of PowerShell Module(s) there is found an update to:"

    # Filter the moduleInfo list where Update is true and format as a table
    $moduleInfoList | Where-Object { $_.Update } | Format-Table -AutoSize
}
else
{
    # No modules found
    Write-Warning "No matching modules found."
}

# Complete
Write-Host "Check is complete for updates to PowerShell Module(s)"
# SIG # Begin signature block
# MIIm2wYJKoZIhvcNAQcCoIImzDCCJsgCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDjt30DpO+DSUtu
# 8/CMfYRqKsnLbMnAVvHAEsUnknUnMKCCH8gwggVvMIIEV6ADAgECAhBI/JO0YFWU
# jTanyYqJ1pQWMA0GCSqGSIb3DQEBDAUAMHsxCzAJBgNVBAYTAkdCMRswGQYDVQQI
# DBJHcmVhdGVyIE1hbmNoZXN0ZXIxEDAOBgNVBAcMB1NhbGZvcmQxGjAYBgNVBAoM
# EUNvbW9kbyBDQSBMaW1pdGVkMSEwHwYDVQQDDBhBQUEgQ2VydGlmaWNhdGUgU2Vy
# dmljZXMwHhcNMjEwNTI1MDAwMDAwWhcNMjgxMjMxMjM1OTU5WjBWMQswCQYDVQQG
# EwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMS0wKwYDVQQDEyRTZWN0aWdv
# IFB1YmxpYyBDb2RlIFNpZ25pbmcgUm9vdCBSNDYwggIiMA0GCSqGSIb3DQEBAQUA
# A4ICDwAwggIKAoICAQCN55QSIgQkdC7/FiMCkoq2rjaFrEfUI5ErPtx94jGgUW+s
# hJHjUoq14pbe0IdjJImK/+8Skzt9u7aKvb0Ffyeba2XTpQxpsbxJOZrxbW6q5KCD
# J9qaDStQ6Utbs7hkNqR+Sj2pcaths3OzPAsM79szV+W+NDfjlxtd/R8SPYIDdub7
# P2bSlDFp+m2zNKzBenjcklDyZMeqLQSrw2rq4C+np9xu1+j/2iGrQL+57g2extme
# me/G3h+pDHazJyCh1rr9gOcB0u/rgimVcI3/uxXP/tEPNqIuTzKQdEZrRzUTdwUz
# T2MuuC3hv2WnBGsY2HH6zAjybYmZELGt2z4s5KoYsMYHAXVn3m3pY2MeNn9pib6q
# RT5uWl+PoVvLnTCGMOgDs0DGDQ84zWeoU4j6uDBl+m/H5x2xg3RpPqzEaDux5mcz
# mrYI4IAFSEDu9oJkRqj1c7AGlfJsZZ+/VVscnFcax3hGfHCqlBuCF6yH6bbJDoEc
# QNYWFyn8XJwYK+pF9e+91WdPKF4F7pBMeufG9ND8+s0+MkYTIDaKBOq3qgdGnA2T
# OglmmVhcKaO5DKYwODzQRjY1fJy67sPV+Qp2+n4FG0DKkjXp1XrRtX8ArqmQqsV/
# AZwQsRb8zG4Y3G9i/qZQp7h7uJ0VP/4gDHXIIloTlRmQAOka1cKG8eOO7F/05QID
# AQABo4IBEjCCAQ4wHwYDVR0jBBgwFoAUoBEKIz6W8Qfs4q8p74Klf9AwpLQwHQYD
# VR0OBBYEFDLrkpr/NZZILyhAQnAgNpFcF4XmMA4GA1UdDwEB/wQEAwIBhjAPBgNV
# HRMBAf8EBTADAQH/MBMGA1UdJQQMMAoGCCsGAQUFBwMDMBsGA1UdIAQUMBIwBgYE
# VR0gADAIBgZngQwBBAEwQwYDVR0fBDwwOjA4oDagNIYyaHR0cDovL2NybC5jb21v
# ZG9jYS5jb20vQUFBQ2VydGlmaWNhdGVTZXJ2aWNlcy5jcmwwNAYIKwYBBQUHAQEE
# KDAmMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5jb21vZG9jYS5jb20wDQYJKoZI
# hvcNAQEMBQADggEBABK/oe+LdJqYRLhpRrWrJAoMpIpnuDqBv0WKfVIHqI0fTiGF
# OaNrXi0ghr8QuK55O1PNtPvYRL4G2VxjZ9RAFodEhnIq1jIV9RKDwvnhXRFAZ/ZC
# J3LFI+ICOBpMIOLbAffNRk8monxmwFE2tokCVMf8WPtsAO7+mKYulaEMUykfb9gZ
# pk+e96wJ6l2CxouvgKe9gUhShDHaMuwV5KZMPWw5c9QLhTkg4IUaaOGnSDip0TYl
# d8GNGRbFiExmfS9jzpjoad+sPKhdnckcW67Y8y90z7h+9teDnRGWYpquRRPaf9xH
# +9/DUp/mBlXpnYzyOmJRvOwkDynUWICE5EV7WtgwggYaMIIEAqADAgECAhBiHW0M
# UgGeO5B5FSCJIRwKMA0GCSqGSIb3DQEBDAUAMFYxCzAJBgNVBAYTAkdCMRgwFgYD
# VQQKEw9TZWN0aWdvIExpbWl0ZWQxLTArBgNVBAMTJFNlY3RpZ28gUHVibGljIENv
# ZGUgU2lnbmluZyBSb290IFI0NjAeFw0yMTAzMjIwMDAwMDBaFw0zNjAzMjEyMzU5
# NTlaMFQxCzAJBgNVBAYTAkdCMRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQxKzAp
# BgNVBAMTIlNlY3RpZ28gUHVibGljIENvZGUgU2lnbmluZyBDQSBSMzYwggGiMA0G
# CSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQCbK51T+jU/jmAGQ2rAz/V/9shTUxjI
# ztNsfvxYB5UXeWUzCxEeAEZGbEN4QMgCsJLZUKhWThj/yPqy0iSZhXkZ6Pg2A2NV
# DgFigOMYzB2OKhdqfWGVoYW3haT29PSTahYkwmMv0b/83nbeECbiMXhSOtbam+/3
# 6F09fy1tsB8je/RV0mIk8XL/tfCK6cPuYHE215wzrK0h1SWHTxPbPuYkRdkP05Zw
# mRmTnAO5/arnY83jeNzhP06ShdnRqtZlV59+8yv+KIhE5ILMqgOZYAENHNX9SJDm
# +qxp4VqpB3MV/h53yl41aHU5pledi9lCBbH9JeIkNFICiVHNkRmq4TpxtwfvjsUe
# dyz8rNyfQJy/aOs5b4s+ac7IH60B+Ja7TVM+EKv1WuTGwcLmoU3FpOFMbmPj8pz4
# 4MPZ1f9+YEQIQty/NQd/2yGgW+ufflcZ/ZE9o1M7a5Jnqf2i2/uMSWymR8r2oQBM
# dlyh2n5HirY4jKnFH/9gRvd+QOfdRrJZb1sCAwEAAaOCAWQwggFgMB8GA1UdIwQY
# MBaAFDLrkpr/NZZILyhAQnAgNpFcF4XmMB0GA1UdDgQWBBQPKssghyi47G9IritU
# pimqF6TNDDAOBgNVHQ8BAf8EBAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIBADATBgNV
# HSUEDDAKBggrBgEFBQcDAzAbBgNVHSAEFDASMAYGBFUdIAAwCAYGZ4EMAQQBMEsG
# A1UdHwREMEIwQKA+oDyGOmh0dHA6Ly9jcmwuc2VjdGlnby5jb20vU2VjdGlnb1B1
# YmxpY0NvZGVTaWduaW5nUm9vdFI0Ni5jcmwwewYIKwYBBQUHAQEEbzBtMEYGCCsG
# AQUFBzAChjpodHRwOi8vY3J0LnNlY3RpZ28uY29tL1NlY3RpZ29QdWJsaWNDb2Rl
# U2lnbmluZ1Jvb3RSNDYucDdjMCMGCCsGAQUFBzABhhdodHRwOi8vb2NzcC5zZWN0
# aWdvLmNvbTANBgkqhkiG9w0BAQwFAAOCAgEABv+C4XdjNm57oRUgmxP/BP6YdURh
# w1aVcdGRP4Wh60BAscjW4HL9hcpkOTz5jUug2oeunbYAowbFC2AKK+cMcXIBD0Zd
# OaWTsyNyBBsMLHqafvIhrCymlaS98+QpoBCyKppP0OcxYEdU0hpsaqBBIZOtBajj
# cw5+w/KeFvPYfLF/ldYpmlG+vd0xqlqd099iChnyIMvY5HexjO2AmtsbpVn0OhNc
# WbWDRF/3sBp6fWXhz7DcML4iTAWS+MVXeNLj1lJziVKEoroGs9Mlizg0bUMbOalO
# hOfCipnx8CaLZeVme5yELg09Jlo8BMe80jO37PU8ejfkP9/uPak7VLwELKxAMcJs
# zkyeiaerlphwoKx1uHRzNyE6bxuSKcutisqmKL5OTunAvtONEoteSiabkPVSZ2z7
# 6mKnzAfZxCl/3dq3dUNw4rg3sTCggkHSRqTqlLMS7gjrhTqBmzu1L90Y1KWN/Y5J
# KdGvspbOrTfOXyXvmPL6E52z1NZJ6ctuMFBQZH3pwWvqURR8AgQdULUvrxjUYbHH
# j95Ejza63zdrEcxWLDX6xWls/GDnVNueKjWUH3fTv1Y8Wdho698YADR7TNx8X8z2
# Bev6SivBBOHY+uqiirZtg0y9ShQoPzmCcn63Syatatvx157YK9hlcPmVoa1oDE5/
# L9Uo2bC5a4CH2RwwggZKMIIEsqADAgECAhAR4aCGZIeugmCCjSjwUXrGMA0GCSqG
# SIb3DQEBDAUAMFQxCzAJBgNVBAYTAkdCMRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0
# ZWQxKzApBgNVBAMTIlNlY3RpZ28gUHVibGljIENvZGUgU2lnbmluZyBDQSBSMzYw
# HhcNMjMwMjE5MDAwMDAwWhcNMjYwNTE4MjM1OTU5WjBhMQswCQYDVQQGEwJESzEU
# MBIGA1UECAwLSG92ZWRzdGFkZW4xHTAbBgNVBAoMFE1pY2hhZWwgTW9ydGVuIFNv
# bm5lMR0wGwYDVQQDDBRNaWNoYWVsIE1vcnRlbiBTb25uZTCCAiIwDQYJKoZIhvcN
# AQEBBQADggIPADCCAgoCggIBALVGIWG57aPiOruK3bg3tlPMHol1pfnEQiCkYom7
# hFXLVxhGve4OcQmx9xtKy7QIHmbHdH3Vc4J4foS0/bv4cnzYRd0g2qcTjo0Q+b5J
# RUSZQ0yUbLyHJf1TkCJOODWORJlsi/xppcQdAbU7QX2KFE4NkQzNUIOTSlKctx99
# ZqFevKIvwhkmIoB+WWnl/qS4ipFMO/d4m7o8IIgi49LPq3tVxZs0aJ6N02X5Xp2F
# oG2fZynudHIf9waYFtYXA3B8msQwaREpQY880Kki/275pSC+T8+mbnbwrKXOZ8Gj
# W2vvEJZe5ySIrA27omMsBnmoZYkiNMmMGYWQiZ5E75ZIiZ4UqWpuahoGpBLoZNX+
# TjKFFuqmo8EqfYdCpLiYgw95q3gHONu6TwTg01WwaeZFtlhx8qSgD8x7L/SRn4qn
# x//ucBg1Q0f3Al6lz++z8t4ty6CxF/Wr9ZKOoYhHft6SAE7Td9VGdWJLkp6cY1qf
# rq+QA+xR7rjFi7dagxvP1RzZqeh5glAQ74g3/lZJdgDTv/yB/zjxj6dHjzwii501
# VW4ecSX9RQpwWbleDDriDbVNJxwz37mBcSQykGXVfVV8AcdXn1zvEDkdshtLUGAL
# 6q61CugAE4LoOWohBEtk7dV2X0rvEY3Wce47ATLY14VM5gQCEsRxkEqt1HwdK4R+
# v/LtAgMBAAGjggGJMIIBhTAfBgNVHSMEGDAWgBQPKssghyi47G9IritUpimqF6TN
# DDAdBgNVHQ4EFgQUdfN+UjqPPYYWLqh4zXaTNj8AfJswDgYDVR0PAQH/BAQDAgeA
# MAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwMwSgYDVR0gBEMwQTA1
# BgwrBgEEAbIxAQIBAwIwJTAjBggrBgEFBQcCARYXaHR0cHM6Ly9zZWN0aWdvLmNv
# bS9DUFMwCAYGZ4EMAQQBMEkGA1UdHwRCMEAwPqA8oDqGOGh0dHA6Ly9jcmwuc2Vj
# dGlnby5jb20vU2VjdGlnb1B1YmxpY0NvZGVTaWduaW5nQ0FSMzYuY3JsMHkGCCsG
# AQUFBwEBBG0wazBEBggrBgEFBQcwAoY4aHR0cDovL2NydC5zZWN0aWdvLmNvbS9T
# ZWN0aWdvUHVibGljQ29kZVNpZ25pbmdDQVIzNi5jcnQwIwYIKwYBBQUHMAGGF2h0
# dHA6Ly9vY3NwLnNlY3RpZ28uY29tMA0GCSqGSIb3DQEBDAUAA4IBgQBF8qhaDXok
# 5R784NqfjMsNfS97H+ItE+Sxm/QMcIhTiiIBhIYd/lLfdTwpz5aqTl5M4+FDBDeN
# m0mjY8k2Cdg+DOf4JfvZAv4tQVybhEd42E5NTfG5sWN6ruMjBLpSsjwVzvonmeUL
# SwnXY+AtVSag0MU/UnyFOTS69gTjOq3EC+H/OJa/DfI8T/sDICzTy55c5aCDHRXb
# 6Dsr+Hm7PiGCQ6c0AhYOt/etXK1+YjQo9T+FcIF0Ze34CKirIRa1FFe26gNjHdpr
# MA62TOXQJrK+x9DtVY8QCb+IUZNYj6lNiXno3t69JN6FvIU2EtPrKs8SBV2uDZQM
# ecNJ+3w77/EHod82uB73vGiOvX8Q2CkdMunz+VfXyY4Oh10AEnCqzl0UV2HHH66H
# sa8Zti+kXWH9HTUkDJCd2VHdDEOJ0o2kA1/SfETMPAO/yeFz1xXy6CIJ50dkfzuY
# gf9SsIAod1Dx9THs2qkXIwyf5lTJBvPHLRqxs/k+Mn70AUiyj50/JYMwggbsMIIE
# 1KADAgECAhAwD2+s3WaYdHypRjaneC25MA0GCSqGSIb3DQEBDAUAMIGIMQswCQYD
# VQQGEwJVUzETMBEGA1UECBMKTmV3IEplcnNleTEUMBIGA1UEBxMLSmVyc2V5IENp
# dHkxHjAcBgNVBAoTFVRoZSBVU0VSVFJVU1QgTmV0d29yazEuMCwGA1UEAxMlVVNF
# UlRydXN0IFJTQSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTAeFw0xOTA1MDIwMDAw
# MDBaFw0zODAxMTgyMzU5NTlaMH0xCzAJBgNVBAYTAkdCMRswGQYDVQQIExJHcmVh
# dGVyIE1hbmNoZXN0ZXIxEDAOBgNVBAcTB1NhbGZvcmQxGDAWBgNVBAoTD1NlY3Rp
# Z28gTGltaXRlZDElMCMGA1UEAxMcU2VjdGlnbyBSU0EgVGltZSBTdGFtcGluZyBD
# QTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMgbAa/ZLH6ImX0BmD8g
# kL2cgCFUk7nPoD5T77NawHbWGgSlzkeDtevEzEk0y/NFZbn5p2QWJgn71TJSeS7J
# Y8ITm7aGPwEFkmZvIavVcRB5h/RGKs3EWsnb111JTXJWD9zJ41OYOioe/M5YSdO/
# 8zm7uaQjQqzQFcN/nqJc1zjxFrJw06PE37PFcqwuCnf8DZRSt/wflXMkPQEovA8N
# T7ORAY5unSd1VdEXOzQhe5cBlK9/gM/REQpXhMl/VuC9RpyCvpSdv7QgsGB+uE31
# DT/b0OqFjIpWcdEtlEzIjDzTFKKcvSb/01Mgx2Bpm1gKVPQF5/0xrPnIhRfHuCkZ
# pCkvRuPd25Ffnz82Pg4wZytGtzWvlr7aTGDMqLufDRTUGMQwmHSCIc9iVrUhcxIe
# /arKCFiHd6QV6xlV/9A5VC0m7kUaOm/N14Tw1/AoxU9kgwLU++Le8bwCKPRt2ieK
# BtKWh97oaw7wW33pdmmTIBxKlyx3GSuTlZicl57rjsF4VsZEJd8GEpoGLZ8DXv2D
# olNnyrH6jaFkyYiSWcuoRsDJ8qb/fVfbEnb6ikEk1Bv8cqUUotStQxykSYtBORQD
# Hin6G6UirqXDTYLQjdprt9v3GEBXc/Bxo/tKfUU2wfeNgvq5yQ1TgH36tjlYMu9v
# GFCJ10+dM70atZ2h3pVBeqeDAgMBAAGjggFaMIIBVjAfBgNVHSMEGDAWgBRTeb9a
# qitKz1SA4dibwJ3ysgNmyzAdBgNVHQ4EFgQUGqH4YRkgD8NBd0UojtE1XwYSBFUw
# DgYDVR0PAQH/BAQDAgGGMBIGA1UdEwEB/wQIMAYBAf8CAQAwEwYDVR0lBAwwCgYI
# KwYBBQUHAwgwEQYDVR0gBAowCDAGBgRVHSAAMFAGA1UdHwRJMEcwRaBDoEGGP2h0
# dHA6Ly9jcmwudXNlcnRydXN0LmNvbS9VU0VSVHJ1c3RSU0FDZXJ0aWZpY2F0aW9u
# QXV0aG9yaXR5LmNybDB2BggrBgEFBQcBAQRqMGgwPwYIKwYBBQUHMAKGM2h0dHA6
# Ly9jcnQudXNlcnRydXN0LmNvbS9VU0VSVHJ1c3RSU0FBZGRUcnVzdENBLmNydDAl
# BggrBgEFBQcwAYYZaHR0cDovL29jc3AudXNlcnRydXN0LmNvbTANBgkqhkiG9w0B
# AQwFAAOCAgEAbVSBpTNdFuG1U4GRdd8DejILLSWEEbKw2yp9KgX1vDsn9FqguUlZ
# kClsYcu1UNviffmfAO9Aw63T4uRW+VhBz/FC5RB9/7B0H4/GXAn5M17qoBwmWFzz
# tBEP1dXD4rzVWHi/SHbhRGdtj7BDEA+N5Pk4Yr8TAcWFo0zFzLJTMJWk1vSWVgi4
# zVx/AZa+clJqO0I3fBZ4OZOTlJux3LJtQW1nzclvkD1/RXLBGyPWwlWEZuSzxWYG
# 9vPWS16toytCiiGS/qhvWiVwYoFzY16gu9jc10rTPa+DBjgSHSSHLeT8AtY+dwS8
# BDa153fLnC6NIxi5o8JHHfBd1qFzVwVomqfJN2Udvuq82EKDQwWli6YJ/9GhlKZO
# qj0J9QVst9JkWtgqIsJLnfE5XkzeSD2bNJaaCV+O/fexUpHOP4n2HKG1qXUfcb9b
# Q11lPVCBbqvw0NP8srMftpmWJvQ8eYtcZMzN7iea5aDADHKHwW5NWtMe6vBE5jJv
# HOsXTpTDeGUgOw9Bqh/poUGd/rG4oGUqNODeqPk85sEwu8CgYyz8XBYAqNDEf+oR
# nR4GxqZtMl20OAkrSQeq/eww2vGnL8+3/frQo4TZJ577AWZ3uVYQ4SBuxq6x+ba6
# yDVdM3aO8XwgDCp3rrWiAoa6Ke60WgCxjKvj+QrJVF3UuWp0nr1Irpgwggb1MIIE
# 3aADAgECAhA5TCXhfKBtJ6hl4jvZHSLUMA0GCSqGSIb3DQEBDAUAMH0xCzAJBgNV
# BAYTAkdCMRswGQYDVQQIExJHcmVhdGVyIE1hbmNoZXN0ZXIxEDAOBgNVBAcTB1Nh
# bGZvcmQxGDAWBgNVBAoTD1NlY3RpZ28gTGltaXRlZDElMCMGA1UEAxMcU2VjdGln
# byBSU0EgVGltZSBTdGFtcGluZyBDQTAeFw0yMzA1MDMwMDAwMDBaFw0zNDA4MDIy
# MzU5NTlaMGoxCzAJBgNVBAYTAkdCMRMwEQYDVQQIEwpNYW5jaGVzdGVyMRgwFgYD
# VQQKEw9TZWN0aWdvIExpbWl0ZWQxLDAqBgNVBAMMI1NlY3RpZ28gUlNBIFRpbWUg
# U3RhbXBpbmcgU2lnbmVyICM0MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKC
# AgEApJMoUkvPJ4d2pCkcmTjA5w7U0RzsaMsBZOSKzXewcWWCvJ/8i7u7lZj7JRGO
# WogJZhEUWLK6Ilvm9jLxXS3AeqIO4OBWZO2h5YEgciBkQWzHwwj6831d7yGawn7X
# LMO6EZge/NMgCEKzX79/iFgyqzCz2Ix6lkoZE1ys/Oer6RwWLrCwOJVKz4VQq2cD
# JaG7OOkPb6lampEoEzW5H/M94STIa7GZ6A3vu03lPYxUA5HQ/C3PVTM4egkcB9Ei
# 4GOGp7790oNzEhSbmkwJRr00vOFLUHty4Fv9GbsfPGoZe267LUQqvjxMzKyKBJPG
# V4agczYrgZf6G5t+iIfYUnmJ/m53N9e7UJ/6GCVPE/JefKmxIFopq6NCh3fg9EwC
# SN1YpVOmo6DtGZZlFSnF7TMwJeaWg4Ga9mBmkFgHgM1Cdaz7tJHQxd0BQGq2qBDu
# 9o16t551r9OlSxihDJ9XsF4lR5F0zXUS0Zxv5F4Nm+x1Ju7+0/WSL1KF6NpEUSqi
# zADKh2ZDoxsA76K1lp1irScL8htKycOUQjeIIISoh67DuiNye/hU7/hrJ7CF9adD
# hdgrOXTbWncC0aT69c2cPcwfrlHQe2zYHS0RQlNxdMLlNaotUhLZJc/w09CRQxLX
# Mn2YbON3Qcj/HyRU726txj5Ve/Fchzpk8WBLBU/vuS/sCRMCAwEAAaOCAYIwggF+
# MB8GA1UdIwQYMBaAFBqh+GEZIA/DQXdFKI7RNV8GEgRVMB0GA1UdDgQWBBQDDzHI
# kSqTvWPz0V1NpDQP0pUBGDAOBgNVHQ8BAf8EBAMCBsAwDAYDVR0TAQH/BAIwADAW
# BgNVHSUBAf8EDDAKBggrBgEFBQcDCDBKBgNVHSAEQzBBMDUGDCsGAQQBsjEBAgED
# CDAlMCMGCCsGAQUFBwIBFhdodHRwczovL3NlY3RpZ28uY29tL0NQUzAIBgZngQwB
# BAIwRAYDVR0fBD0wOzA5oDegNYYzaHR0cDovL2NybC5zZWN0aWdvLmNvbS9TZWN0
# aWdvUlNBVGltZVN0YW1waW5nQ0EuY3JsMHQGCCsGAQUFBwEBBGgwZjA/BggrBgEF
# BQcwAoYzaHR0cDovL2NydC5zZWN0aWdvLmNvbS9TZWN0aWdvUlNBVGltZVN0YW1w
# aW5nQ0EuY3J0MCMGCCsGAQUFBzABhhdodHRwOi8vb2NzcC5zZWN0aWdvLmNvbTAN
# BgkqhkiG9w0BAQwFAAOCAgEATJtlWPrgec/vFcMybd4zket3WOLrvctKPHXefpRt
# wyLHBJXfZWlhEwz2DJ71iSBewYfHAyTKx6XwJt/4+DFlDeDrbVFXpoyEUghGHCrC
# 3vLaikXzvvf2LsR+7fjtaL96VkjpYeWaOXe8vrqRZIh1/12FFjQn0inL/+0t2v++
# kwzsbaINzMPxbr0hkRojAFKtl9RieCqEeajXPawhj3DDJHk6l/ENo6NbU9irALpY
# +zWAT18ocWwZXsKDcpCu4MbY8pn76rSSZXwHfDVEHa1YGGti+95sxAqpbNMhRnDc
# L411TCPCQdB6ljvDS93NkiZ0dlw3oJoknk5fTtOPD+UTT1lEZUtDZM9I+GdnuU2/
# zA2xOjDQoT1IrXpl5Ozf4AHwsypKOazBpPmpfTXQMkCgsRkqGCGyyH0FcRpLJzaq
# 4Jgcg3Xnx35LhEPNQ/uQl3YqEqxAwXBbmQpA+oBtlGF7yG65yGdnJFxQjQEg3gf3
# AdT4LhHNnYPl+MolHEQ9J+WwhkcqCxuEdn17aE+Nt/cTtO2gLe5zD9kQup2ZLHzX
# dR+PEMSU5n4k5ZVKiIwn1oVmHfmuZHaR6Ej+yFUK7SnDH944psAU+zI9+KmDYjbI
# w74Ahxyr+kpCHIkD3PVcfHDZXXhO7p9eIOYJanwrCKNI9RX8BE/fzSEceuX1jhrU
# uUAxggZpMIIGZQIBATBoMFQxCzAJBgNVBAYTAkdCMRgwFgYDVQQKEw9TZWN0aWdv
# IExpbWl0ZWQxKzApBgNVBAMTIlNlY3RpZ28gUHVibGljIENvZGUgU2lnbmluZyBD
# QSBSMzYCEBHhoIZkh66CYIKNKPBResYwDQYJYIZIAWUDBAIBBQCggYQwGAYKKwYB
# BAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAc
# BgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgWqkw
# BqyBB6TQRLawcNes39ihl5LKFaMDAE/5i/hHQ9QwDQYJKoZIhvcNAQEBBQAEggIA
# gYf6ruY33Zt4HtUG1CsfMUB70JHwJGXXaWC24eyfe37Gdy6n1zGEYVlBqE6LBdsp
# ickKlHHUDUPxDP26iIXhhMNtRwiDJ5j2Fea1PvIjz8KolwllE8Ui2D4I1143pnL6
# 0KfwA/BNCCmN/vmmon/+MaoUyVtkLHwc3kYXQcCVZNKtIiJk/EALk0tfmN+P7zaY
# 7v1lLOvRFxYmWngE4b6M+DXwNngYirF/opq6vw1NlQzkWuBPx3NHKEztB+AWjS4l
# GN2fNgXioaoVpRd2ix6hE4TD24sQV2KEn6N3xtPiDT8fkNjGsQSimfH7YN6445l4
# EnxHhR6YpaFTD9tyYdlXRc8wQbOMsSn+PY2fxewOgWk59d3R8A2EyomzkiR46bkX
# 9ATWJurjV+RyMNQJlxPNRyT9UA/CnzS32YT2aHpmOusto0cY6iqRqrLN7Y1LCrp1
# Tx/TpR7gGu9EBPPBivBIFEhihr2DFJoLSS9T47UCygiHeE511wMCHl7A0a26atyo
# k2ekwRXc79vgJp7jp8Lrar+3xU1RRjUFksaCQQewtQ75DlnP2egdjHK4AIFEiffS
# hB/cvqsuWo4IgH7jZ4LfqcgfV6ULkY9L5don6BPkIoPAF6Nz7IqtkVo2DlweMP4U
# SPsujAvgo5IrzbsC0z/wmUuOzyUJIrwlc5E5C71io2ihggNLMIIDRwYJKoZIhvcN
# AQkGMYIDODCCAzQCAQEwgZEwfTELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0
# ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEYMBYGA1UEChMPU2VjdGln
# byBMaW1pdGVkMSUwIwYDVQQDExxTZWN0aWdvIFJTQSBUaW1lIFN0YW1waW5nIENB
# AhA5TCXhfKBtJ6hl4jvZHSLUMA0GCWCGSAFlAwQCAgUAoHkwGAYJKoZIhvcNAQkD
# MQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjMwOTE0MjAyMzIxWjA/Bgkq
# hkiG9w0BCQQxMgQw1/AB11KDL+AwRdPIxVRC95IR5TPM6+wc0sdLnN3P6HljEYgj
# ALBme2Xr/r7I8rJUMA0GCSqGSIb3DQEBAQUABIICAHCf1JUncAQblIDTII53SMC/
# q+niEFNDgtM8eCI6r4tg2S5aNMBD7Ipve85XYe8eMM6Au3np4Mzpt/Q0rJa4xbOy
# ARNccdv5ACAiK5MF2krSCH4aH5c2TnBk1XudLsH5uW3kxOrNQTVQa3Ci0lCSC22f
# D5VQKYvtQlv8t2Mxkjc3dgmSvHE6e6meIYNDco+HyCKT+05HfHQsRDVT/jQg9q+9
# bZsMkb5vYKqMZZLD7b66/6GWopt3k1SkNaBuddWvhAcJhXmrxf8SF6tnTSyN4hnk
# v8Ziwc+uxaLkPYxKpm/Ktp+Sws9mmUBppZ8yhQq107SPuF8EGq85AE7yeKUGOGeF
# UI5Z8i2VLS9l/UgCWYnrZhQoObAtZ6/FJY8TnkFAUq91Lu+EgSGVRArf14q5y3ui
# 65w9dRra6IgEpjYmE6SVSWBZkORTM9eaWgM0iWGoFFiKpo2hoPETzQdZUtpqachp
# jrQzJ0T8Kfhr/SzZRy86QbqqAMXmLOi6GxxqLYSf/hUFy/c9uGFkOacVFasRcbF3
# FHYLtWcDc36pccAu3/kqNTW5AMAiPhj/7dOVVZC0wS1bi9zmXiV/KB3Bf9MWAPV8
# uVhabiFCSx7NCY+t5EDMXx/pDb0CFd1lPI8NYingwGtM5/SG/JdSo4aMpZh8TwFL
# UPOQ1PbHZsonfaB4FFoJ
# SIG # End signature block
