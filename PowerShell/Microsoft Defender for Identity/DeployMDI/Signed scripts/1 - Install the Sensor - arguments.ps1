<#	
	.NOTES
	===========================================================================
	 Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2022 v5.8.213
	 Created on:   	18-01-2024 19:23
	 Created by:   	Michael Morten Sonne
	 Organization: 	Sonne´s Cloud
	 Filename:     	"1 - Install the Sensor - arguments.ps1"
	 Version:		1.0
	===========================================================================
	.DESCRIPTION
        This script will install the sensor on the host and ask for the access key.

    .EXAMPLE
        .\"1 - Install the Sensor - arguments.ps1" -AccessKey 'YourAccessKey' -UseProxy -ProxyUrl 'YourProxyUrl' -ProxyUserName 'YourProxyUsername' -ProxyUserPassword 'YourProxyPassword'
#>

param (
    [string]$InstallerPath = ".\Azure ATP sensor Setup.exe",
    [string]$AccessKey,
    [switch]$UseProxy,
    [string]$ProxyUrl,
    [string]$ProxyUserName,
    [string]$ProxyUserPassword # Needs to be a SecureString, but fails when using [SecureString]$ProxyUserPassword... TODO: Fix this
)

# Check if the installer exists
Write-Host "Checking if '$InstallerPath' exists in the current folder..." -ForegroundColor Yellow
if (Test-Path $InstallerPath -PathType Leaf) {
    # Confirm that the installer exists
    Write-Host "'$InstallerPath' found in the current folder." -ForegroundColor Green

    # Make AccessKey mandatory
    if (-not $AccessKey) {
        throw "Error: AccessKey is mandatory. Please provide a valid AccessKey."
    }

    # Check if the user wants to use a proxy
    if ($UseProxy) {
        # Check if the proxy settings are complete and not empty
        if ([string]::IsNullOrWhiteSpace($ProxyUrl) -or [string]::IsNullOrWhiteSpace($ProxyUserName) -or -not $ProxyUserPassword) {
            Write-Host "Error: Proxy settings are incomplete. Please provide all proxy details (ProxyUrl, ProxyUsername, and ProxyPassword)." -ForegroundColor Red
            return
        }
        else {
            # Convert the plain text password to a SecureString
            $SecureProxyUserPassword = ConvertTo-SecureString -String $ProxyUserPassword -AsPlainText -Force
            # Clear the plain text password from memory
            $ProxyUserPassword = $null

            # Confirm the entered proxy settings
            Write-Host "Entered Proxy Settings:" -ForegroundColor Yellow
            Write-Host "Proxy URL: $ProxyUrl"
            Write-Host "Proxy Username: $ProxyUserName"
            Write-Host "Proxy Password: Not shown for security reasons."

            # Proxy arguments for the installer confirmed by the user
            Write-Host "Proxy settings confirmed. Continuing with the installation process." -ForegroundColor Green

            # Construct the proxy arguments
            $ProxyArguments = "/ProxyUrl=`"$ProxyUrl`" /ProxyUserName=`"$ProxyUserName`" /ProxyUserPassword=`"$SecureProxyUserPassword`""
        }
    }

    # Construct the argument list dynamically based on whether a proxy is used
    $ArgumentList = @('/quiet', 'NetFrameworkCommandLineArguments="/q"', "AccessKey=`"$AccessKey`"")
    if ($ProxyArguments) {
        $ArgumentList += $ProxyArguments
    }

    # Start the installation process
    Write-Host "Starting installation process..."  -ForegroundColor Yellow
    $Process = Start-Process -FilePath $InstallerPath -ArgumentList $ArgumentList -PassThru -Wait

    if ($Process.ExitCode -eq 0) {
        Write-Host "Installation completed successfully." -ForegroundColor Green
    } else {
        Write-Host "Installation failed with exit code $($Process.ExitCode)." -ForegroundColor Red
    }
} else {
    Write-Host "Error: '$InstallerPath' not found in the current folder." -ForegroundColor Red
}

# Script completed
Write-host "Script completed."
# SIG # Begin signature block
# MIIo7QYJKoZIhvcNAQcCoIIo3jCCKNoCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDJC+7p+q9fw/tf
# lJ7uis9nAYJcgaMNKe9IPzhS79XKeqCCEd8wggVvMIIEV6ADAgECAhBI/JO0YFWU
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
# gf9SsIAod1Dx9THs2qkXIwyf5lTJBvPHLRqxs/k+Mn70AUiyj50/JYMxghZkMIIW
# YAIBATBoMFQxCzAJBgNVBAYTAkdCMRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQx
# KzApBgNVBAMTIlNlY3RpZ28gUHVibGljIENvZGUgU2lnbmluZyBDQSBSMzYCEBHh
# oIZkh66CYIKNKPBResYwDQYJYIZIAWUDBAIBBQCgfDAQBgorBgEEAYI3AgEMMQIw
# ADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYK
# KwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgBlo2s5IcAMuxs4Xjm9z+46aGpXQ0
# kFczh8g/aE4skncwDQYJKoZIhvcNAQEBBQAEggIAfyKswnStiQdc0BrnP21aCXQe
# EH8nSI14mjSEnPAMaWWK6xG5HSzsifrxFTYcbtxzlFCAABV1quh51ksNEcEXVQtf
# HFt4AJ4Jz5a9KYJ+yQeSaZy5Q6WKzQ0xF1E+TF2sG4MjKJaiBFlv64gvncEkJDTN
# 3RizhppozC9GG34FPZagV+kY1CxvwM1nfAgBQJNMyvHuRLh/g4fQdUj1fL7Hjh2b
# 0IW1dPP3V9aVVN4FQsmKMLvo1kv9GF7Gd+eGNLfGqs9YmGgbzNDig99eRASd2q9J
# tcGEw8g9uril1LPbEG55UpQ2JXkTPQPacZ634raVXi6tmt3GuEPzYNC9Q5XM+ae4
# EEdR3nf1JRRsihCW9zEaaZV8YM1ER6O8auwjCdBpvk04Xa0Q00M9DUYvHljpmsuX
# eP3dJIfXZgnuh5RocbFH89EqgpbrpxG1LQKNmzk0UImmPtzAJXPQH3OlYUqMYxxh
# FsuO7W87oL0m5QWQQVZtxjYD/CQLOMRGUmqx0I3Z3pja0RgO/3X6VyKufSYAsTwm
# dxpsYa+skZx5cN1i67JUvuvpbmdW6wZg37QRTl68O0++ISRPvBwryoG5XYYWx1ny
# 4KrRO1x72fgx9ufZACFANYskG5SDDCyumGrz9YuqFDDnsuTVFBJF4vbY/iGFUVpX
# 5t1J8yZn/4PWCa/zvCGhghNPMIITSwYKKwYBBAGCNwMDATGCEzswghM3BgkqhkiG
# 9w0BBwKgghMoMIITJAIBAzEPMA0GCWCGSAFlAwQCAgUAMIHwBgsqhkiG9w0BCRAB
# BKCB4ASB3TCB2gIBAQYKKwYBBAGyMQIBATAxMA0GCWCGSAFlAwQCAQUABCB525rB
# fdZKhwhbZAh/wTkX9O/yWJpuQO+lVg3ZuFE1OwIVAIbQ683G/jtHk+MOJ+zZA2Ua
# WYXdGA8yMDI0MDEyMDExMTAxNlqgbqRsMGoxCzAJBgNVBAYTAkdCMRMwEQYDVQQI
# EwpNYW5jaGVzdGVyMRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQxLDAqBgNVBAMM
# I1NlY3RpZ28gUlNBIFRpbWUgU3RhbXBpbmcgU2lnbmVyICM0oIIN6TCCBvUwggTd
# oAMCAQICEDlMJeF8oG0nqGXiO9kdItQwDQYJKoZIhvcNAQEMBQAwfTELMAkGA1UE
# BhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBxMHU2Fs
# Zm9yZDEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMSUwIwYDVQQDExxTZWN0aWdv
# IFJTQSBUaW1lIFN0YW1waW5nIENBMB4XDTIzMDUwMzAwMDAwMFoXDTM0MDgwMjIz
# NTk1OVowajELMAkGA1UEBhMCR0IxEzARBgNVBAgTCk1hbmNoZXN0ZXIxGDAWBgNV
# BAoTD1NlY3RpZ28gTGltaXRlZDEsMCoGA1UEAwwjU2VjdGlnbyBSU0EgVGltZSBT
# dGFtcGluZyBTaWduZXIgIzQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoIC
# AQCkkyhSS88nh3akKRyZOMDnDtTRHOxoywFk5IrNd7BxZYK8n/yLu7uVmPslEY5a
# iAlmERRYsroiW+b2MvFdLcB6og7g4FZk7aHlgSByIGRBbMfDCPrzfV3vIZrCftcs
# w7oRmB780yAIQrNfv3+IWDKrMLPYjHqWShkTXKz856vpHBYusLA4lUrPhVCrZwMl
# obs46Q9vqVqakSgTNbkf8z3hJMhrsZnoDe+7TeU9jFQDkdD8Lc9VMzh6CRwH0SLg
# Y4anvv3Sg3MSFJuaTAlGvTS84UtQe3LgW/0Zux88ahl7brstRCq+PEzMrIoEk8ZX
# hqBzNiuBl/obm36Ih9hSeYn+bnc317tQn/oYJU8T8l58qbEgWimro0KHd+D0TAJI
# 3VilU6ajoO0ZlmUVKcXtMzAl5paDgZr2YGaQWAeAzUJ1rPu0kdDF3QFAaraoEO72
# jXq3nnWv06VLGKEMn1ewXiVHkXTNdRLRnG/kXg2b7HUm7v7T9ZIvUoXo2kRRKqLM
# AMqHZkOjGwDvorWWnWKtJwvyG0rJw5RCN4gghKiHrsO6I3J7+FTv+GsnsIX1p0OF
# 2Cs5dNtadwLRpPr1zZw9zB+uUdB7bNgdLRFCU3F0wuU1qi1SEtklz/DT0JFDEtcy
# fZhs43dByP8fJFTvbq3GPlV78VyHOmTxYEsFT++5L+wJEwIDAQABo4IBgjCCAX4w
# HwYDVR0jBBgwFoAUGqH4YRkgD8NBd0UojtE1XwYSBFUwHQYDVR0OBBYEFAMPMciR
# KpO9Y/PRXU2kNA/SlQEYMA4GA1UdDwEB/wQEAwIGwDAMBgNVHRMBAf8EAjAAMBYG
# A1UdJQEB/wQMMAoGCCsGAQUFBwMIMEoGA1UdIARDMEEwNQYMKwYBBAGyMQECAQMI
# MCUwIwYIKwYBBQUHAgEWF2h0dHBzOi8vc2VjdGlnby5jb20vQ1BTMAgGBmeBDAEE
# AjBEBgNVHR8EPTA7MDmgN6A1hjNodHRwOi8vY3JsLnNlY3RpZ28uY29tL1NlY3Rp
# Z29SU0FUaW1lU3RhbXBpbmdDQS5jcmwwdAYIKwYBBQUHAQEEaDBmMD8GCCsGAQUF
# BzAChjNodHRwOi8vY3J0LnNlY3RpZ28uY29tL1NlY3RpZ29SU0FUaW1lU3RhbXBp
# bmdDQS5jcnQwIwYIKwYBBQUHMAGGF2h0dHA6Ly9vY3NwLnNlY3RpZ28uY29tMA0G
# CSqGSIb3DQEBDAUAA4ICAQBMm2VY+uB5z+8VwzJt3jOR63dY4uu9y0o8dd5+lG3D
# IscEld9laWETDPYMnvWJIF7Bh8cDJMrHpfAm3/j4MWUN4OttUVemjIRSCEYcKsLe
# 8tqKRfO+9/YuxH7t+O1ov3pWSOlh5Zo5d7y+upFkiHX/XYUWNCfSKcv/7S3a/76T
# DOxtog3Mw/FuvSGRGiMAUq2X1GJ4KoR5qNc9rCGPcMMkeTqX8Q2jo1tT2KsAulj7
# NYBPXyhxbBlewoNykK7gxtjymfvqtJJlfAd8NUQdrVgYa2L73mzECqls0yFGcNwv
# jXVMI8JB0HqWO8NL3c2SJnR2XDegmiSeTl9O048P5RNPWURlS0Nkz0j4Z2e5Tb/M
# DbE6MNChPUitemXk7N/gAfCzKko5rMGk+al9NdAyQKCxGSoYIbLIfQVxGksnNqrg
# mByDdefHfkuEQ81D+5CXdioSrEDBcFuZCkD6gG2UYXvIbrnIZ2ckXFCNASDeB/cB
# 1PguEc2dg+X4yiUcRD0n5bCGRyoLG4R2fXtoT4239xO07aAt7nMP2RC6nZksfNd1
# H48QxJTmfiTllUqIjCfWhWYd+a5kdpHoSP7IVQrtKcMf3jimwBT7Mj34qYNiNsjD
# vgCHHKv6SkIciQPc9Vx8cNldeE7un14g5glqfCsIo0j1FfwET9/NIRx65fWOGtS5
# QDCCBuwwggTUoAMCAQICEDAPb6zdZph0fKlGNqd4LbkwDQYJKoZIhvcNAQEMBQAw
# gYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpOZXcgSmVyc2V5MRQwEgYDVQQHEwtK
# ZXJzZXkgQ2l0eTEeMBwGA1UEChMVVGhlIFVTRVJUUlVTVCBOZXR3b3JrMS4wLAYD
# VQQDEyVVU0VSVHJ1c3QgUlNBIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MB4XDTE5
# MDUwMjAwMDAwMFoXDTM4MDExODIzNTk1OVowfTELMAkGA1UEBhMCR0IxGzAZBgNV
# BAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEYMBYGA1UE
# ChMPU2VjdGlnbyBMaW1pdGVkMSUwIwYDVQQDExxTZWN0aWdvIFJTQSBUaW1lIFN0
# YW1waW5nIENBMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAyBsBr9ks
# foiZfQGYPyCQvZyAIVSTuc+gPlPvs1rAdtYaBKXOR4O168TMSTTL80VlufmnZBYm
# CfvVMlJ5LsljwhObtoY/AQWSZm8hq9VxEHmH9EYqzcRaydvXXUlNclYP3MnjU5g6
# Kh78zlhJ07/zObu5pCNCrNAVw3+eolzXOPEWsnDTo8Tfs8VyrC4Kd/wNlFK3/B+V
# cyQ9ASi8Dw1Ps5EBjm6dJ3VV0Rc7NCF7lwGUr3+Az9ERCleEyX9W4L1GnIK+lJ2/
# tCCwYH64TfUNP9vQ6oWMilZx0S2UTMiMPNMUopy9Jv/TUyDHYGmbWApU9AXn/TGs
# +ciFF8e4KRmkKS9G493bkV+fPzY+DjBnK0a3Na+WvtpMYMyou58NFNQYxDCYdIIh
# z2JWtSFzEh79qsoIWId3pBXrGVX/0DlULSbuRRo6b83XhPDX8CjFT2SDAtT74t7x
# vAIo9G3aJ4oG0paH3uhrDvBbfel2aZMgHEqXLHcZK5OVmJyXnuuOwXhWxkQl3wYS
# mgYtnwNe/YOiU2fKsfqNoWTJiJJZy6hGwMnypv99V9sSdvqKQSTUG/xypRSi1K1D
# HKRJi0E5FAMeKfobpSKupcNNgtCN2mu32/cYQFdz8HGj+0p9RTbB942C+rnJDVOA
# ffq2OVgy728YUInXT50zvRq1naHelUF6p4MCAwEAAaOCAVowggFWMB8GA1UdIwQY
# MBaAFFN5v1qqK0rPVIDh2JvAnfKyA2bLMB0GA1UdDgQWBBQaofhhGSAPw0F3RSiO
# 0TVfBhIEVTAOBgNVHQ8BAf8EBAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIBADATBgNV
# HSUEDDAKBggrBgEFBQcDCDARBgNVHSAECjAIMAYGBFUdIAAwUAYDVR0fBEkwRzBF
# oEOgQYY/aHR0cDovL2NybC51c2VydHJ1c3QuY29tL1VTRVJUcnVzdFJTQUNlcnRp
# ZmljYXRpb25BdXRob3JpdHkuY3JsMHYGCCsGAQUFBwEBBGowaDA/BggrBgEFBQcw
# AoYzaHR0cDovL2NydC51c2VydHJ1c3QuY29tL1VTRVJUcnVzdFJTQUFkZFRydXN0
# Q0EuY3J0MCUGCCsGAQUFBzABhhlodHRwOi8vb2NzcC51c2VydHJ1c3QuY29tMA0G
# CSqGSIb3DQEBDAUAA4ICAQBtVIGlM10W4bVTgZF13wN6MgstJYQRsrDbKn0qBfW8
# Oyf0WqC5SVmQKWxhy7VQ2+J9+Z8A70DDrdPi5Fb5WEHP8ULlEH3/sHQfj8ZcCfkz
# XuqgHCZYXPO0EQ/V1cPivNVYeL9IduFEZ22PsEMQD43k+ThivxMBxYWjTMXMslMw
# laTW9JZWCLjNXH8Blr5yUmo7Qjd8Fng5k5OUm7Hcsm1BbWfNyW+QPX9FcsEbI9bC
# VYRm5LPFZgb289ZLXq2jK0KKIZL+qG9aJXBigXNjXqC72NzXStM9r4MGOBIdJIct
# 5PwC1j53BLwENrXnd8ucLo0jGLmjwkcd8F3WoXNXBWiap8k3ZR2+6rzYQoNDBaWL
# pgn/0aGUpk6qPQn1BWy30mRa2Coiwkud8TleTN5IPZs0lpoJX47997FSkc4/ifYc
# obWpdR9xv1tDXWU9UIFuq/DQ0/yysx+2mZYm9Dx5i1xkzM3uJ5rloMAMcofBbk1a
# 0x7q8ETmMm8c6xdOlMN4ZSA7D0GqH+mhQZ3+sbigZSo04N6o+TzmwTC7wKBjLPxc
# FgCo0MR/6hGdHgbGpm0yXbQ4CStJB6r97DDa8acvz7f9+tCjhNknnvsBZne5VhDh
# IG7GrrH5trrINV0zdo7xfCAMKneutaIChrop7rRaALGMq+P5CslUXdS5anSevUiu
# mDGCBCwwggQoAgEBMIGRMH0xCzAJBgNVBAYTAkdCMRswGQYDVQQIExJHcmVhdGVy
# IE1hbmNoZXN0ZXIxEDAOBgNVBAcTB1NhbGZvcmQxGDAWBgNVBAoTD1NlY3RpZ28g
# TGltaXRlZDElMCMGA1UEAxMcU2VjdGlnbyBSU0EgVGltZSBTdGFtcGluZyBDQQIQ
# OUwl4XygbSeoZeI72R0i1DANBglghkgBZQMEAgIFAKCCAWswGgYJKoZIhvcNAQkD
# MQ0GCyqGSIb3DQEJEAEEMBwGCSqGSIb3DQEJBTEPFw0yNDAxMjAxMTEwMTZaMD8G
# CSqGSIb3DQEJBDEyBDBLPfpk9QnKvrljz66V3XcblToNy/BIXhCsA+6ll5lli5bu
# apaEiOWSuEoN9TWTeU8wge0GCyqGSIb3DQEJEAIMMYHdMIHaMIHXMBYEFK5ir3UK
# DL1H1kYfdWjivIznyk+UMIG8BBQC1luV4oNwwVcAlfqI+SPdk3+tjzCBozCBjqSB
# izCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCk5ldyBKZXJzZXkxFDASBgNVBAcT
# C0plcnNleSBDaXR5MR4wHAYDVQQKExVUaGUgVVNFUlRSVVNUIE5ldHdvcmsxLjAs
# BgNVBAMTJVVTRVJUcnVzdCBSU0EgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkCEDAP
# b6zdZph0fKlGNqd4LbkwDQYJKoZIhvcNAQEBBQAEggIAbVRaFcnvXY/o8MNBEhVq
# Czx6Laj6FVAKLY8ha3iqErGUnR54iSuFoguZSuwuPSnBXMzTH1qIYHHlBEKCk++M
# 6iHECvfzTBiAvb4g/xutqq/ifxc6a2/ilCs/eaUm5pvGonrqGDlh3Xe3wKB+Wfns
# I7lzUDcf6A49uymy6MKKvPT4IG0BMHrA0Xb6kd8xnwk6J9loIkqQ4/Wd9wfZb7Yo
# R1eJAfegBLMEqd3WxD62juapgJM5ZReCnx5Ghub+UzhUqmYnt1cICiBSUmOQrQ+a
# ZrM5YKk0Jje2mT8sz3EXelh2WQmE3/cVj6rLu4ekfZEhpfYbC7Lt1xTECNoSmoQg
# xej2LSPtdcuBHsYV1fkgpeGgTqseWuWhNWP3Qj+SGgDEMF3TCHqX854q2R56ITdZ
# M8HCQZ+Eyjgr5cl7miqyFGAcI1o5AxxXA30vG8ghcnx16pDe2DLnSOyZYO/iqanc
# d24QdKYgM8hSH2dnVEfjte8DaBN5XxepVFKdDmQTCsXMFufmDCm3ETLuLWtKa1RI
# yuRF/r9NRukrRAepR3lgkcyzijgIQJT+8AZKrxww5Jk3+69K1bFHK6PzogqS2d1W
# XURBgiRm5fTmjr9WIzsaHZAh7d706WpEwDkiwVhZx/jHZaYFG4YhNeZfIsmTsQXP
# KO0KWctf4+MPhRkjiSs8AGI=
# SIG # End signature block
