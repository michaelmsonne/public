<#	
	.NOTES
	===========================================================================
	 Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2022 v5.8.213
	 Created on:   	17-05-2024 19:21
	 Created by:   	Michael Morten Sonne
	 Organization: 	Sonne´s Cloud
	 Blog:          https://blog.sonnes.cloud
	 GitHub:        https://github.com/michaelmsonne
	 Filename:     	'Veeam-FixTeamsBackupError.ps1'
	===========================================================================
	.DESCRIPTION
		PowerShell script to fix Veeam Backup for Microsoft 365 error "Processing mailbox user@domain.com failed with error: Failed to get folder properties. Not allowed to access Non IPM folder."
        by adding the SkipTeamsMessagesDataFolders setting to the Config.xml file and restarting the Veeam Archiver Service.

    .REQUREMENT
        - Veeam Backup for Microsoft 365 v6 or later
        - PowerShell 5.1 or later
        - Run script with elevated privileges
        - Backup original Config.xml file before running the script

    .CHANGELOG
        17-05-2024 - Michael Morten Sonne - Initial release

    .EXAMPLE
        PS> Veeam-FixTeamsBackupError.ps1

    .CHANGELOG
        17-05-2024 - Michael Morten Sonne - Initial release
#>

$configFilePath = "C:\ProgramData\Veeam\Backup365\Config.xml"

try {
    # Load XML content from Config.xml
    $xmlContent = [xml](Get-Content $configFilePath)

    # Check if SkipTeamsMessagesDataFolders setting already exists
    if ($xmlContent.SelectSingleNode("//Archiver/Proxy[@SkipTeamsMessagesDataFolders='True']")) {
        Write-Output "The 'SkipTeamsMessagesDataFolders' setting already exists. No changes were made!"
    } else {
        # Backup the original Config.xml file
        $backupFilePath = "$configFilePath$($(Get-Date -Format '.ddMMyyyy')).old"
        Copy-Item -Path $configFilePath -Destination $backupFilePath -ErrorAction Stop

        # Verify that the backup was created successfully
        if (Test-Path -Path $backupFilePath) {
            Write-Output "Backup created successfully at $backupFilePath."

            # Create a new Proxy element and set attributes
            $newElement = $xmlContent.CreateElement("Proxy")
            $newElement.SetAttribute("SkipTeamsMessagesDataFolders", "True")

            # Append the new element to the Archiver node
            $archiverNode = $xmlContent.SelectSingleNode("//Archiver")
            $archiverNode.AppendChild($newElement)

            # Save changes to Config.xml
            $xmlContent.Save($configFilePath)
            Write-Output "The 'SkipTeamsMessagesDataFolders' setting has been added."

            # Restart the Veeam Archiver Service
            Restart-Service -Name "Veeam.Archiver.Service" -ErrorAction Stop
        } else {
            Write-Error "Failed to create a backup of the Config.xml file. Changes will not be made."
        }
    }
}
catch {
    Write-Error "An error occurred: $_"
}
finally {
    Write-Output "Process completed. Please verify the changes and ensure services are ready for backup again."
}
# SIG # Begin signature block
# MIIo7AYJKoZIhvcNAQcCoIIo3TCCKNkCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBnM4fhWSi1HY8C
# H2Ihbar+XZxff7crG2TMdJ9FGDXv1KCCEd8wggVvMIIEV6ADAgECAhBI/JO0YFWU
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
# gf9SsIAod1Dx9THs2qkXIwyf5lTJBvPHLRqxs/k+Mn70AUiyj50/JYMxghZjMIIW
# XwIBATBoMFQxCzAJBgNVBAYTAkdCMRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQx
# KzApBgNVBAMTIlNlY3RpZ28gUHVibGljIENvZGUgU2lnbmluZyBDQSBSMzYCEBHh
# oIZkh66CYIKNKPBResYwDQYJYIZIAWUDBAIBBQCgfDAQBgorBgEEAYI3AgEMMQIw
# ADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYK
# KwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgxcuk/ZtyoyFQOkP3EqMv37C48nt8
# zQdSmvEkpEsNr2UwDQYJKoZIhvcNAQEBBQAEggIAmqoNJG8MiWZm2xxCjLr208t5
# +dYpSuKGSWwy84BrExllIaZA+FrUcPu6xE2QIt7LEmjNqNZ62Pz+uo0TTH8nuo61
# 8F21Q2/bTWqFpT93ibbWozNvQN7QgIp8l7mZDS3LFSYfkjmFY64iYRB5dyQJFKWT
# EPFiaQEhbF7VQfOtHVynbq4XHa4WCtJPd5WxTwtpyVb0ZF81KwOXg9PFZs17E82G
# sNnCpaFLJ9/+OA9BtWzJ2z/B6YZb20m3e8Ag0Yvix8ZGfAzjqQI+EaEEhy/rOEXU
# ARx1F2TogYiZSoxXbcjip5tjP1JwzEmA1S5RNcndEjfSJGxUPbqHSTDRZC9R/zOr
# N7jWeI+D2owhp85kV5tVdSIYa5EVXDJceCmzmvGeBKpC2AHBbneAApbsJPlZtZBo
# gglACzfh7ketbZo6nfPXyc9g7pOiz5Wr6Hb7z26IHaJeEHTfhhdAZlfoxUAalSqO
# TfVtdogql4hnS/v36DyXhH8tDUF+qfVMRTz3QSbI4YCNv8s0gcW0H8wFI3tjlKop
# U96QleYfHQOJNYWLTh2vIPeRQ1IOvhbliQQIM4EYnByuMrYtDL/VPcPGbZFqqBrG
# zMZXwQzXh/muylF+ZJYKEAwAsExwQFn6d23zLmwA6BR9D3ELmlcySjw0ptHBiUih
# 9/NzzeT5EMQDTvskCamhghNOMIITSgYKKwYBBAGCNwMDATGCEzowghM2BgkqhkiG
# 9w0BBwKgghMnMIITIwIBAzEPMA0GCWCGSAFlAwQCAgUAMIHvBgsqhkiG9w0BCRAB
# BKCB3wSB3DCB2QIBAQYKKwYBBAGyMQIBATAxMA0GCWCGSAFlAwQCAQUABCCrLL7U
# ABbQYtGqjFZhRFsNl1Wb8F31yePyHcza02LLTgIUfx7pTaSwY6cRBsve/PBwAgdp
# E7QYDzIwMjQwNjI5MDkzNDMyWqBupGwwajELMAkGA1UEBhMCR0IxEzARBgNVBAgT
# Ck1hbmNoZXN0ZXIxGDAWBgNVBAoTD1NlY3RpZ28gTGltaXRlZDEsMCoGA1UEAwwj
# U2VjdGlnbyBSU0EgVGltZSBTdGFtcGluZyBTaWduZXIgIzSggg3pMIIG9TCCBN2g
# AwIBAgIQOUwl4XygbSeoZeI72R0i1DANBgkqhkiG9w0BAQwFADB9MQswCQYDVQQG
# EwJHQjEbMBkGA1UECBMSR3JlYXRlciBNYW5jaGVzdGVyMRAwDgYDVQQHEwdTYWxm
# b3JkMRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQxJTAjBgNVBAMTHFNlY3RpZ28g
# UlNBIFRpbWUgU3RhbXBpbmcgQ0EwHhcNMjMwNTAzMDAwMDAwWhcNMzQwODAyMjM1
# OTU5WjBqMQswCQYDVQQGEwJHQjETMBEGA1UECBMKTWFuY2hlc3RlcjEYMBYGA1UE
# ChMPU2VjdGlnbyBMaW1pdGVkMSwwKgYDVQQDDCNTZWN0aWdvIFJTQSBUaW1lIFN0
# YW1waW5nIFNpZ25lciAjNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB
# AKSTKFJLzyeHdqQpHJk4wOcO1NEc7GjLAWTkis13sHFlgryf/Iu7u5WY+yURjlqI
# CWYRFFiyuiJb5vYy8V0twHqiDuDgVmTtoeWBIHIgZEFsx8MI+vN9Xe8hmsJ+1yzD
# uhGYHvzTIAhCs1+/f4hYMqsws9iMepZKGRNcrPznq+kcFi6wsDiVSs+FUKtnAyWh
# uzjpD2+pWpqRKBM1uR/zPeEkyGuxmegN77tN5T2MVAOR0Pwtz1UzOHoJHAfRIuBj
# hqe+/dKDcxIUm5pMCUa9NLzhS1B7cuBb/Rm7HzxqGXtuuy1EKr48TMysigSTxleG
# oHM2K4GX+hubfoiH2FJ5if5udzfXu1Cf+hglTxPyXnypsSBaKaujQod34PRMAkjd
# WKVTpqOg7RmWZRUpxe0zMCXmloOBmvZgZpBYB4DNQnWs+7SR0MXdAUBqtqgQ7vaN
# ereeda/TpUsYoQyfV7BeJUeRdM11EtGcb+ReDZvsdSbu/tP1ki9ShejaRFEqoswA
# yodmQ6MbAO+itZadYq0nC/IbSsnDlEI3iCCEqIeuw7ojcnv4VO/4ayewhfWnQ4XY
# Kzl021p3AtGk+vXNnD3MH65R0Hts2B0tEUJTcXTC5TWqLVIS2SXP8NPQkUMS1zJ9
# mGzjd0HI/x8kVO9urcY+VXvxXIc6ZPFgSwVP77kv7AkTAgMBAAGjggGCMIIBfjAf
# BgNVHSMEGDAWgBQaofhhGSAPw0F3RSiO0TVfBhIEVTAdBgNVHQ4EFgQUAw8xyJEq
# k71j89FdTaQ0D9KVARgwDgYDVR0PAQH/BAQDAgbAMAwGA1UdEwEB/wQCMAAwFgYD
# VR0lAQH/BAwwCgYIKwYBBQUHAwgwSgYDVR0gBEMwQTA1BgwrBgEEAbIxAQIBAwgw
# JTAjBggrBgEFBQcCARYXaHR0cHM6Ly9zZWN0aWdvLmNvbS9DUFMwCAYGZ4EMAQQC
# MEQGA1UdHwQ9MDswOaA3oDWGM2h0dHA6Ly9jcmwuc2VjdGlnby5jb20vU2VjdGln
# b1JTQVRpbWVTdGFtcGluZ0NBLmNybDB0BggrBgEFBQcBAQRoMGYwPwYIKwYBBQUH
# MAKGM2h0dHA6Ly9jcnQuc2VjdGlnby5jb20vU2VjdGlnb1JTQVRpbWVTdGFtcGlu
# Z0NBLmNydDAjBggrBgEFBQcwAYYXaHR0cDovL29jc3Auc2VjdGlnby5jb20wDQYJ
# KoZIhvcNAQEMBQADggIBAEybZVj64HnP7xXDMm3eM5Hrd1ji673LSjx13n6UbcMi
# xwSV32VpYRMM9gye9YkgXsGHxwMkysel8Cbf+PgxZQ3g621RV6aMhFIIRhwqwt7y
# 2opF87739i7Efu347Wi/elZI6WHlmjl3vL66kWSIdf9dhRY0J9Ipy//tLdr/vpMM
# 7G2iDczD8W69IZEaIwBSrZfUYngqhHmo1z2sIY9wwyR5OpfxDaOjW1PYqwC6WPs1
# gE9fKHFsGV7Cg3KQruDG2PKZ++q0kmV8B3w1RB2tWBhrYvvebMQKqWzTIUZw3C+N
# dUwjwkHQepY7w0vdzZImdHZcN6CaJJ5OX07Tjw/lE09ZRGVLQ2TPSPhnZ7lNv8wN
# sTow0KE9SK16ZeTs3+AB8LMqSjmswaT5qX010DJAoLEZKhghssh9BXEaSyc2quCY
# HIN158d+S4RDzUP7kJd2KhKsQMFwW5kKQPqAbZRhe8huuchnZyRcUI0BIN4H9wHU
# +C4RzZ2D5fjKJRxEPSflsIZHKgsbhHZ9e2hPjbf3E7TtoC3ucw/ZELqdmSx813Uf
# jxDElOZ+JOWVSoiMJ9aFZh35rmR2kehI/shVCu0pwx/eOKbAFPsyPfipg2I2yMO+
# AIccq/pKQhyJA9z1XHxw2V14Tu6fXiDmCWp8KwijSPUV/ARP380hHHrl9Y4a1LlA
# MIIG7DCCBNSgAwIBAgIQMA9vrN1mmHR8qUY2p3gtuTANBgkqhkiG9w0BAQwFADCB
# iDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCk5ldyBKZXJzZXkxFDASBgNVBAcTC0pl
# cnNleSBDaXR5MR4wHAYDVQQKExVUaGUgVVNFUlRSVVNUIE5ldHdvcmsxLjAsBgNV
# BAMTJVVTRVJUcnVzdCBSU0EgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMTkw
# NTAyMDAwMDAwWhcNMzgwMTE4MjM1OTU5WjB9MQswCQYDVQQGEwJHQjEbMBkGA1UE
# CBMSR3JlYXRlciBNYW5jaGVzdGVyMRAwDgYDVQQHEwdTYWxmb3JkMRgwFgYDVQQK
# Ew9TZWN0aWdvIExpbWl0ZWQxJTAjBgNVBAMTHFNlY3RpZ28gUlNBIFRpbWUgU3Rh
# bXBpbmcgQ0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDIGwGv2Sx+
# iJl9AZg/IJC9nIAhVJO5z6A+U++zWsB21hoEpc5Hg7XrxMxJNMvzRWW5+adkFiYJ
# +9UyUnkuyWPCE5u2hj8BBZJmbyGr1XEQeYf0RirNxFrJ29ddSU1yVg/cyeNTmDoq
# HvzOWEnTv/M5u7mkI0Ks0BXDf56iXNc48RaycNOjxN+zxXKsLgp3/A2UUrf8H5Vz
# JD0BKLwPDU+zkQGObp0ndVXRFzs0IXuXAZSvf4DP0REKV4TJf1bgvUacgr6Unb+0
# ILBgfrhN9Q0/29DqhYyKVnHRLZRMyIw80xSinL0m/9NTIMdgaZtYClT0Bef9Maz5
# yIUXx7gpGaQpL0bj3duRX58/Nj4OMGcrRrc1r5a+2kxgzKi7nw0U1BjEMJh0giHP
# Yla1IXMSHv2qyghYh3ekFesZVf/QOVQtJu5FGjpvzdeE8NfwKMVPZIMC1Pvi3vG8
# Aij0bdonigbSlofe6GsO8Ft96XZpkyAcSpcsdxkrk5WYnJee647BeFbGRCXfBhKa
# Bi2fA179g6JTZ8qx+o2hZMmIklnLqEbAyfKm/31X2xJ2+opBJNQb/HKlFKLUrUMc
# pEmLQTkUAx4p+hulIq6lw02C0I3aa7fb9xhAV3PwcaP7Sn1FNsH3jYL6uckNU4B9
# +rY5WDLvbxhQiddPnTO9GrWdod6VQXqngwIDAQABo4IBWjCCAVYwHwYDVR0jBBgw
# FoAUU3m/WqorSs9UgOHYm8Cd8rIDZsswHQYDVR0OBBYEFBqh+GEZIA/DQXdFKI7R
# NV8GEgRVMA4GA1UdDwEB/wQEAwIBhjASBgNVHRMBAf8ECDAGAQH/AgEAMBMGA1Ud
# JQQMMAoGCCsGAQUFBwMIMBEGA1UdIAQKMAgwBgYEVR0gADBQBgNVHR8ESTBHMEWg
# Q6BBhj9odHRwOi8vY3JsLnVzZXJ0cnVzdC5jb20vVVNFUlRydXN0UlNBQ2VydGlm
# aWNhdGlvbkF1dGhvcml0eS5jcmwwdgYIKwYBBQUHAQEEajBoMD8GCCsGAQUFBzAC
# hjNodHRwOi8vY3J0LnVzZXJ0cnVzdC5jb20vVVNFUlRydXN0UlNBQWRkVHJ1c3RD
# QS5jcnQwJQYIKwYBBQUHMAGGGWh0dHA6Ly9vY3NwLnVzZXJ0cnVzdC5jb20wDQYJ
# KoZIhvcNAQEMBQADggIBAG1UgaUzXRbhtVOBkXXfA3oyCy0lhBGysNsqfSoF9bw7
# J/RaoLlJWZApbGHLtVDb4n35nwDvQMOt0+LkVvlYQc/xQuUQff+wdB+PxlwJ+TNe
# 6qAcJlhc87QRD9XVw+K81Vh4v0h24URnbY+wQxAPjeT5OGK/EwHFhaNMxcyyUzCV
# pNb0llYIuM1cfwGWvnJSajtCN3wWeDmTk5SbsdyybUFtZ83Jb5A9f0VywRsj1sJV
# hGbks8VmBvbz1kteraMrQoohkv6ob1olcGKBc2NeoLvY3NdK0z2vgwY4Eh0khy3k
# /ALWPncEvAQ2ted3y5wujSMYuaPCRx3wXdahc1cFaJqnyTdlHb7qvNhCg0MFpYum
# Cf/RoZSmTqo9CfUFbLfSZFrYKiLCS53xOV5M3kg9mzSWmglfjv33sVKRzj+J9hyh
# tal1H3G/W0NdZT1QgW6r8NDT/LKzH7aZlib0PHmLXGTMze4nmuWgwAxyh8FuTVrT
# HurwROYybxzrF06Uw3hlIDsPQaof6aFBnf6xuKBlKjTg3qj5PObBMLvAoGMs/FwW
# AKjQxH/qEZ0eBsambTJdtDgJK0kHqv3sMNrxpy/Pt/360KOE2See+wFmd7lWEOEg
# bsausfm2usg1XTN2jvF8IAwqd661ogKGuinutFoAsYyr4/kKyVRd1LlqdJ69SK6Y
# MYIELDCCBCgCAQEwgZEwfTELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIg
# TWFuY2hlc3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEYMBYGA1UEChMPU2VjdGlnbyBM
# aW1pdGVkMSUwIwYDVQQDExxTZWN0aWdvIFJTQSBUaW1lIFN0YW1waW5nIENBAhA5
# TCXhfKBtJ6hl4jvZHSLUMA0GCWCGSAFlAwQCAgUAoIIBazAaBgkqhkiG9w0BCQMx
# DQYLKoZIhvcNAQkQAQQwHAYJKoZIhvcNAQkFMQ8XDTI0MDYyOTA5MzQzMlowPwYJ
# KoZIhvcNAQkEMTIEMDdMX60STaHqR5IFkACPzCdtWDafMXr9tGb6HuM2rcImJPxT
# roJ1vb8kXWaNhmhIPDCB7QYLKoZIhvcNAQkQAgwxgd0wgdowgdcwFgQUrmKvdQoM
# vUfWRh91aOK8jOfKT5QwgbwEFALWW5Xig3DBVwCV+oj5I92Tf62PMIGjMIGOpIGL
# MIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMKTmV3IEplcnNleTEUMBIGA1UEBxML
# SmVyc2V5IENpdHkxHjAcBgNVBAoTFVRoZSBVU0VSVFJVU1QgTmV0d29yazEuMCwG
# A1UEAxMlVVNFUlRydXN0IFJTQSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eQIQMA9v
# rN1mmHR8qUY2p3gtuTANBgkqhkiG9w0BAQEFAASCAgB/Sq01FHfgiiCWcATKojev
# HU56Q1E4LGV/MOBOpVKj4hWFqtMp6VMK9F3VA3BmcasA2+BaCmCxUXjYC36KH9W4
# HvMKVJ2ZXRZtYezKxFTWmduh6IgpEDl3ZmUE7D/n4BUO2vpL6A0ufQdfO4ka6fM1
# +pmQwHUNANrtF/MsJjwT/BAGSjyNWoVlf7vHz/tdm4MN4vuYF5dFBPcFDj+Yn7Cg
# 5/E2he1GvFTSGGyaKshbcelaLWQRtYIuntrGstrFt/WZ11pz9KgL+PLc4xfcp/ka
# 8uwIUrsIhbXL/Ul2GfO+REiai87amgrE0TCsbSumNwaOS8nGHuWF7aHk4LReNbR0
# XKM6fGVia2KigEMFs2pP+mdiZHkjEUSKQXiNpg/UYibPKbXtZW1PDncEwL5It90b
# 8/ZDsETFHuwoiYqPYzF38MVv8O+Hw1ZDLFCBhPLlHQAFpUKis8gZJK7SDWGyApBj
# FgfCzpiWdHp/eR8CNFXymlE0U2gMzuiQtaNkFtd+oh0X5znMXSIQJf2XIHYoHVcr
# QPCWoNwWdRiS34uzGOEfzc89RHzHOMMd0ByMeKFJdpmGkCYbLQMIN5Lei1DQ2IF6
# RDaStPZ5zJNS6njG8OErGUTfnb0wW/UPjKnSmoaDyPbz0Bxg2adbK3BujEax0dx+
# 1UQy76Z+V//aWnkMsKh5ng==
# SIG # End signature block
