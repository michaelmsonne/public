# Create self-signed certificate
$mycert = New-SelfSignedCertificate -DnsName "domain.com" -CertStoreLocation "cert:\LocalMachine\My" -NotAfter (Get-Date).AddYears(5) -KeySpec KeyExchange -FriendlyName "EXO unattended cert"

#See generated certificate
$mycert | Select-Object -Property Subject,Thumbprint,NotBefore,NotAfter

#Export certificate to .cer
$mycert | Export-Certificate -FilePath "C:\temp\EXOUnattendedCert.cer"

#Export certificate to .pfx
$mycert | Export-PfxCertificate -FilePath "C:\temp\EXOUnattendedCert.pfx" -Password $(ConvertTo-SecureString -String "P@ssw0Rd1234" -AsPlainText -Force)

#Unattended PowerShell script example
#Connect Exchange Online PowerShell
$AppId = "cd4fad71-3820-4198-8748-b88035aeec51"
$CertificateThumbprint = "4F3CB0EFE918A3544274F9E2D54AB1BEE8B96B78"
$Organization = "domain.onmicrosoft.com"
Connect-ExchangeOnline -AppId $AppId -CertificateThumbprint $CertificateThumbprint -Organization $Organization -ShowBanner:$false
# Split path
$Path = Split-Path -Parent "C:\temp\*.*"
# Create variable for the date stamp
$LogDate = Get-Date -f yyyyMMddhhmm
# Define CSV and log file location variables
$Csvfile = $Path + "\AllMailboxes_$logDate.csv"
Get-EXOMailbox -ResultSize Unlimited | Select-Object DisplayName, PrimarySmtpAddress | Sort-Object PrimarySmtpAddress | Export-CSV -Path $Csvfile -NoTypeInformation -Encoding UTF8
# Disconnect Exchange Online PowerShell
Disconnect-ExchangeOnline -Confirm:$false