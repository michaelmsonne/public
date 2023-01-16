# If you want to find all users that were configured this way, the following PowerShell command will do the trick:
Get-ADUser -Filter 'UserAccountControl -band 0x200000'

#The bitwise and of UserAccountControl with 0x200000 shows whether the DES encryption flag is set. If you want to remove this, you can do so as follows:
Get-ADUser -Filter 'UserAccountControl -band 0x200000' |
ForEach-Object {Set-ADAccountControl -Identity $_ -UseDESKeyOnly $false}

#Remove RC4 from the attribute
#To remove RC4 from these accounts, you can proceed as follows:
Get-ADUser -Filter 'msDS-SupportedEncryptionTypes -band 0x4' -Properties msDS-SupportedEncryptionTypes |
ForEach-Object {
    $NewEncTyp = $_.'msDS-SupportedEncryptionTypes' - 0x4
    Set-ADUser -Identity $_ –replace @{'msDS-SupportedEncryptionTypes'=$NewEncTyp}
    }

#On the other hand, if you want to completely rewrite the attribute, you can use the KerberosEncryptionType parameter for this purpose
Get-ADUser -Filter 'msDS-SupportedEncryptionTypes -band 0x4' -Properties msDS-SupportedEncryptionTypes |
ForEach-Object{
    Set-ADUser -Identity $_ -KerberosEncryptionType "AES128,AES256"
    }

#Document encryption type for all users
$encTypes = @("Not defined - defaults to RC4_HMAC_MD5","DES_CBC_CRC","DES_CBC_MD5","DES_CBC_CRC | DES_CBC_MD5","RC4","DES_CBC_CRC | RC4","DES_CBC_MD5 | RC4","DES_CBC_CRC | DES_CBC_MD5 | RC4","AES 128","DES_CBC_CRC | AES 128","DES_CBC_MD5 | AES 128","DES_CBC_CRC | DES_CBC_MD5 | AES 128","RC4 | AES 128","DES_CBC_CRC | RC4 | AES 128","DES_CBC_MD5 | RC4 | AES 128","DES_CBC_CBC | DES_CBC_MD5 | RC4 | AES 128","AES 256","DES_CBC_CRC | AES 256","DES_CBC_MD5 | AES 256","DES_CBC_CRC | DES_CBC_MD5 | AES 256","RC4 | AES 256","DES_CBC_CRC | RC4 | AES 256","DES_CBC_MD5 | RC4 | AES 256","DES_CBC_CRC | DES_CBC_MD5 | RC4 | AES 256","AES 128 | AES 256","DES_CBC_CRC | AES 128 | AES 256","DES_CBC_MD5 | AES 128 | AES 256","DES_CBC_MD5 | DES_CBC_MD5 | AES 128 | AES 256","RC4 | AES 128 | AES 256","DES_CBC_CRC | RC4 | AES 128 | AES 256","DES_CBC_MD5 | RC4 | AES 128 | AES 256","DES+A1:C33_CBC_MD5 | DES_CBC_MD5 | RC4 | AES 128 | AES 256")
$EncVal = Get-ADUser -SearchBase "OU=Finance,DC=contoso,DC=com" `
-Filter * -properties msDS-SupportedEncryptionTypes
foreach($e in $EncVal){
  try {
    $e.Name + "," + $encTypes[$e.'msDS-SupportedEncryptionTypes']
      }
  catch{
    $e.Name + "," + $encTypes[0]
      }
    }