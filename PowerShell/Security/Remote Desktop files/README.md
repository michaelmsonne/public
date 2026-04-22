# RDPFileSigner.ps1

**Comprehensive RDP file signing tool for the April 2026 Windows security update (CVE-2026-26151).**

The April 2026 cumulative updates (KB5083769 for Windows 11 / KB5082200 for Windows 10) enforce mandatory signing of `.rdp` files. Unsigned files now display a **"Caution: Unknown remote connection"** warning on every open and block drive/clipboard redirections by default.

`RDPFileSigner.ps1` addresses this by providing a single script to:
- Create or import a code-signing certificate
- Sign and unsign `.rdp` files via `rdpsign.exe`
- **Cryptographically verify** signatures (full PKCS#7 `CheckSignature`)
- Register right-click context menu entries ("Sign RDP" / "UnSign RDP")
- Register a scheduled task for automatic signing of new `.rdp` files

---

## Requirements

| Requirement | Detail |
|---|---|
| PowerShell | 5.1 or later |
| OS | Windows 10 / 11 / Server 2016+ |
| `rdpsign.exe` | Included with the Remote Desktop client (System32) |
| Administrator | Required for certificate store, registry, and task operations |
| Elevation | Sign / Unsign / Verify do **not** require elevation |

---

## Operation Modes

### Default / `-Setup`
Creates or reuses a self-signed code-signing certificate, installs it into
`LocalMachine\Root` and `LocalMachine\TrustedPublisher`, optionally exports
the public `.cer` and/or `.pfx`, and registers the context menu entries.

### `-Sign`
Signs one or more `.rdp` files using an existing certificate.

### `-Unsign`
Strips the digital signature from one or more `.rdp` files.

### `-Verify`
Performs full cryptographic verification of `.rdp` file signatures.
Reconstructs the exact signed content blob, decodes the PKCS#7 signature,
and calls `CheckSignature` — confirming the file has not been tampered with.

### `-ListCerts`
Lists all available code-signing certificates with thumbprints, expiry dates,
and colour-coded expiry warnings.

### `-ShellRegister` / `-ShellUnregister`
Registers or removes the "Sign RDP" / "UnSign RDP" right-click context menu
entries for `.rdp` files.

### `-TaskRegister` / `-TaskUnregister`
Registers or removes a Windows Scheduled Task (`RDPFileSigner - Auto Sign`)
that automatically signs all `.rdp` files in a watch folder every 5 minutes.

---

## Certificate Options

| Option | Description |
|---|---|
| Self-signed (default) | 4096-bit RSA / SHA-256, configurable validity (1–10 years) |
| `-CertTemplate` | Request from an Active Directory Certificate Services CA |
| `-ImportPfxPath` | Import from a commercial CA `.pfx` |
| `-CertThumbprint` | Use an existing certificate by SHA-256 thumbprint |

---

## Usage Examples

```powershell
# Run once on the signing machine: create cert, install to trust stores, register context menu
.\RDPFileSigner.ps1

# List available code-signing certificates and their thumbprints
.\RDPFileSigner.ps1 -ListCerts

# Sign a single RDP file
.\RDPFileSigner.ps1 -Sign -RdpFile "C:\RDP\MyServer.rdp"

# Sign all RDP files in a folder (including subfolders)
.\RDPFileSigner.ps1 -Sign -RdpFolder "C:\RDP" -Recurse

# Sign using a specific certificate thumbprint
.\RDPFileSigner.ps1 -Sign -RdpFile "C:\RDP\MyServer.rdp" -CertThumbprint "A1B2C3..."

# Sign all files and export the public certificate for distribution to clients
.\RDPFileSigner.ps1 -Sign -RdpFolder "C:\RDP" -ExportCerPath "C:\RDP\rdp-signing.cer"

# Verify signatures on all RDP files (full PKCS#7 cryptographic check)
.\RDPFileSigner.ps1 -Verify -RdpFolder "C:\RDP" -Recurse

# Verify and export a CSV report
.\RDPFileSigner.ps1 -Verify -RdpFolder "C:\RDP" -ExportCsvPath "C:\Reports\rdp-status.csv"

# Remove signatures from all RDP files in a folder
.\RDPFileSigner.ps1 -Unsign -RdpFolder "C:\RDP"

# Setup using an Enterprise CA certificate template
.\RDPFileSigner.ps1 -Setup -CertTemplate "CodeSigning"

# Setup importing a commercial CA PFX and exporting the public cert
.\RDPFileSigner.ps1 -Setup -ImportPfxPath "C:\Certs\commercial.pfx" -ExportCerPath "C:\Certs\public.cer"

# Register a scheduled task to auto-sign RDP files every 5 minutes
.\RDPFileSigner.ps1 -TaskRegister -WatchFolder "C:\RDP" -CertThumbprint "D6A630B8..."

# Remove the scheduled task
.\RDPFileSigner.ps1 -TaskUnregister

# Re-register context menu entries after moving the script
.\RDPFileSigner.ps1 -ShellRegister

# Remove context menu entries
.\RDPFileSigner.ps1 -ShellUnregister

# Print script version
.\RDPFileSigner.ps1 -Version
```

---

## Screenshots

### Full setup run (`-Setup`)

Running the script without parameters creates a self-signed certificate,
installs it into the trust stores, grants private key read access to users,
prints Group Policy deployment hints, and registers the context menu entries.

![Full default setup output](docs/RDP%20-%20signer%20full%20default%20deploy.png)

---

### Right-click context menu

After setup, right-clicking any `.rdp` file shows the **Sign RDP** and
**UnSign RDP** entries in the Windows shell context menu.

![Sign RDP / UnSign RDP context menu](docs/RDP%20-%20signer%20menu%20deploy.png)

---

### Valid signature

A signed `.rdp` file whose PKCS#7 signature verifies correctly against the
reconstructed content. The signer's certificate thumbprint is shown.

![Valid signature verification](docs/RDP%20-%20signer%20valid%20file.png)

---

### Invalid / tampered signature

A `.rdp` file that has been modified after signing. The script detects the
mismatch during `CheckSignature` and outputs the reconstructed signed fields
as a diagnostic aid.

![Invalid signature - tampered file](docs/RDP%20-%20signer%20invalid%20file.png)

---

## Distributing the Certificate to Client Machines

After setup, export the public `.cer` with `-ExportCerPath` and import it on
each client machine:

```powershell
# Run as Administrator on each client
Import-Certificate -FilePath "rdp-signing.cer" -CertStoreLocation Cert:\LocalMachine\Root
Import-Certificate -FilePath "rdp-signing.cer" -CertStoreLocation Cert:\LocalMachine\TrustedPublisher
```

### Enterprise / Group Policy deployment

1. **Distribute the certificate** via GPO:
   `Computer Configuration > Windows Settings > Security Settings > Public Key Policies > Trusted Publishers`
   *(Also add to Trusted Root Certification Authorities for self-signed certificates.)*

2. **Add the thumbprint** to the RDP trusted publishers policy:
   `Computer Configuration > Administrative Templates > Windows Components > Remote Desktop Services > Remote Desktop Connection Client > "Specify SHA1 thumbprints of certificates representing trusted .rdp publishers"`

---

## Security Notes

- **Scheduled task (`-TaskRegister`)** runs as `SYSTEM` and will sign **any** `.rdp` file placed in the watch folder. Restrict write access to Administrators only:
  ```cmd
  icacls "C:\RDP" /inheritance:r /grant "BUILTIN\Administrators:(OI)(CI)F" /grant "SYSTEM:(OI)(CI)F"
  ```
- **Self-signed certificates** are only trusted on machines where the `.cer` has been imported. Use an Enterprise CA or commercial CA certificate for domain-wide trust without manual distribution.
- **Private key ACL** — during setup, `BUILTIN\Users` is granted read access to the private key so that context menu signing works without a UAC prompt. Remove this if non-admin signing is not required.

---

## Log File

By default the script writes a PowerShell transcript to **`RDPFileSigner.log`** in the same folder as the script. The log captures all console output for every run and is appended (not overwritten) so history is preserved.

| Switch / Parameter | Effect |
|---|---|
| *(default)* | Log written to `<script folder>\RDPFileSigner.log` |
| `-LogPath "C:\Logs\rdp.log"` | Override the log file location |
| `-NoLog` | Suppress transcript logging entirely (useful for scheduled tasks or CI pipelines where logging is handled externally) |

---

## Parameters

| Parameter | Description |
|---|---|
| `-Setup` | Full setup: cert, trust stores, context menu |
| `-Sign` | Sign `.rdp` files |
| `-Unsign` | Remove signatures from `.rdp` files |
| `-Verify` | Cryptographically verify signatures |
| `-ListCerts` | List available code-signing certificates |
| `-ShellRegister` | Register context menu entries |
| `-ShellUnregister` | Remove context menu entries |
| `-TaskRegister` | Register auto-sign scheduled task |
| `-TaskUnregister` | Remove auto-sign scheduled task |
| `-RdpFile` | Path to a single `.rdp` file |
| `-RdpFolder` | Path to a folder of `.rdp` files |
| `-Recurse` | Include subdirectories with `-RdpFolder` |
| `-CertSubject` | CN= subject for cert creation/lookup (default: `CN=<COMPUTERNAME> RDP Signing`) |
| `-CertValidityYears` | Self-signed cert validity in years (1–10, default: 3) |
| `-CertTemplate` | Enterprise CA template name |
| `-CertThumbprint` | Thumbprint of existing certificate |
| `-ImportPfxPath` | Path to `.pfx` to import |
| `-ImportPfxPassword` | SecureString password for PFX import |
| `-ExportCerPath` | Path to export public `.cer` |
| `-ExportPfxPath` | Path to export `.pfx` with private key |
| `-ExportPfxPassword` | SecureString password for PFX export |
| `-ExportCsvPath` | Export verify results to CSV (used with `-Verify`) |
| `-WatchFolder` | Folder to watch for auto-signing (used with `-TaskRegister`) |
| `-LogPath` | Override default log file path |
| `-NoLog` | Suppress transcript logging |
| `-Version` | Print script version and exit |

---

## Related

- [CVE-2026-26151 – Remote Desktop spoofing vulnerability](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-26151)
- KB5083769 (Windows 11) / KB5082200 (Windows 10) — April 2026 cumulative updates
- [rdpsign.exe documentation (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/rdpsign)

---

## Author

**Michael Morten Sonne** - https://blog.sonnes.cloud