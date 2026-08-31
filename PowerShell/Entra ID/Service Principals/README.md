# Service Principals

PowerShell scripts to **discover** and **create** missing Entra ID service principals (Enterprise Applications) that are required by Conditional Access policies and other security configurations.

## Overview

Many Microsoft first-party applications (Azure Virtual Desktop, Windows 365, Microsoft Intune Enrollment, Global Secure Access, etc.) do **not** have a service principal in your tenant until something references them. When you build a Conditional Access (CA) policy that targets one of these apps - or a user/device signs in through it - the app can be **missing as a service principal**, which causes sign-ins to be blocked or evaluated incorrectly and makes the app impossible to select in the CA policy picker.

These two scripts work together:

| Script | Purpose |
|--------|---------|
| [`Find-MissingServicePrincipalsFromSignInLogs.ps1`](Find-MissingServicePrincipalsFromSignInLogs.ps1) | **Detect** - reads interactive & non-interactive sign-in logs and lists apps/resources seen in logs that have **no** matching service principal. |
| [`CreateMissingServicePrincipals.ps1`](CreateMissingServicePrincipals.ps1) | **Remediate** - registers a curated list of well-known Microsoft Enterprise Applications as service principals in your tenant. |

**Typical workflow:** Run *Find* → copy the suggested `@{ AppId = ...; ExpectedName = ... }` lines → add them to the `$APPIDs` list in *Create* → run *Create* with `-WhatIf`, then for real.

---

## Why service principals go missing (Conditional Access impact)

When an application has no service principal in the tenant, you may see the following in the **Entra ID → Sign-in logs**:

- **Sign-in interrupted / blocked** even though no CA policy *should* apply - because the app object the policy references cannot be resolved.
- **Conditional Access = "Not applied"** or **"Failure"** on sign-ins for the app, since CA cannot evaluate an app it cannot resolve to a service principal.
- Errors surfaced in the sign-in log detail, most commonly:
  - **AADSTS7000112** – *"The service principal for the application ... is disabled."* (or missing)
  - **AADSTS650052** – *"The app needs access to a service that your organization ... has not subscribed to or enabled."* - often shown when the resource/service principal is not present.
  - **AADSTS500011** – *"The resource principal named ... was not found in the tenant."* - the resource service principal is missing.
  - **AADSTS7000112 / "Application not found in the directory"** – the client `appId` has no service principal.
- In the CA policy editor the app **cannot be selected** under *Target resources → Apps*, because only apps with a service principal appear in the picker.

The *Find* script surfaces exactly which `appId`s (clients) and `resourceId`s (resources) appear in your logs but are missing a service principal, so you can remediate before these errors affect users.

---

## Prerequisites

- **PowerShell 5.1** or later (PowerShell 7+ recommended)
- **Microsoft Graph PowerShell modules**
- **Entra ID P1 or higher** - sign-in log queries require P1/P2 licensing
- **Required Microsoft Graph permissions**

| Script | Required Graph modules | Delegated permissions |
|--------|------------------------|-----------------------|
| `Find-MissingServicePrincipalsFromSignInLogs.ps1` | `Microsoft.Graph.Authentication`, `Microsoft.Graph.Reports` | `AuditLog.Read.All`, `Application.Read.All` |
| `CreateMissingServicePrincipals.ps1` | `Microsoft.Graph.Authentication`, `Microsoft.Graph.Applications` | `Application.ReadWrite.All` |

### Install the Microsoft Graph modules

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
```

> If you hit a *"Could not load file or assembly"* error, your Microsoft.Graph sub-modules are at mismatched versions. Reinstall cleanly:
>
> ```powershell
> Get-InstalledModule Microsoft.Graph* | Uninstall-Module -AllVersions -Force
> Install-Module Microsoft.Graph -Scope CurrentUser -Force
> ```

---

## 1. Find-MissingServicePrincipalsFromSignInLogs.ps1

### What it does

- Connects to Microsoft Graph and fetches **all existing service principals** (keyed by both `AppId` and object `Id`).
- Reads **interactive** sign-in logs (`Get-MgAuditLogSignIn`) and **non-interactive** summarized sign-in logs (beta `getSummarizedNonInteractiveSignIns` endpoint).
- Builds a unique list of **client apps** (`appId`) and **resources** (`resourceId`) seen in the logs.
- Reports:
  - **Missing client app service principals** - matched by `appId`. These can be auto-created with the *Create* script and the script prints ready-to-paste `@{ AppId = ...; ExpectedName = ... }` lines.
  - **Missing resource service principals** - matched by SP object `Id`/`AppId`. These **cannot** be auto-created (the `resourceId` is an SP object ID, not an `appId`) and must be investigated manually.

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `TenantId` | string | (current) | Connect to a specific Entra tenant. |
| `DaysBack` | int | `1` | How many days back to query sign-in logs. |
| `StartDate` | datetime | (none) | Explicit start date/time. Overrides `DaysBack`. |
| `EndDate` | datetime | now (UTC) | Explicit end date/time. |
| `Top` | int | `500` | Max non-interactive entries per page. |
| `SkipInteractive` | switch | off | Skip querying interactive sign-in logs. |
| `SkipNonInteractive` | switch | off | Skip querying non-interactive sign-in logs. |

### Usage examples

```powershell
# Check the last 24 hours (default)
.\Find-MissingServicePrincipalsFromSignInLogs.ps1

# Check the last 7 days
.\Find-MissingServicePrincipalsFromSignInLogs.ps1 -DaysBack 7

# Check a specific date range
.\Find-MissingServicePrincipalsFromSignInLogs.ps1 -StartDate "2026-08-01" -EndDate "2026-08-28"

# Only interactive sign-ins
.\Find-MissingServicePrincipalsFromSignInLogs.ps1 -SkipNonInteractive

# Target a specific tenant
.\Find-MissingServicePrincipalsFromSignInLogs.ps1 -TenantId "00000000-0000-0000-0000-000000000000"
```

### Example output

```
==== Missing Client App Service Principals ====
  The following 2 client app(s) appear in sign-in logs but have no service principal:

  Azure Virtual Desktop [9cdead84-a844-4324-93f2-b2e6bb768d07]  (Interactive, NonInteractive)
  Windows 365 [0af06dc6-e4b5-4f28-818e-e78e62d137a5]  (NonInteractive)

  To add these as entries in CreateMissingServicePrincipals.ps1, use:

    @{ AppId = "9cdead84-a844-4324-93f2-b2e6bb768d07"; ExpectedName = "Azure Virtual Desktop" }
    @{ AppId = "0af06dc6-e4b5-4f28-818e-e78e62d137a5"; ExpectedName = "Windows 365" }
```

---

## 2. CreateMissingServicePrincipals.ps1

### What it does

- Connects to Microsoft Graph and fetches all existing service principals (into a fast `AppId` lookup).
- Iterates a curated `$APPIDs` list of well-known Microsoft first-party applications.
- For each app: if the service principal already exists it is reported as **OK**; if missing it is **created** via `New-MgServicePrincipal`.
- Supports **`-WhatIf`** to preview exactly what would be created without making changes.
- Handles common edge cases gracefully:
  - **AppId not instantiable** (`Request_BadRequest`) → reported as **[SKIP]**.
  - **Already created / duplicate** (`Request_MultipleObjectsWithSameKeyValue`, 409) → reported as **[OK]**.
- Prints a summary: existing, created, would-be-created, skipped and failed counts.

### Customizing the app list

Add or remove entries in the `#region Variables` block near the top of the script. Paste the lines produced by the *Find* script:

```powershell
$APPIDs = @(
    @{ AppId = "9cdead84-a844-4324-93f2-b2e6bb768d07"; ExpectedName = "Azure Virtual Desktop" }
    @{ AppId = "0af06dc6-e4b5-4f28-818e-e78e62d137a5"; ExpectedName = "Windows 365" }
    # ... add your discovered apps here
)
```

> **Note:** `ExpectedName` is only used for readable console output. The actual display name is assigned by Entra ID when the service principal is created from the `AppId`.

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `TenantId` | string | (current) | Connect to a specific Entra tenant. |
| `WhatIf` | switch | off | Preview which service principals would be created without making changes. |

### Usage examples

```powershell
# Preview what would be created (recommended first run)
.\CreateMissingServicePrincipals.ps1 -WhatIf

# Register the missing Enterprise Applications
.\CreateMissingServicePrincipals.ps1

# Target a specific tenant
.\CreateMissingServicePrincipals.ps1 -TenantId "00000000-0000-0000-0000-000000000000"
```

---

## End-to-end example

```powershell
# 1. Discover what's missing over the last 7 days
.\Find-MissingServicePrincipalsFromSignInLogs.ps1 -DaysBack 7

# 2. Copy the printed @{ AppId = ...; ExpectedName = ... } lines into
#    the $APPIDs list inside CreateMissingServicePrincipals.ps1

# 3. Preview the changes
.\CreateMissingServicePrincipals.ps1 -WhatIf

# 4. Apply the changes
.\CreateMissingServicePrincipals.ps1
```

## Notes & caveats

- **Resource service principals cannot be auto-created.** When the *Find* script lists *Missing Resource Service Principals*, the `resourceId` is an SP object ID (not an `appId`). Investigate each one manually and register it via its real `appId` if one exists.
- **Some first-party AppIds are not instantiable** in every tenant. The *Create* script reports these as `[SKIP]` - this is expected, not an error.
- **Least privilege:** the *Find* script only needs read permissions (`AuditLog.Read.All`, `Application.Read.All`). Grant the write permission (`Application.ReadWrite.All`) only when running the *Create* script.
- **Licensing:** sign-in log access requires **Entra ID P1/P2**.

## References

Useful resources for identifying and mapping Microsoft first-party application (service principal) IDs:

- [Microsoft 365 Application IDs - BEC Investigation Resources (ByteIntoCyber)](https://byteintocyber.com/microsoft-365-application-ids-bec-investigation-resources/) - reference list of Microsoft 365 app IDs, handy when investigating sign-in logs and BEC incidents.
- [merill/microsoft-info - MicrosoftApps.debug.csv](https://github.com/merill/microsoft-info/blob/main/_info/MicrosoftApps.debug.csv) - community-maintained, machine-readable mapping of Microsoft `appId` → display name (great for enriching the output of the *Find* script).

## Author

Michael Morten Sonne - Sonne´s Cloud
