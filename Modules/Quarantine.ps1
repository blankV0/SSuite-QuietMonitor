<#
.SYNOPSIS
    Quarantine.ps1 - Quarantines suspicious files using AES-256 encryption.
.DESCRIPTION
    Moves a suspicious file to C:\QuietMonitor\Quarantine\ as an AES-256-CBC encrypted
    archive (pure .NET - no external tools). Key derivation uses PBKDF2/SHA256 with
    100,000 iterations. The original file is moved (not deleted) after successful
    encryption. A JSON manifest records metadata for each quarantine entry.

    Encryption format: [MAGIC(4)][SALT(16)][IV(16)][CIPHERTEXT]
    MAGIC = 0x514D5145 ("QMQE" - QuietMonitor Quarantine Entry)

    IMPORTANT: This module requires explicit user confirmation before execution.
    It will NOT run silently even with -AutoQuarantine unless the caller has
    already obtained a "YES" confirmation.

    ThreatLocker Note: This module MODIFIES the file system (moves files).
    Sign with: Set-AuthenticodeSignature .\Modules\Quarantine.ps1 -Certificate $cert
.OUTPUTS
    Writes encrypted file and manifest entry. Returns $true on success.
#>

function Invoke-QuarantineFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$FilePath,

        [Parameter(Mandatory)]
        [string]$Reason,

        [Parameter(Mandatory)]
        [string]$QuarantinePath,

        [Parameter(Mandatory)]
        [string]$Password,

        [Parameter(Mandatory)]
        [string]$AuditLog,

        # When $true the caller has ALREADY obtained user confirmation (YES prompt)
        [switch]$Confirmed
    )

    # Validate input file exists
    if (-not (Test-Path $FilePath -PathType Leaf)) {
        throw "Quarantine target not found or is not a file: $FilePath"
    }

    # Enforce minimum password length for security
    if ($Password.Length -lt 12) {
        throw "Quarantine password must be at least 12 characters. Update Config\settings.json."
    }

    # Require explicit confirmation unless already confirmed by caller
    if (-not $Confirmed) {
        Write-Host "`n[!] QUARANTINE ACTION REQUESTED" -ForegroundColor Red
        Write-Host "    File   : $FilePath" -ForegroundColor Yellow
        Write-Host "    Reason : $Reason" -ForegroundColor Yellow
        Write-Host "    Target : $QuarantinePath" -ForegroundColor Yellow
        Write-Host ""
        $confirm = Read-Host "Are you sure? Type YES to proceed"
        if ($confirm -ne 'YES') {
            Write-Host "    Quarantine aborted by user." -ForegroundColor Yellow
            Add-Content -Path $AuditLog -Value (
                "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')] " +
                "[USER: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)] " +
                "[MODULE: Quarantine] [ACTION: QuarantineAborted] " +
                "[DETAILS: User declined for: $FilePath]"
            ) -Encoding UTF8
            return $false
        }
    }

    # Ensure quarantine directory exists
    if (-not (Test-Path $QuarantinePath)) {
        New-Item -ItemType Directory -Path $QuarantinePath -Force | Out-Null
    }

    # Restrict quarantine folder ACL to SYSTEM and Administrators only
    try {
        $acl = Get-Acl -Path $QuarantinePath
        $acl.SetAccessRuleProtection($true, $false)  # Block inheritance, remove inherited
        $adminRule  = New-Object System.Security.AccessControl.FileSystemAccessRule(
            'BUILTIN\Administrators', 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            'NT AUTHORITY\SYSTEM', 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.SetAccessRule($adminRule)
        $acl.SetAccessRule($systemRule)
        Set-Acl -Path $QuarantinePath -AclObject $acl -ErrorAction SilentlyContinue
    } catch { <# ACL restriction is best-effort #> }

    $timestamp   = Get-Date -Format 'yyyyMMdd_HHmmss'
    $fileName    = [System.IO.Path]::GetFileName($FilePath)
    $encFileName = "${fileName}_${timestamp}.qmenc"
    $encFilePath = Join-Path $QuarantinePath $encFileName
    $manifestPath = Join-Path $QuarantinePath 'quarantine_manifest.json'

    # Compute hashes of original file BEFORE moving
    $sha256 = (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash
    $md5    = (Get-FileHash -Path $FilePath -Algorithm MD5).Hash
    $fileSize = (Get-Item $FilePath).Length

    try {
        # Read original file bytes
        $plainBytes = [System.IO.File]::ReadAllBytes($FilePath)

        # Generate cryptographically random salt and IV
        $rng  = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        $salt = New-Object byte[] 16
        $iv   = New-Object byte[] 16
        $rng.GetBytes($salt)
        $rng.GetBytes($iv)
        $rng.Dispose()

        # Derive 256-bit key using PBKDF2/SHA256, 100,000 iterations
        $pBytes = [System.Text.Encoding]::UTF8.GetBytes($Password)
        $deriveBytes = New-Object System.Security.Cryptography.Rfc2898DeriveBytes(
            $Password, $salt, 100000, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
        $key = $deriveBytes.GetBytes(32)
        $deriveBytes.Dispose()

        # Encrypt with AES-256-CBC + PKCS7 padding
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.KeySize  = 256
        $aes.BlockSize = 128
        $aes.Key      = $key
        $aes.IV       = $iv
        $aes.Mode     = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding  = [System.Security.Cryptography.PaddingMode]::PKCS7

        $encryptor     = $aes.CreateEncryptor()
        $cipherBytes   = $encryptor.TransformFinalBlock($plainBytes, 0, $plainBytes.Length)
        $encryptor.Dispose()
        $aes.Dispose()

        # Build output: MAGIC(4) + SALT(16) + IV(16) + CIPHERTEXT
        $magic  = [byte[]]@(0x51, 0x4D, 0x51, 0x45)  # "QMQE"
        $output = New-Object byte[] ($magic.Length + $salt.Length + $iv.Length + $cipherBytes.Length)
        [System.Array]::Copy($magic,      0, $output, 0,                                          $magic.Length)
        [System.Array]::Copy($salt,       0, $output, $magic.Length,                              $salt.Length)
        [System.Array]::Copy($iv,         0, $output, $magic.Length + $salt.Length,               $iv.Length)
        [System.Array]::Copy($cipherBytes,0, $output, $magic.Length + $salt.Length + $iv.Length,  $cipherBytes.Length)

        [System.IO.File]::WriteAllBytes($encFilePath, $output)

        # Securely clear sensitive byte arrays from memory
        # Compute entropy and PE header metadata BEFORE clearing plainBytes
        $entropy = 0.0
        $isPE    = $false
        $peArch  = 'N/A'
        try {
            # Shannon entropy: H = -sum(p * log2(p))
            $freq = [int[]]::new(256)
            foreach ($b in $plainBytes) { $freq[$b]++ }
            $len = $plainBytes.Length
            if ($len -gt 0) {
                $h = 0.0
                foreach ($count in $freq) {
                    if ($count -gt 0) {
                        $p = $count / $len
                        $h -= $p * [Math]::Log($p, 2)
                    }
                }
                $entropy = [Math]::Round($h, 4)
            }
            # PE header: check MZ magic
            if ($plainBytes.Length -gt 1 -and $plainBytes[0] -eq 0x4D -and $plainBytes[1] -eq 0x5A) {
                $isPE = $true
                if ($plainBytes.Length -gt 0x40) {
                    $peOffset = [System.BitConverter]::ToInt32($plainBytes, 0x3C)
                    if ($peOffset -gt 0 -and ($peOffset + 26) -lt $plainBytes.Length) {
                        # Optional header magic at PE offset + 24 bytes (after PE signature + FileHeader)
                        $optMagic = [System.BitConverter]::ToUInt16($plainBytes, $peOffset + 24)
                        $peArch   = switch ($optMagic) {
                            0x10B { 'PE32 (x86)' }
                            0x20B { 'PE64 (x64)' }
                            0x107 { 'ROM Image' }
                            default { "Unknown (0x$($optMagic.ToString('X4')))" }
                        }
                    }
                }
            }
        } catch { <# PE parsing is best-effort #> }

        [System.Array]::Clear($key,        0, $key.Length)
        [System.Array]::Clear($plainBytes, 0, $plainBytes.Length)
        [System.Array]::Clear($cipherBytes,0, $cipherBytes.Length)

    } catch {
        throw "Encryption failed: $($_.Exception.Message)"
    }

    # Move (not delete) the original file to quarantine staging area
    $stagedPath = Join-Path $QuarantinePath "${fileName}_${timestamp}.original"
    try {
        Move-Item -Path $FilePath -Destination $stagedPath -Force
    } catch {
        # If move fails, log but keep the encrypted copy
        Write-Warning "Could not move original file to quarantine staging: $($_.Exception.Message)"
        $stagedPath = $FilePath  # Indicate original is still in place
    }

    # Update manifest JSON (append entry)
    $currentUser    = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $manifestEntry  = [PSCustomObject]@{
        Timestamp       = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')
        OriginalPath    = $FilePath
        StagedPath      = $stagedPath
        EncryptedFile   = $encFilePath
        SHA256          = $sha256
        MD5             = $md5
        FileSizeBytes   = $fileSize
        Entropy         = $entropy
        IsPE            = $isPE
        PEArch          = $peArch
        Reason          = $Reason
        QuarantinedBy   = $currentUser
        EncryptionAlgo  = 'AES-256-CBC/PBKDF2-SHA256-100k'
        Removed         = $false
    }

    $manifest = [System.Collections.Generic.List[PSCustomObject]]::new()
    if (Test-Path $manifestPath) {
        try {
            $existing = Get-Content $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($existing -is [System.Array]) {
                foreach ($e in $existing) { $manifest.Add($e) }
            } elseif ($existing) {
                $manifest.Add($existing)
            }
        } catch {}
    }
    $manifest.Add($manifestEntry)
    $manifest | ConvertTo-Json -Depth 5 | Set-Content -Path $manifestPath -Encoding UTF8

    # Write audit log
    Add-Content -Path $AuditLog -Value (
        "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')] " +
        "[USER: $currentUser] " +
        "[MODULE: Quarantine] [ACTION: Quarantine] " +
        "[DETAILS: File='$FilePath' SHA256=$sha256 Reason='$Reason' EncFile='$encFilePath']"
    ) -Encoding UTF8

    Write-Host "    [+] Quarantined: $FilePath -> $encFilePath" -ForegroundColor Green
    Write-Host "    [+] SHA256: $sha256" -ForegroundColor Gray
    return $true
}


function Invoke-QuarantineRestore {
    <#
    .SYNOPSIS
        Restores a quarantined file from its encrypted archive.
    .PARAMETER ManifestEntry
        A manifest entry object from quarantine_manifest.json.
    .PARAMETER Password
        The same password used during quarantine.
    .PARAMETER RestorePath
        Target directory to restore the file into.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$ManifestEntry,

        [Parameter(Mandatory)]
        [string]$Password,

        [Parameter(Mandatory)]
        [string]$RestorePath,

        [Parameter(Mandatory)]
        [string]$AuditLog
    )

    $encFile = $ManifestEntry.EncryptedFile
    if (-not (Test-Path $encFile)) {
        throw "Encrypted quarantine file not found: $encFile"
    }

    $rawBytes = [System.IO.File]::ReadAllBytes($encFile)

    # Validate magic header
    $magic = $rawBytes[0..3]
    if ($magic[0] -ne 0x51 -or $magic[1] -ne 0x4D -or $magic[2] -ne 0x51 -or $magic[3] -ne 0x45) {
        throw "Invalid quarantine file format (bad magic bytes)."
    }

    $salt       = $rawBytes[4..19]
    $iv         = $rawBytes[20..35]
    $cipher     = $rawBytes[36..($rawBytes.Length - 1)]

    $deriveBytes = New-Object System.Security.Cryptography.Rfc2898DeriveBytes(
        $Password, $salt, 100000, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    $key = $deriveBytes.GetBytes(32)
    $deriveBytes.Dispose()

    $aes           = [System.Security.Cryptography.Aes]::Create()
    $aes.Key       = $key
    $aes.IV        = $iv
    $aes.Mode      = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding   = [System.Security.Cryptography.PaddingMode]::PKCS7
    $decryptor     = $aes.CreateDecryptor()
    $plainBytes    = $decryptor.TransformFinalBlock($cipher, 0, $cipher.Length)
    $decryptor.Dispose()
    $aes.Dispose()
    [System.Array]::Clear($key, 0, $key.Length)

    $origFileName = [System.IO.Path]::GetFileName($ManifestEntry.OriginalPath)
    $destFile     = Join-Path $RestorePath $origFileName
    [System.IO.File]::WriteAllBytes($destFile, $plainBytes)
    [System.Array]::Clear($plainBytes, 0, $plainBytes.Length)

    # Verify hash matches
    $restoredHash = (Get-FileHash -Path $destFile -Algorithm SHA256).Hash
    if ($restoredHash -ne $ManifestEntry.SHA256) {
        Remove-Item $destFile -Force
        throw "Hash mismatch after restore! Expected $($ManifestEntry.SHA256), got $restoredHash. File deleted."
    }

    Add-Content -Path $AuditLog -Value (
        "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')] " +
        "[USER: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)] " +
        "[MODULE: Quarantine] [ACTION: Restore] " +
        "[DETAILS: Restored '$($ManifestEntry.OriginalPath)' -> '$destFile' SHA256 verified]"
    ) -Encoding UTF8

    Write-Host "    [+] File restored to: $destFile (hash verified)" -ForegroundColor Green
    return $destFile
}
