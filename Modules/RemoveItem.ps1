<#
.SYNOPSIS
    RemoveItem.ps1 - Permanently removes a quarantined or flagged item after explicit confirmation.
.DESCRIPTION
    This module ONLY executes removal when the operator types the exact phrase:
        CONFIRM REMOVE <item_name>

    It operates on:
      1. Items already in the quarantine manifest (removes both encrypted and staged files)
      2. Live file paths (when called with -FilePath directly)

    Every removal is permanently logged to the audit trail with timestamp, user, target,
    and SHA256 hash. This action is IRREVERSIBLE.

    IMPORTANT: This module permanently destroys data. It cannot be undone.
    Use Quarantine.ps1 first - only call RemoveItem.ps1 after quarantine is confirmed.

    ThreatLocker Note: This module PERMANENTLY DELETES files.
    Sign with: Set-AuthenticodeSignature .\Modules\RemoveItem.ps1 -Certificate $cert
.OUTPUTS
    $true on successful removal, $false if aborted.
#>

function Invoke-RemoveItem {
    [CmdletBinding()]
    param(
        # Name to confirm against (shown to operator and required in confirmation phrase)
        [Parameter(Mandatory, ParameterSetName = 'ByName')]
        [Parameter(Mandatory, ParameterSetName = 'ByPath')]
        [string]$ItemName,

        # Full path to remove (when removing a live file, not from quarantine manifest)
        [Parameter(ParameterSetName = 'ByPath')]
        [string]$FilePath,

        # Quarantine manifest entry (PSCustomObject from quarantine_manifest.json)
        [Parameter(ParameterSetName = 'ByManifest')]
        [PSCustomObject]$ManifestEntry,

        [Parameter(Mandatory)]
        [string]$AuditLog,

        # Path to the quarantine manifest JSON for updating Removed=true
        [string]$ManifestPath = 'C:\QuietMonitor\Quarantine\quarantine_manifest.json'
    )

    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

    Write-Host "`n[!!!] PERMANENT REMOVAL REQUESTED" -ForegroundColor Red
    Write-Host "      Item   : $ItemName" -ForegroundColor Red
    if ($FilePath) {
        Write-Host "      Path   : $FilePath" -ForegroundColor Red
    }
    if ($ManifestEntry) {
        Write-Host "      Original path : $($ManifestEntry.OriginalPath)" -ForegroundColor Red
        Write-Host "      Encrypted file: $($ManifestEntry.EncryptedFile)" -ForegroundColor Red
        Write-Host "      Staged file   : $($ManifestEntry.StagedPath)" -ForegroundColor Red
    }
    Write-Host ""
    Write-Host "  This action is IRREVERSIBLE. Files cannot be recovered." -ForegroundColor Red
    Write-Host "  To confirm, type exactly:  CONFIRM REMOVE $ItemName" -ForegroundColor Yellow
    Write-Host ""

    $confirmation = Read-Host "Confirmation"

    $expectedPhrase = "CONFIRM REMOVE $ItemName"
    if ($confirmation -ne $expectedPhrase) {
        Write-Host "    Removal aborted - confirmation phrase did not match." -ForegroundColor Yellow
        Add-Content -Path $AuditLog -Value (
            "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')] " +
            "[USER: $currentUser] " +
            "[MODULE: RemoveItem] [ACTION: RemovalAborted] " +
            "[DETAILS: Item='$ItemName' - Incorrect confirmation phrase provided]"
        ) -Encoding UTF8
        return $false
    }

    $removedFiles  = [System.Collections.Generic.List[string]]::new()
    $removedHashes = [System.Collections.Generic.List[string]]::new()

    # --- Remove by manifest entry ---
    if ($PSCmdlet.ParameterSetName -eq 'ByManifest' -or $ManifestEntry) {
        foreach ($target in @($ManifestEntry.EncryptedFile, $ManifestEntry.StagedPath)) {
            if ($target -and (Test-Path $target -ErrorAction SilentlyContinue)) {
                try {
                    $hash = ''
                    try { $hash = (Get-FileHash -Path $target -Algorithm SHA256).Hash } catch {}
                    Remove-Item -Path $target -Force -ErrorAction Stop
                    $removedFiles.Add($target)
                    $removedHashes.Add($hash)
                    Write-Host "    [+] Removed: $target" -ForegroundColor Green
                } catch {
                    Write-Warning "    Failed to remove '$target': $($_.Exception.Message)"
                }
            }
        }

        # Update manifest: mark entry as Removed = true
        if (Test-Path $ManifestPath) {
            try {
                $manifest = Get-Content $ManifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
                foreach ($entry in $manifest) {
                    if ($entry.EncryptedFile -eq $ManifestEntry.EncryptedFile) {
                        $entry | Add-Member -NotePropertyName 'Removed' -NotePropertyValue $true -Force
                        $entry | Add-Member -NotePropertyName 'RemovedAt' -NotePropertyValue (Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC') -Force
                        $entry | Add-Member -NotePropertyName 'RemovedBy' -NotePropertyValue $currentUser -Force
                    }
                }
                $manifest | ConvertTo-Json -Depth 5 | Set-Content -Path $ManifestPath -Encoding UTF8
            } catch {
                Write-Warning "Could not update quarantine manifest: $($_.Exception.Message)"
            }
        }

    # --- Remove by file path ---
    } elseif ($FilePath) {
        if (-not (Test-Path $FilePath -ErrorAction SilentlyContinue)) {
            Write-Warning "    File not found: $FilePath"
            Add-Content -Path $AuditLog -Value (
                "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')] " +
                "[USER: $currentUser] " +
                "[MODULE: RemoveItem] [ACTION: RemovalFailed] " +
                "[DETAILS: File not found '$FilePath']"
            ) -Encoding UTF8
            return $false
        }

        $hash = ''
        try { $hash = (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash } catch {}

        try {
            Remove-Item -Path $FilePath -Force -ErrorAction Stop
            $removedFiles.Add($FilePath)
            $removedHashes.Add($hash)
            Write-Host "    [+] Removed: $FilePath (SHA256: $hash)" -ForegroundColor Green
        } catch {
            throw "Failed to remove file '$FilePath': $($_.Exception.Message)"
        }
    } else {
        Write-Warning "    No file path or manifest entry provided. Nothing removed."
        return $false
    }

    # Write permanent audit record
    Add-Content -Path $AuditLog -Value (
        "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')] " +
        "[USER: $currentUser] " +
        "[MODULE: RemoveItem] [ACTION: PermanentRemoval] " +
        "[DETAILS: Item='$ItemName' Files='$($removedFiles -join '; ')' Hashes='$($removedHashes -join '; ')']"
    ) -Encoding UTF8

    Write-Host ""
    Write-Host "    [+] Removal complete. $($removedFiles.Count) file(s) permanently deleted." -ForegroundColor Green
    Write-Host "    [+] Action recorded in audit log: $AuditLog" -ForegroundColor Gray
    return $true
}
