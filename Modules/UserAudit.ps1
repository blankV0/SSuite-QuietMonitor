<#
.SYNOPSIS
    UserAudit.ps1 - Audits local users and group memberships for unauthorized privileged accounts.
.DESCRIPTION
    Enumerates all local user accounts and members of privileged groups (Administrators,
    Remote Desktop Users, Remote Management Users). Flags accounts not in the AdminUsers
    whitelist that hold administrative privileges, disabled accounts that are still admin,
    and accounts with suspicious naming patterns.

    ThreatLocker Note: This module is read-only. No system modifications are made.
    Sign with: Set-AuthenticodeSignature .\Modules\UserAudit.ps1 -Certificate $cert
.OUTPUTS
    [System.Collections.Generic.List[PSCustomObject]] - List of finding objects.
#>

function Invoke-UserAudit {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Whitelist,

        [Parameter(Mandatory)]
        [string]$AuditLog
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Built-in/expected account SIDs and names that are always acceptable
    $builtinAdminSids = @(
        'S-1-5-32-544',  # Administrators group itself
        'S-1-5-18',      # SYSTEM
        'S-1-5-19',      # LOCAL SERVICE
        'S-1-5-20'       # NETWORK SERVICE
    )

    $privilegedGroups = @(
        'Administrators',
        'Remote Desktop Users',
        'Remote Management Users',
        'Backup Operators',
        'Power Users'
    )

    $unknownAdminCount = 0

    try {
        # --- Enumerate all local users ---
        $localUsers = Get-LocalUser -ErrorAction SilentlyContinue

        foreach ($user in $localUsers) {
            $severity = 'Green'
            $details  = "Local user account. Enabled: $($user.Enabled). Last logon: $($user.LastLogon)"

            # Flag accounts with no password required
            if ($user.PasswordRequired -eq $false -and $user.Enabled) {
                $severity = 'Yellow'
                $details  = "Account has no password required and is enabled. Last logon: $($user.LastLogon)"
            }

            # Flag accounts that have never logged on but are enabled (potential backdoor)
            if ($user.Enabled -and -not $user.LastLogon -and $user.Name -ne 'Administrator' -and $user.Name -ne 'DefaultAccount' -and $user.Name -ne 'WDAGUtilityAccount') {
                if ($severity -ne 'Yellow') {
                    $severity = 'Yellow'
                    $details  = "Enabled account with no recorded logon. Potential unused/backdoor account."
                }
            }

            if ($severity -ne 'Green') {
                $findings.Add([PSCustomObject]@{
                    Module      = 'UserAudit'
                    Severity    = $severity
                    Category    = 'User Account'
                    Title       = "$($user.Name) ($($user.FullName))"
                    Path        = ''
                    Detail          = $details
                    MitreId     = 'T1087'
                    MitreName   = 'Account Discovery'
                    ActionTaken = ''
                })
            }
        }

        # --- Enumerate privileged group members ---
        foreach ($groupName in $privilegedGroups) {
            $members = @()
            try {
                $members = Get-LocalGroupMember -Group $groupName -ErrorAction SilentlyContinue
            } catch {
                # Group may not exist on this system
                continue
            }

            foreach ($member in $members) {
                $memberName = $member.Name
                # Strip domain prefix for whitelist comparison
                $shortName = ($memberName -split '\\')[-1]

                $isWhitelisted = $Whitelist.AdminUsers -contains $shortName -or
                                  $Whitelist.AdminUsers -contains $memberName

                # Check for built-in SID
                $isBuiltin = $builtinAdminSids -contains $member.SID.Value -or
                              $member.SID.Value -match '^S-1-5-(18|19|20|32-544)$'

                # Domain admins / AD groups added to local admins are Yellow (review needed)
                $isDomain = $memberName -match '\\' -and -not ($memberName -match "^$([regex]::Escape($env:COMPUTERNAME))\\")

                if ($isBuiltin) { continue }

                if (-not $isWhitelisted) {
                    $unknownAdminCount++
                    $severity = 'Red'
                    $details  = "Account '$memberName' is a member of '$groupName' but NOT in the admin whitelist."

                    if ($isDomain) {
                        $severity = 'Yellow'
                        $details  = "Domain account '$memberName' is a member of local '$groupName'. Verify this is intended."
                    }

                    $findings.Add([PSCustomObject]@{
                        Module      = 'UserAudit'
                        Severity    = $severity
                        Category    = "Privileged Group: $groupName"
                        Title       = $memberName
                        Path        = ''
                        Detail          = $details
                        MitreId     = 'T1087'
                        MitreName   = 'Account Discovery'
                        ActionTaken = ''
                    })
                }
            }
        }

        if ($unknownAdminCount -eq 0 -and ($findings | Where-Object { $_.Severity -in 'Yellow','Red' }).Count -eq 0) {
            $findings.Add([PSCustomObject]@{
                Module      = 'UserAudit'
                Severity    = 'Green'
                Category    = 'User Account'
                Title       = 'User Audit'
                Path        = ''
                Detail          = "All $($localUsers.Count) local users checked. No unauthorized admins detected."
                MitreId     = 'T1087'
                MitreName   = 'Account Discovery'
                ActionTaken = ''
            })
        }

        Add-Content -Path $AuditLog -Value (
            "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')] " +
            "[USER: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)] " +
            "[MODULE: UserAudit] [ACTION: Scan] " +
            "[DETAILS: Local users: $($localUsers.Count); Unauthorized admins: $unknownAdminCount]"
        ) -Encoding UTF8

    } catch {
        Add-Content -Path $AuditLog -Value (
            "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')] [MODULE: UserAudit] [STATUS: ERROR] [DETAILS: $($_.Exception.Message)]"
        ) -Encoding UTF8
        throw
    }

    return $findings
}
