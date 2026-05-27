# Get-RodchenkoReplAttributeMetadata-ADSI.ps1
# Requires: domain-joined context or credentials already available to current logon session.
# Does NOT require RSAT / ActiveDirectory PowerShell module.

[CmdletBinding()]
param(
    [string]$SamAccountName = 'user',

    # Optional: DC DNS name, for example: AD-GAM.gam.click
    [string]$DomainController,

    # Optional: explicit search base, for example: DC=gam,DC=click
    [string]$SearchBase
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Escape-LdapFilterValue {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Value
    )

    # RFC4515-ish escaping for LDAP filter assertion values.
    $sb = [System.Text.StringBuilder]::new()

    foreach ($ch in $Value.ToCharArray()) {
        switch ([int][char]$ch) {
            0  { [void]$sb.Append('\00') } # NUL
            40 { [void]$sb.Append('\28') } # (
            41 { [void]$sb.Append('\29') } # )
            42 { [void]$sb.Append('\2a') } # *
            92 { [void]$sb.Append('\5c') } # \
            default { [void]$sb.Append($ch) }
        }
    }

    $sb.ToString()
}

function ConvertTo-ReplMetadataXmlText {
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        $RawValue
    )

    process {
        if ($RawValue -is [byte[]]) {
            $bytes = [byte[]]$RawValue

            # msDS-ReplAttributeMetaData is Unicode string by schema, but depending on
            # how the value is returned, you may see either byte[] or string.
            # Detect likely UTF-16LE by checking NUL bytes in odd positions.
            $sampleLength = [Math]::Min($bytes.Length, 256)
            $zeroOdd = 0

            for ($i = 1; $i -lt $sampleLength; $i += 2) {
                if ($bytes[$i] -eq 0) {
                    $zeroOdd++
                }
            }

            if ($zeroOdd -ge 8) {
                $s = [System.Text.Encoding]::Unicode.GetString($bytes)
            }
            else {
                $s = [System.Text.Encoding]::UTF8.GetString($bytes)
            }
        }
        else {
            $s = [string]$RawValue
        }

        # Some paths return embedded NUL chars; XML parser hates them.
        $s = ($s -replace "`0", '').Trim()

        if ($s.Length -gt 0) {
            $s
        }
    }
}

function ConvertFrom-ReplMetadataXml {
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$XmlText,

        [Parameter(Mandatory)]
        [string]$ObjectDN,

        [string]$Server
    )

    process {
        $nodes = @()

        try {
            [xml]$xml = $XmlText

            if ($xml.DS_REPL_ATTR_META_DATA) {
                $nodes = @($xml.DS_REPL_ATTR_META_DATA)
            }
            elseif ($xml.root.DS_REPL_ATTR_META_DATA) {
                $nodes = @($xml.root.DS_REPL_ATTR_META_DATA)
            }
        }
        catch {
            # Sometimes values may be concatenated or returned as XML fragments.
            # Wrap into a synthetic root and try again.
            try {
                [xml]$xml = "<root>$XmlText</root>"
                $nodes = @($xml.root.DS_REPL_ATTR_META_DATA)
            }
            catch {
                Write-Warning "Cannot parse msDS-ReplAttributeMetaData XML fragment for object '$ObjectDN'. Error: $($_.Exception.Message)"
                return
            }
        }

        foreach ($m in $nodes) {
            $attrName = [string]$m.pszAttributeName

            $changeTimeUtc = $null
            if (-not [string]::IsNullOrWhiteSpace([string]$m.ftimeLastOriginatingChange)) {
                $changeTimeUtc = [datetime]::Parse(
                    [string]$m.ftimeLastOriginatingChange,
                    [System.Globalization.CultureInfo]::InvariantCulture,
                    [System.Globalization.DateTimeStyles]::AssumeUniversal -bor
                    [System.Globalization.DateTimeStyles]::AdjustToUniversal
                )
            }

            $invocationId = $null
            if (-not [string]::IsNullOrWhiteSpace([string]$m.uuidLastOriginatingDsaInvocationID)) {
                $invocationId = [guid]([string]$m.uuidLastOriginatingDsaInvocationID)
            }

            $version = $null
            if (-not [string]::IsNullOrWhiteSpace([string]$m.dwVersion)) {
                $version = [int64]([string]$m.dwVersion)
            }

            $originatingUsn = $null
            if (-not [string]::IsNullOrWhiteSpace([string]$m.usnOriginatingChange)) {
                $originatingUsn = [int64]([string]$m.usnOriginatingChange)
            }

            $localUsn = $null
            if (-not [string]::IsNullOrWhiteSpace([string]$m.usnLocalChange)) {
                $localUsn = [int64]([string]$m.usnLocalChange)
            }

            [pscustomobject][ordered]@{
                ObjectDN                         = $ObjectDN
                AttributeName                    = $attrName
                Version                          = $version
                LastOriginatingChangeTimeUtc      = $changeTimeUtc
                LastOriginatingDsaInvocationId    = $invocationId
                OriginatingUSN                   = $originatingUsn
                LocalUSN                         = $localUsn
                LastOriginatingDsaDN              = [string]$m.pszLastOriginatingDsaDN
                QueriedServer                    = $Server
                RawXml                           = $XmlText
            }
        }
    }
}

# Resolve naming context.
$rootDsePath = if ($DomainController) {
    "LDAP://$DomainController/RootDSE"
}
else {
    "LDAP://RootDSE"
}

$rootDse = [ADSI]$rootDsePath

if (-not $SearchBase) {
    $SearchBase = [string]$rootDse.defaultNamingContext
}

if ([string]::IsNullOrWhiteSpace($SearchBase)) {
    throw "Cannot determine defaultNamingContext. Provide -SearchBase explicitly."
}

$ldapBasePath = if ($DomainController) {
    "LDAP://$DomainController/$SearchBase"
}
else {
    "LDAP://$SearchBase"
}

$baseEntry = [ADSI]$ldapBasePath

# Search user.
$escapedSam = Escape-LdapFilterValue -Value $SamAccountName

$searcher = [System.DirectoryServices.DirectorySearcher]::new($baseEntry)
$searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
$searcher.PageSize = 500
$searcher.Filter = "(&(objectCategory=person)(objectClass=user)(sAMAccountName=$escapedSam))"

[void]$searcher.PropertiesToLoad.Add('distinguishedName')
[void]$searcher.PropertiesToLoad.Add('sAMAccountName')
[void]$searcher.PropertiesToLoad.Add('msDS-ReplAttributeMetaData')

$result = $searcher.FindOne()

if (-not $result) {
    throw "User with sAMAccountName '$SamAccountName' was not found under '$SearchBase'."
}

$objectDn = [string]$result.Properties['distinguishedname'][0]

if (-not $result.Properties.Contains('msds-replattributemetadata')) {
    throw "Object '$objectDn' did not return msDS-ReplAttributeMetaData. Check permissions/DC/search target."
}

$rawValues = @($result.Properties['msds-replattributemetadata'])

$parsed = foreach ($raw in $rawValues) {
    $raw |
        ConvertTo-ReplMetadataXmlText |
        ConvertFrom-ReplMetadataXml -ObjectDN $objectDn -Server $DomainController
}

$parsed |
    Sort-Object LastOriginatingChangeTimeUtc -Descending