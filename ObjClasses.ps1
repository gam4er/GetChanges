#requires -version 5.1
<#
.SYNOPSIS
    Показывает все objectClass, которые реально встречаются
    у существующих объектов в текущем домене, и их schemaIDGUID.

.DESCRIPTION
    Без RSAT.
    Без ActiveDirectory module.
    Использует ADSI + System.DirectoryServices.DirectorySearcher.

    1. Сканирует defaultNamingContext текущего домена.
    2. Собирает все реально встречающиеся значения objectClass.
    3. Для каждого значения ищет classSchema в Schema NC.
    4. Выводит objectClass, schemaIDGUID и количество объектов.

.EXAMPLE
    .\ObjClasses.ps1

.EXAMPLE
    .\ObjClasses.ps1 -LeafOnly

.EXAMPLE
    .\ObjClasses.ps1 -Server server.domain.ru

.EXAMPLE
    .\ObjClasses.ps1 -ExportCsv .\objectclasses-with-guids.csv

.EXAMPLE
    .\ObjClasses.ps1 -IncludeSchemaObjectGuid
#>

param(
    # Учитывать только последний, наиболее специфичный objectClass.
    # Например:
    #   top
    #   person
    #   organizationalPerson
    #   user
    #
    # Без -LeafOnly будут учтены все четыре значения.
    # С -LeafOnly будет учтён только user.
    [switch]$LeafOnly,

    # Размер страницы для DirectorySearcher.
    [int]$PageSize = 1000,

    # Можно явно указать DC.
    # Например: server.domain.ru
    [string]$Server,

    # Добавить в вывод objectGUID самого classSchema-объекта.
    # Обычно для анализа ACL нужен не он, а schemaIDGUID.
    [switch]$IncludeSchemaObjectGuid,

    # CSV-экспорт.
    [string]$ExportCsv
)

Add-Type -AssemblyName System.DirectoryServices

function Convert-ADByteGuid {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Value
    )

    if ($Value -is [byte[]]) {
        return ([guid]::new([byte[]]$Value)).Guid
    }

    # Иногда ADSI может вернуть массив/обёртку, где первый элемент — byte[].
    if ($Value -is [System.Array] -and $Value.Count -gt 0 -and $Value[0] -is [byte[]]) {
        return ([guid]::new([byte[]]$Value[0])).Guid
    }

    return $null
}

function Escape-LdapFilterValue {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    # RFC4515 escaping:
    # *  -> \2a
    # (  -> \28
    # )  -> \29
    # \  -> \5c
    # NUL -> \00
    $escaped = $Value
    $escaped = $escaped -replace '\\', '\5c'
    $escaped = $escaped -replace '\*', '\2a'
    $escaped = $escaped -replace '\(', '\28'
    $escaped = $escaped -replace '\)', '\29'
    $escaped = $escaped -replace "`0", '\00'

    return $escaped
}

$rootDsePath = if ([string]::IsNullOrWhiteSpace($Server)) {
    "LDAP://RootDSE"
} else {
    "LDAP://$Server/RootDSE"
}

$rootDse = [ADSI]$rootDsePath

$defaultNamingContext = [string]$rootDse.defaultNamingContext
$schemaNamingContext  = [string]$rootDse.schemaNamingContext
$dnsHostName          = [string]$rootDse.dnsHostName

if ([string]::IsNullOrWhiteSpace($defaultNamingContext)) {
    throw "Не удалось получить defaultNamingContext из RootDSE: $rootDsePath"
}

if ([string]::IsNullOrWhiteSpace($schemaNamingContext)) {
    throw "Не удалось получить schemaNamingContext из RootDSE: $rootDsePath"
}

if ([string]::IsNullOrWhiteSpace($Server)) {
    $Server = $dnsHostName
}

$domainSearchRootPath = if ([string]::IsNullOrWhiteSpace($Server)) {
    "LDAP://$defaultNamingContext"
} else {
    "LDAP://$Server/$defaultNamingContext"
}

$schemaSearchRootPath = if ([string]::IsNullOrWhiteSpace($Server)) {
    "LDAP://$schemaNamingContext"
} else {
    "LDAP://$Server/$schemaNamingContext"
}

Write-Host "LDAP server: $Server"
Write-Host "Domain NC  : $defaultNamingContext"
Write-Host "Schema NC  : $schemaNamingContext"
Write-Host "Leaf only  : $LeafOnly"
Write-Host ""

# -------------------------------------------------------------------------
# 1. Собираем реально встречающиеся objectClass из объектов домена
# -------------------------------------------------------------------------

$domainRoot = New-Object System.DirectoryServices.DirectoryEntry($domainSearchRootPath)
$searcher = New-Object System.DirectoryServices.DirectorySearcher($domainRoot)

$searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
$searcher.Filter = "(objectClass=*)"
$searcher.PageSize = $PageSize
$searcher.CacheResults = $false
$searcher.ReferralChasing = [System.DirectoryServices.ReferralChasingOption]::None

$searcher.PropertiesToLoad.Clear()
[void]$searcher.PropertiesToLoad.Add("objectClass")

$classes = New-Object 'System.Collections.Generic.Dictionary[string,long]' ([System.StringComparer]::OrdinalIgnoreCase)
$totalObjects = 0L

try {
    $results = $searcher.FindAll()

    try {
        foreach ($result in $results) {
            $totalObjects++

            $props = $result.Properties

            if (-not $props.Contains("objectclass")) {
                continue
            }

            $objectClasses = @(
                $props["objectclass"] | ForEach-Object {
                    [string]$_
                }
            )

            if ($objectClasses.Count -eq 0) {
                continue
            }

            if ($LeafOnly) {
                $objectClasses = @($objectClasses[-1])
            }

            foreach ($objectClass in $objectClasses) {
                if ([string]::IsNullOrWhiteSpace($objectClass)) {
                    continue
                }

                if ($classes.ContainsKey($objectClass)) {
                    $classes[$objectClass]++
                } else {
                    $classes[$objectClass] = 1
                }
            }
        }
    }
    finally {
        if ($null -ne $results) {
            $results.Dispose()
        }
    }
}
catch {
    throw @"
LDAP domain search failed.

Server:      $Server
Search base: $defaultNamingContext
Search path: $domainSearchRootPath
Filter:      (objectClass=*)

Original error:
$($_.Exception.Message)
"@
}

# -------------------------------------------------------------------------
# 2. Для каждого objectClass ищем соответствующий classSchema и schemaIDGUID
# -------------------------------------------------------------------------

$schemaRoot = New-Object System.DirectoryServices.DirectoryEntry($schemaSearchRootPath)
$schemaSearcher = New-Object System.DirectoryServices.DirectorySearcher($schemaRoot)

$schemaSearcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
$schemaSearcher.PageSize = 1000
$schemaSearcher.CacheResults = $false
$schemaSearcher.ReferralChasing = [System.DirectoryServices.ReferralChasingOption]::None

$schemaSearcher.PropertiesToLoad.Clear()
[void]$schemaSearcher.PropertiesToLoad.Add("lDAPDisplayName")
[void]$schemaSearcher.PropertiesToLoad.Add("schemaIDGUID")
[void]$schemaSearcher.PropertiesToLoad.Add("objectGUID")
[void]$schemaSearcher.PropertiesToLoad.Add("cn")

$schemaByLdapDisplayName = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::OrdinalIgnoreCase)

foreach ($className in $classes.Keys) {
    $escapedClassName = Escape-LdapFilterValue -Value $className

    $schemaSearcher.Filter = "(&(objectClass=classSchema)(lDAPDisplayName=$escapedClassName))"

    $schemaResult = $schemaSearcher.FindOne()

    if ($null -eq $schemaResult) {
        $schemaByLdapDisplayName[$className] = [pscustomobject]@{
            schemaIDGUID          = $null
            classSchemaObjectGUID = $null
            cn                    = $null
            FoundInSchema         = $false
        }

        continue
    }

    $p = $schemaResult.Properties

    $schemaIDGUID = $null
    if ($p.Contains("schemaidguid") -and $p["schemaidguid"].Count -gt 0) {
        $schemaIDGUID = Convert-ADByteGuid -Value $p["schemaidguid"][0]
    }

    $classSchemaObjectGUID = $null
    if ($p.Contains("objectguid") -and $p["objectguid"].Count -gt 0) {
        $classSchemaObjectGUID = Convert-ADByteGuid -Value $p["objectguid"][0]
    }

    $cn = $null
    if ($p.Contains("cn") -and $p["cn"].Count -gt 0) {
        $cn = [string]$p["cn"][0]
    }

    $schemaByLdapDisplayName[$className] = [pscustomobject]@{
        schemaIDGUID          = $schemaIDGUID
        classSchemaObjectGUID = $classSchemaObjectGUID
        cn                    = $cn
        FoundInSchema         = $true
    }
}

# -------------------------------------------------------------------------
# 3. Формируем вывод
# -------------------------------------------------------------------------

$output = foreach ($item in $classes.GetEnumerator()) {
    $className = $item.Key
    $count     = $item.Value

    $schemaInfo = $schemaByLdapDisplayName[$className]

    $row = [ordered]@{
        objectClass      = $className
        schemaIDGUID     = $schemaInfo.schemaIDGUID
        ObjectsWithClass = $count
        FoundInSchema    = $schemaInfo.FoundInSchema
    }

    if ($IncludeSchemaObjectGuid) {
        $row["classSchemaObjectGUID"] = $schemaInfo.classSchemaObjectGUID
        $row["classSchemaCN"]         = $schemaInfo.cn
    }

    [pscustomobject]$row
}

$output = $output | Sort-Object objectClass

Write-Host "Scanned objects: $totalObjects"
Write-Host "Distinct objectClass values: $($output.Count)"
Write-Host ""

$output | Out-GridView

if (-not [string]::IsNullOrWhiteSpace($ExportCsv)) {
    $output |
        Export-Csv -NoTypeInformation -Encoding UTF8 -Path $ExportCsv

    Write-Host ""
    Write-Host "CSV exported: $ExportCsv"
}