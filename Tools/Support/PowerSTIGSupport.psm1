<#

#>
function Get-XccdfCheckContentRegExDetail
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $DataFilePath,

        [Parameter(Mandatory = $true)]
        [string]
        $XccdfPath,

        [Parameter()]
        [switch]
        $Recurse
    )

    $xccdfXml = ConvertTo-XccdfXml -Path $XccdfPath -Filter '*xccdf.xml' -Recurse
    $dataFiles = Get-ChildItem -Path $DataFilePath -Filter Data.ps1 -Recurse | Select-Object -ExpandProperty FullName

    foreach ($file in $dataFiles)
    {
        . $file
        foreach ($key in $regularExpression.Keys)
        {
            $xccdfRegExMatch = Get-XccdfCheckContentRegExMatch -XccdfXml $xccdfXml -RegExPattern $regularExpression[$key]

            [PSCustomObject]@{
                DataFile          = $file
                RegExKey          = $key
                RegExValue        = $regularExpression[$key]
                DetectedRule      = $xccdfRegExMatch.DetectedRule
                DetectedRuleCount = $xccdfRegExMatch.DetectedRuleCount
                UniqueRuleId      = $xccdfRegExMatch.UniqueRuleId
                UniqueRuleIdCount = $xccdfRegExMatch.UniqueRuleIdCount
            }
        }
    }
}

function Get-XccdfCheckContentRegExMatch
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [xml[]]
        $XccdfXml,

        [Parameter()]
        [switch]
        $Recurse,

        [Parameter(Mandatory = $true)]
        [string]
        $RegExPattern
    )

    $detectedRules = foreach ($group in $XccdfXml.Benchmark.Group)
    {
        if ($group.Rule.Check.'check-content' -match $RegExPattern)
        {
            $group
        }
    }

    $uniqueRuleId = $detectedRules | Select-Object -ExpandProperty id -Unique

    [PSCustomObject]@{
        DetectedRule      = $detectedRules
        DetectedRuleCount = $detectedRules.Count
        UniqueRuleId      = $uniqueRuleId
        UniqueRuleIdCount = $uniqueRuleId.Count
    }
}

function ConvertTo-XccdfXml
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $Path,

        [Parameter(Mandatory = $true)]
        [string]
        $Filter,

        [Parameter()]
        [switch]
        $Recurse
    )

    try
    {
        $unprocessedXccdf = Get-ChildItem @PSBoundParameters | Select-Object -ExpandProperty FullName
    }
    catch
    {
        # Localization description here...
    }

    $xml = @()

    foreach ($xccdf in $unprocessedXccdf)
    {
        $xml += [xml](Get-Content -Path $xccdf -Raw)
    }

    return $xml
}
