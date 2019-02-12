<#
.SYNOPSIS
    Compares a STIG against an already processed STIG

.DESCRIPTION
Compare-Stig will compares a processed STIG against an unprocessed STIG of either the same or a different version
of a STIG to see what, if any, changes have occured. Changes can be from differences in new versions of a STIG
or if the parsing process has changed.

.PARAMETER StigXmlPath
    The path to the already processed XML STIG

.PARAMETER StigXccdfPath
    Optional parameter to the unprocessed STIG to compare.

.PARAMETER XccdfVersion
    Optional parameter to define the version of unprocessed STIG to compare.

.EXAMPLE
    In this example we compare an XML STIG against a new version.
        Compare-Stig -StigXmlPath 'C:\Temp\U_Windows_2012_and_2012_R2_MS_STIG_V2R14_Manual-xccdf.xml' -Version 2.15

.NOTES
    If no 'Version' or 'StigXccdfPath' are provided, the function will compare the same version as the provided 'StigXmlPath'
#>
function Compare-Stig
{
    [CmdletBinding()]
    [OutputType([psobject])]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $StigXmlPath,

        [Parameter()]
        [AllowNull()]
        [string]
        $StigXccdfPath,

        [Parameter()]
        [AllowNull()]
        $XccdfVersion
    )

    $ruleResults = [ordered] @{
        AddedRule       = @()
        RemovedRule     = @()
        RuleTypeChange  = @()
        RuleValueChange = @()
    }

    if (-not $StigXccdfPath)
    {
        $StigXccdfPath = Get-StigXccdfPath -StigXmlPath $StigXmlPath -Version $XccdfVersion
    }
    # Get path to the temporary STIG conversion to remove later.
    $unmatchedPath = ConvertTo-PowerStigXml -Path $StigXccdfPath -Destination $env:TEMP
    $differenceStigPath = (Select-String -InputObject $unmatchedPath -Pattern "(?<=Converted Output: ).*").Matches.Value

    [xml] $newStigContent = Get-Content -Path $differenceStigPath
    [xml] $oldStigContent = Get-Content -Path $StigXmlPath

    $ruleTypes = Get-RuleType -DisaStigContent $oldStigContent.DISASTIG

    foreach ($ruleType in $ruleTypes)
    {
        foreach ($referenceRule in $oldStigContent.DISASTIG.$ruleType.Rule)
        {
            $differenceRule = $newStigContent.DISASTIG.$ruleType.Rule | Where-Object -FilterScript {$_.id -eq $referenceRule.id}
            if ($null -eq $differenceRule)
            {
                $newRuleType = Get-NewRuleType -Id $referenceRule.id -StigContent $newStigContent
                if ($null -ne $newRuleType)
                {
                    $ruleResults.RuleTypeChange += New-Object -TypeName psobject -Property @{
                        RuleId       = $referenceRule.Id
                        NewRuleType  = $newRuleType.RuleType
                        OldRuleType  = $referenceRule.ToString()
                        NewRawString = $newRuleType.RawString
                        OldRawString = $referenceRule.RawString
                    }
                }
            }
            else
            {
                $difference = Compare-StigRule -ReferenceRule $referenceRule -DifferenceRule $differenceRule -RuleType $ruleType

                if ($null -ne $difference)
                {
                    $difference.NewRawString = $differenceRule.RawString
                    $difference.OldRawString = $referenceRule.RawString

                    $differenceObject = New-Object -TypeName psobject -Property $difference

                    Write-Verbose -Message "Rule $($differenceRule.id) has been changed."
                    $ruleResults.RuleValueChange += $differenceObject
                }
                else
                {
                    Write-Verbose -Message "Rule $($differenceRule.id) is not changed."
                }
            }

            $oldRuleId = Get-AllStigId -StigContent $oldStigContent
            $newRuleId = Get-AllStigId -StigContent $newStigContent

            $NewAndRemovedRuleId = Get-AddedOrRemovedRuleId -NewId $newRuleId -OldId $oldRuleId

            $ruleResults.AddedRule = $NewAndRemovedRuleId.AddedRuleId
            $ruleResults.RemovedRule = $NewAndRemovedRuleId.RemovedRuleId
        }
    }

    # Remove temporary STIG conversion.
    Remove-Item -Path $differenceStigPath -Force

    return $ruleResults
}

<#
.SYNOPSIS
    Compares the reference rule against the difference rule.

.PARAMETER ReferenceRule
    The processed STIG rule to be compared against

.PARAMETER DifferenceRule
    Newly Processed STIG rule to compare

.PARAMETER RuleType
    Rule Type of the rule function is comparing.
#>
function Compare-StigRule
{
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]
        $ReferenceRule,

        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]
        $DifferenceRule,

        [Parameter(Mandatory = $true)]
        [string]
        $RuleType
    )

    $propertyNames = Get-RuleProperty -Rule $ReferenceRule
    $parameters = @{
        ReferenceRule  = $ReferenceRule
        DifferenceRule = $DifferenceRule
        PropertyName   = $propertyNames
        RuleType       = $RuleType
    }

    switch ($RuleType)
    {
        'PermissionRule'
        {
            $returnRule = Compare-NestedPropertyRule @parameters
        }
        default
        {
            $returnRule = Compare-Property @parameters
        }
    }
    
    if ($null -ne $returnRule.id)
    {
        return $returnRule
    }
    else 
    {
        $null = return
    }
}

<#
.SYNOPSIS
    Returns a list of property names to compare.

.PARAMETER Rule
    Rule to get a list of paroperties from.
#>
function Get-RuleProperty
{
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]
        $Rule
    )

    $toRemove = @(
        'IsNullOrEmpty',
        'Severity',
        'Title',
        'dscresource',
        'RawString'
    )

    $propertyNames = (Get-Member -InputObject $Rule | Where-Object -FilterScript {$_.MemberType -eq 'Property'}).Name
    $propertyNames = $propertyNames | Where-Object -FilterScript {$_ -notin $toRemove}

    return $propertyNames
}

<#
.SYNOPSIS
    Returns the difference between properties

.DESCRIPTION
    If a difference is found between properties, an object is returned containing 
    the new and old properties. If no difference is found, nothing is returned

.PARAMETER ReferenceRule
    Reference Rule to compare against

.PARAMETER DifferenceRule
    Difference rule to compare against the reference rule.

.PARAMETER PropertyName
    Name of the property to compare.

.PARAMETER RuleType
    Type of rule being compared
#>
function Compare-Property
{
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]
        $ReferenceRule,

        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]
        $DifferenceRule,

        [Parameter(Mandatory = $true)]
        [string[]]
        $PropertyName,

        [Parameter(Mandatory = $true)]
        [string]
        $RuleType
    )

    $return = [ordered] @{}

    foreach ($property in $PropertyName)
    {
        if (Test-Property -ReferenceProperty $ReferenceRule.$property -DifferenceProperty $DifferenceRule.$property)
        {
            if (-not($return.id))
            {
                $return.id = $ReferenceRule.id
                $return.RuleType = $RuleType
            }
            
            $return."Old$property" = $ReferenceRule.$property
            $return."New$property" = $DifferenceRule.$property
        }
    }

    if ($null -ne $return.id)
    {
        return $return
    }
    else 
    {
        $null = return 
    }
}

<#
.SYNOPSIS
    Returns a boolean where the properties are different

.DESCRIPTION
    Some properties are not a straight comparison and need to be adjusted
    for accurate results.

.PARAMETER ReferenceProperty
    Property to be compared against.

.PARAMETER DifferenceProperty
    Property to campare against the reference property.
#>
function Test-Property
{
    [CmdletBinding()]
    [OutputType([Bool])]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        $ReferenceProperty,

        [Parameter(Mandatory = $true)]
        [AllowNull()]
        $DifferenceProperty
    )

    if ($null -eq $ReferenceProperty -or $null -eq $DifferenceProperty)
    {
        if ($null -eq $ReferenceProperty)
        {
            $ReferenceProperty = ''
        }
        if ($null -eq $DifferenceProperty)
        {
            $DifferenceProperty = ''
        }

        $return = $ReferenceProperty -ne $DifferenceProperty
    }
    elseif ($DifferenceProperty.GetType().ToString() -eq 'System.String[]')
    {
        $return = $ReferenceProperty.ToString() -ne $DifferenceProperty
    }
    else
    {
        $return = $ReferenceProperty.ToString() -ne $DifferenceProperty.ToString()
    }

    return $return
}

<#
.SYNOPSIS
    Compares properties that have nested attributes

.PARAMETER ReferenceRule
    Reference Rule to compare against

.PARAMETER DifferenceRule
    Difference rule to compare against the reference rule.

.PARAMETER PropertyName
    Name of property to compare.

.PARAMETER RuleType
    Type of rule being compared.
#>
function Compare-NestedPropertyRule
{
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]
        $ReferenceRule,

        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]
        $DifferenceRule,

        [Parameter(Mandatory = $true)]
        [string[]]
        $PropertyName,

        [Parameter(Mandatory = $true)]
        [string]
        $RuleType
    )

    $newPropertyNames = $PropertyName | Where-Object -FilterScript {$_ -ne 'AccessControlEntry'}

    $return = Compare-Property -ReferenceRule $ReferenceRule -DifferenceRule $DifferenceRule -PropertyName $newPropertyNames -RuleType $RuleType
    $accessControlDiff = Compare-AccessControl `
        -ReferenceList $ReferenceRule.AccessControlEntry.Entry `
        -DifferenceList $DifferenceRule.AccessControlEntry.Entry

    if ($null -ne $return)
    {
        if ($null -ne $accessControlDiff)
        {
            $return.OldAccessControlList = $accessControlDiff.OldAccessControlList
            $return.NewAccessControlList = $accessControlDiff.NewAccessControlList
        }
        
        return $return
    }
    else
    {
        if ($null -ne $accessControlDiff)
        {
            $return = [ordered] @{
                id                   = $DifferenceRule.id
                RuleType             = $RuleType
                OldAccessControlList = $accessControlDiff.OldAccessControlList
                NewAccessControlList = $accessControlDiff.NewAccessControlList
            }

            return $return
        }
        else
        {
            $null = return
        }
    }
}

<#
.SYNOPSIS
    Compares Access Control Entries from AccessControlRules

.PARAMETER ReferenceList
    Access Control List to compare against.

.PARAMETER DifferenceList
    Access Control List to compare against the reference ACL
#>
function Compare-AccessControl
{
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.Object[]]
        $ReferenceList,

        [Parameter(Mandatory = $true)]
        [System.Object[]]
        $DifferenceList
    )
    
    $returnList = [ordered]@{
        OldAccessControlList = @()
        NewAccessControlEntry = @()
    }

    foreach ($referenceEntry in $ReferenceList)
    {
        $differenceEntry = $DifferenceList | Where-Object -FilterScript {
            $_.Principal -eq $referenceEntry.Principal -and
            $_.Inheritance -eq $referenceEntry.Inheritance -and
            $_.Rights -eq $referenceEntry.Rights
        }

        if ($null -eq $differenceEntry)
        {
            $returnList.OldAccessControlList += $referenceEntry
        }
        else
        {
            if (Test-Property -ReferenceProperty $referenceEntry.ForcePrincipal -DifferenceProperty $differenceEntry.ForcePrincipal)
            {
                $returnList.OldAccessControlList += $referenceEntry
                $returnList.NewAccessControlList += $differenceEntry    

                break
            }
        }
    }

    # We tested that Reference Entries had a difference companion but nee to do the same for the Difference Entries.
    foreach ($differenceEntry in $DifferenceList)
    {
        $referenceMatch = $ReferenceList | Where-Object -FilterScript {
            $_.Principal -eq $differenceEntry.Principal -and
            $_.Inheritance -eq $differenceEntry.Inheritance -and
            $_.Rights -eq $differenceEntry.Rights
        }
        if ($null -eq $referenceMatch)
        {
            $returnList.NewAccessControlList += $differenceEntry
        }
    }

    if ($returnList.OldAccessControlList.Count -gt 0 -or $returnList.NewAccessControlList.Count -gt 0)
    {
        return $returnList
    }

    $null = return
}

<#
.SYNOPSIS
    Returns a collection of rules Id's that have been added or removed.

.PARAMETER NewId
    Array of id's to compare from the newly processsed STIG

.PARAMETER OldId
    Array of Id's from the processed STIG XML
#>
function Get-AddedOrRemovedRuleId
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [Parameter(Mandatory = $true)]
        [array]
        $NewId,

        [Parameter(Mandatory = $true)]
        [array]
        $OldId
    )

    $returnId = @{
        AddedRuleId   = ($NewId | Where-Object -FilterScript {$_ -notin $OldId})
        RemovedRuleId = ($OldId | Where-Object -FilterScript {$_ -notin $NewId})
    }

    return $returnId
}

<#
.SYNOPSIS
    Returns a list of rule types from the STIG beign processed.

.PARAMETER DisaStigContent
    Content of the STIG being processed
#>
function Get-RuleType
{
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]
        $DisaStigContent
    )

    return (Get-Member -InputObject $DisaStigContent | Where-Object -FilterScript {$_.Name -match '.*Rule'}).Name
}

<#
.SYNOPSIS
    Checks to see if a rule has changed type.

.PARAMETER Id
    Rule Id to check.

.PARAMETER StigContent
    STIG Content to process.
#>
function Get-NewRuleType
{
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $Id,

        [Parameter(Mandatory = $true)]
        $StigContent
    )

    $ruleTypes = Get-RuleType -DisaStigContent $StigContent.DISASTIG

    foreach ($ruleType in $ruleTypes)
    {
        $returnRule = $StigContent.DISASTIG.$ruleType.Rule | Where-Object -FilterScript {$_.id -eq $Id}
        
        if ($null -ne $returnRule)
        {
            $returnObject = @{
                id        = $returnRule.id
                RawString = $returnRule.RawString
                RuleType  = $ruleType
            }

            return $returnObject
        }
    }

    $null = return
} 

<#
.SYNOPSIS
    Returns the list of STIG id's from STIG content

.PARAMETER StigContent
    Content of the STIG to process.
#>
function Get-AllStigId
{
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlDocument]
        $StigContent
    )

    $ruleId = @()

    $ruleTypes = Get-RuleType -DisaStigContent $StigContent.DISASTIG

    foreach ($ruleType in $ruleTypes)
    {
        $ruleId += $StigContent.DISASTIG.$RuleType.Rule.Id
    }

    return $ruleId
}

<#
.SYNOPSIS
    Returns the approate STIG XCCDF path to convert

.PARAMETER StigXmlPath
    XML Path to test against.

.PARAMETER Version
    Version of the XCCDF to convert and compare.
#>

function Get-StigXccdfPath
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $StigXmlPath,

        [Parameter()]
        [AllowNull()]
        $Version
    )
      
    if ($Version)
    {
        $versionSplit = $Version.Split('.')
    }
    else
    {
        $xmlTitle = ($StigXmlPath.Split('\')[-1]).Trim('.xml')
        $xmlSplit = $xmlTitle.Split('-')
        $versionPlace = $xmlSplit.Count - 1
        $versionSplit = $xmlSplit[$versionPlace].Split('.')
    }

    $stigVersion = "V$($versionSplit[0])R$($versionSplit[1])"

    [xml] $xmlContent = Get-Content -Path $StigXmlPath
    $stigId = $xmlContent.DISASTIG.Id
    if ($null -eq $stigId)
    {
        $stigId = $xmlContent.DisaStig.StigId
    }

    $archives = Get-ChildItem -Path "$Script:PSScriptRoot\..\..\StigData\Archive" -Recurse -Include "*.xml" | Where-Object -FilterScript {$_.Name -match ".*$stigVersion"}
    
    foreach ($stig in $archives)
    {
        [xml] $testContent = Get-Content -Path $stig.Fullname 
        $testId = $testContent.BenchMark.Id

        if ($testId -eq $stigId)
        {
            return $stig.Fullname
        }
    }

    throw "Cannot find xccdf for $xmlTitle. Please verify the desired xccdf is in the 'Archive' folder."
}
