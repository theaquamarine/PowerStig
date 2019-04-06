# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
using module .\..\..\Common\Common.psm1
using module .\..\nxServiceRule.psm1

$exclude = @($MyInvocation.MyCommand.Name,'Template.*.txt')
$supportFileList = Get-ChildItem -Path $PSScriptRoot -Exclude $exclude
foreach ($supportFile in $supportFileList)
{
    Write-Verbose "Loading $($supportFile.FullName)"
    . $supportFile.FullName
}
# Header

<#
    .SYNOPSIS
        Convert the contents of an xccdf check-content element into a process
        nxServiceRule object
    .DESCRIPTION
        The nxServiceRule class is used to extract the nxService
        settings from the check-content of the xccdf. Once a STIG rule is identified
        a process nxService rule, it is passed to the nxServiceRule class
        for parsing and validation.
#>
Class nxServiceRuleConvert : nxServiceRule
{
    <#
        .SYNOPSIS
            Empty constructor for SplitFactory
    #>
    nxServiceRuleConvert ()
    {
    }

    <#
        .SYNOPSIS
            Converts a xccdf stig rule element into a nxService Rule
        .PARAMETER XccdfRule
            The STIG rule to convert
    #>
    nxServiceRuleConvert ([xml.xmlelement] $XccdfRule) : Base ($XccdfRule, $true)
    {
        $fixText = [nxServiceRule]::GetFixText($XccdfRule)
        $properties = Get-nxServiceRuleProperty -FixText $FixText
        $this.SetServiceName($properties)
        $this.SetController($properties)
        $this.SetEnabled($properties)
        $this.SetState($properties)
        if ($this.conversionstatus -eq 'pass')
        {
            $this.SetDuplicateRule()
        }
        $this.SetDscResource()
    }

    #region Methods

    <#
        .SYNOPSIS
            Extracts the mitigation target name from the check-content and sets
            the value
        .DESCRIPTION
            Gets the nxService name from the xccdf content and sets the
            value. If the nxService name that is returned is not valid,
            the parser status is set to fail
    #>
    [void] SetServiceName ([object[]]$properties)
    {
        if (-not $this.SetStatus($properties.Name))
        {
            $this.set_Name($properties.Name)
        }
    }

    <#
        .SYNOPSIS
            Extracts the Controller name from the check-content and sets
            the value
        .DESCRIPTION
            Gets the Controller name from the xccdf content and sets the
            value. If the Controller name that is returned is not valid,
            the parser status is set to fail
    #>
    [void] SetController ([object[]]$properties)
    {
        if (-not $this.SetStatus($properties.Controller))
        {
            $this.set_Controller($properties.Controller)
        }
    }

    <#
        .SYNOPSIS
            Extracts the Controller name from the check-content and sets
            the value
        .DESCRIPTION
            Gets the Controller name from the xccdf content and sets the
            value. If the Controller name that is returned is not valid,
            the parser status is set to fail
    #>
    [void] SetEnabled ([object[]]$properties)
    {
        if (-not $this.SetStatus($properties.Enabled))
        {
            $this.set_Enabled($properties.Enabled)
        }
    }

    <#
        .SYNOPSIS
            Extracts the Service Running State from the check-content and sets
            the value
        .DESCRIPTION
            Gets the Service Running State from the xccdf content and sets the
            value. If the Service Running State that is returned is not valid,
            the parser status is set to fail
    #>
    [void] SetState ([object[]]$properties)
    {
        if (-not $this.SetStatus($properties.State))
        {
            $this.set_State($properties.State)
        }
    }

    static [bool] Match ([string] $FixText)
    {
        if ($FixText -Match 'systemctl.*(disable|enable|start).*')
        {
            return $true
        }
        return $false
    }
}
