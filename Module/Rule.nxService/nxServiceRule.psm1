# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
using module .\..\Common\Common.psm1
using module .\..\Rule\Rule.psm1
#header

<#
    .SYNOPSIS
        An nxService Rule object
    .DESCRIPTION
        The nxServiceRule class is used to manage the Linux services/daemons.
    .PARAMETER Name
        The name of the service/daemon to configure.
    .PARAMETER Controller
        The type of service controller to use when configuring the service.
    .PARAMETER Enabled
        Indicates whether the service starts on boot.
    .PARAMETER State
        Indicates whether the service is running.
#>
Class nxServiceRule : Rule
{
    [string] $Name
    [string] $Controller
    [bool] $Enabled
    [string] $State

    <#
        .SYNOPSIS
            Default constructor to support the AsRule cast method
    #>
    nxServiceRule ()
    {
    }

        <#
        .SYNOPSIS
            Used to load PowerSTIG data from the processed data directory
        .PARAMETER Rule
            The STIG rule to load
    #>
    nxServiceRule ([xml.xmlelement] $Rule) : Base ($Rule)
    {
    }

        <#
        .SYNOPSIS
            The Convert child class constructor
        .PARAMETER Rule
            The STIG rule to convert
        .PARAMETER Convert
            A simple bool flag to create a unique constructor signature
    #>
    nxServiceRule ([xml.xmlelement] $Rule, [switch] $Convert) : Base ($Rule, $Convert)
    {
    }
}
