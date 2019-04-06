# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#region Method Functions

<#
    .SYNOPSIS
        Retreives the required nxServiceRule properties from the FixText element in the xccdf.

    .PARAMETER FixText
        Specifies the FixText element in the xccdf.
#>
function Get-nxServiceRuleProperty
{
    [CmdletBinding()]
    [OutputType([object[]])]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string[]]
        $FixText
    )

    $results = @()
    $patternMatches = $FixText | Select-String -Pattern 'systemctl.*(disable|enable|start|stop).*' -AllMatches

    foreach ($patternMatch in $patternMatches.matches.value)
    {
        if ($patternMatch -match 'disable|enable|start|stop')
        {
            $Controller, $state, $serviceName = $patternMatch -split '\s'

            $results +=[PSCustomObject]@{
                Controller  = $Controller
                Name        = $serviceName
                State       = $state | Where-Object -FilterScript {$PSItem -match 'start|stop'}
                Enabled     = $state | Where-Object -FilterScript {$PSItem -match 'enable|disable'}
            }
        }
    }
    # Need a way to combind the objects
}
