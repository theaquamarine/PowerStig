# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

<#
    Instructions:  Use this file to add/update/delete regsitry expressions that are used accross 
    multiple technologies files that are considered commonly used.  Enure expressions are listed
    from MOST Restrive to LEAST Restrictive, similar to exception handling.  Also, ensure only
    UNIQUE Keys are used in each hashtable to prevent errors and conflicts.
#>
$global:SingleLineRegistryPath =+ [ordered]@{
    McAfee1 = [ordered]@{
        Join = 'HKLM\Software\Wow6432Node\McAfee'
        Match = '\(32-bit\)'
        Match2 = '\(64-bit\)'
    }
}