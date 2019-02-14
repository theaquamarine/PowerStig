#region Header
# Convert Class Private functions Header V1
$script:moduleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$script:moduleName = 'PowerStig'
$script:modulePath = "$($script:moduleRoot)\$($script:moduleName).psd1"

Import-Module -Name (Join-Path -Path $script:moduleRoot -ChildPath 'PowerStig.Convert.psm1') -Force
Import-Module -Name (Join-Path -Path $script:moduleRoot -ChildPath 'Tools\TestHelper\TestHelper.psm1') -Force

$latestStigs = Get-LatestStigList -StigFolderPath (Join-Path -Path $script:moduleRoot -ChildPath 'StigData\Processed')

foreach ($stig in $latestStigs)
{
    Describe "$($stig.Name)" {
        Context "When $($stig.Name) is converted" {
            $result = Compare-Stig -StigXmlPath $stig.Fullname
            It 'Should not return any changed values from the currently stored STIGs.' {
                $result.RuleValueChange.id | Should -Be $null
            }
            It 'Should not have any changed rule types' {
                $result.RuleTypeChange.RuleId | Should -Be $null
            }
        }
    }
}
