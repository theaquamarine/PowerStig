#region Header
using module .\..\..\..\Module\Rule.WindowsFeature\Convert\WindowsFeatureRule.Convert.psm1
. $PSScriptRoot\.tests.header.ps1
#endregion
try
{
    InModuleScope -ModuleName "$($script:moduleName).Convert" {
        #region Test Data
        $testRuleList = @(
            @{
                FeatureName = 'TelnetClient'
                InstallState = 'Absent'
                OrganizationValueRequired = $false
                CheckContent = 'The "Telnet Client" is not installed by default.  Verify it has not been installed.

                Navigate to the Windows\System32 directory.

                If the "telnet" application exists, this is a finding.'
            },
            @{
                FeatureName = 'Web-DAV-Publishing'
                InstallState = 'Absent'
                OrganizationValueRequired = $false
                CheckContent = 'Open the IIS 8.5 Manager.

                Click the IIS 8.5 web server name.

                Review the features listed under the “IIS" section.

                If the "WebDAV Authoring Rules" icon exists, this is a finding.'
            }
        )
        #endregion
        Foreach ($testRule in $testRuleList)
        {
            . .\Convert.CommonTests.ps1
        }

        #region Add Custom Tests Here

        #endregion
    }
}
finally
{
    . $PSScriptRoot\.tests.footer.ps1
}
