Describe 'Compare-Stig' {
    Context 'When ' {

    }
    Context 'When a version to test agianst is provided' {

    }
}

Describe 'Compare-StigRule' {

}

Describe 'Get-RuleProperty' {

}

Describe 'Compare-Property' {

}

Describe 'Test-Property' {

}

Describe 'Compare-NestedPropertyRule' {

}

Describe 'Compare-AccessControl' {

}

Describe 'Get-AddedOrRemovedRuleId' {

}

Describe 'Get-RuleType' {

}

Describe 'Get-NewRuleType' {

}

Describe 'Get-AllStigId' {

}

Describe 'Get-StigXccdfPath' {
    Context 'When a version is supplied' {
        $result = Get-StigXccdfPath -StigXmlPath "$TestDrive\Test" -Version 1.15
        It 'Should return a path to a the same stig of the input version' {

        }
    }
}
