rule Unix_Tool_13676_1
{
strings:
	$a0 = { 31c050b00f6861646f7768632f7368682f2f657489e331c966b9ff01cd8040cd80 }

condition:
	$a0
}

        
