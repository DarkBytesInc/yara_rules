rule Unix_Tool_13325_1
{
strings:
	$a0 = { 5166b9[2]6861646f7768632f7368682f2f657489e36a0f58cd8040cd80 }

condition:
	$a0
}

        
