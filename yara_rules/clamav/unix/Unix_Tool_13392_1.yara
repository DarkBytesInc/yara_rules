rule Unix_Tool_13392_1
{
strings:
	$a0 = { 6a0f5831c95166b9b6016861646f7768632f7368682f2f657489e3cd8040cd80 }

condition:
	$a0
}

        
