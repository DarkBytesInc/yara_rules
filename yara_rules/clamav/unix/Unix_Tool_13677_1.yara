rule Unix_Tool_13677_1
{
strings:
	$a0 = { 31c0506861646f7768632f7368682f2f657489e36668ff0159b00fcd80 }

condition:
	$a0
}

        
