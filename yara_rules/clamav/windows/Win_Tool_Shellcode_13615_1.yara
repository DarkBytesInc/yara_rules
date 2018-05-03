rule Win_Tool_Shellcode_13615_1
{
strings:
	$a0 = { 8bec558bec686578652f68636d642e8d45f850b8c793c177ffd0 }

condition:
	$a0
}

        
