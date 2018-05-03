rule Win_Tool_Shellcode_13574_1
{
strings:
	$a0 = { 8bec686578652068636d642e8d45f850b88d15867cffd0 }

condition:
	$a0
}

        
