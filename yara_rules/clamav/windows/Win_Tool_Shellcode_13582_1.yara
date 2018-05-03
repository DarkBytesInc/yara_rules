rule Win_Tool_Shellcode_13582_1
{
strings:
	$a0 = { 68874c807cb86d13867cffd068874c807cb86d13867cffd0 }

condition:
	$a0
}

        
