rule Win_Tool_Shellcode_13595_1
{
strings:
	$a0 = { eb02bac793bf77ffd2cce8f3ffffff63616c63 }

condition:
	$a0
}

        
