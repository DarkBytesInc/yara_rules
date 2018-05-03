rule Win_Tool_Shellcode_13581_1
{
strings:
	$a0 = { b97868827c33c0bbf80c867c5150ffd3b97868827c33c0bbf80c867c5150ffd3 }

condition:
	$a0
}

        
