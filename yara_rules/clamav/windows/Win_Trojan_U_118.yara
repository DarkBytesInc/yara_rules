rule Win_Trojan_U_118
{
strings:
	$a0 = { 57565381ec18010000e8000000005d83ed0fb8f8040000890424c74424042e00000031 }

condition:
	$a0
}

        
