rule Win_Trojan_Tiny_91
{
strings:
	$a0 = { 01010055a60100000001000000000025000000030000004503 }

condition:
	$a0
}

        
