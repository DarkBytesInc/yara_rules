rule Win_Trojan_Banker_6355
{
strings:
	$a0 = { 68bc284000e8f0ffffff000000000000300000004000000000000000b419eba546f81a4084ea180804b8c2 }

condition:
	$a0
}

        
