rule Win_Trojan_Flooder_25
{
strings:
	$a0 = { 546865526170697374 }
	$a1 = { 43006f006f006b00690065003a00200000000000080000004700450054 }

condition:
	$a0 and $a1
}

        
