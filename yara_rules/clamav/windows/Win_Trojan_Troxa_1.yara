rule Win_Trojan_Troxa_1
{
strings:
	$a0 = { e990fcffff }

condition:
	$a0
}

        
