rule Win_Trojan_Batalia4_1
{
strings:
	$a0 = { 0d0a666f722025256220696e20282a2e6261742920646f2063616c6c202530203420252562 }

condition:
	$a0
}

        
