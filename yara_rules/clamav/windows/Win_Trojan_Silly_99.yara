rule Win_Trojan_Silly_99
{
strings:
	$a0 = { 666f722025256220696e20282a2e6261742920646f206966206e6f74202525 }

condition:
	$a0
}

        
