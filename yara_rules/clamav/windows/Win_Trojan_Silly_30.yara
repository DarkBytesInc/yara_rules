rule Win_Trojan_Silly_30
{
strings:
	$a0 = { 666f722025256220696e20282a2e6261742920646f20636f707920253020256125 }

condition:
	$a0
}

        
