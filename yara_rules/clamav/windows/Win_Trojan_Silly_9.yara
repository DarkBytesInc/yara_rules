rule Win_Trojan_Silly_9
{
strings:
	$a0 = { 6f722025256220696e20282a2e6261742920646f20636f707920253020252562 }

condition:
	$a0
}

        
