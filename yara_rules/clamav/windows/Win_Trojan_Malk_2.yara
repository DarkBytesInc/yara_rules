rule Win_Trojan_Malk_2
{
strings:
	$a0 = { 666f722025256620696e20282a2e6261742920646f20736574206d616c6b5f623d252566 }

condition:
	$a0
}

        
