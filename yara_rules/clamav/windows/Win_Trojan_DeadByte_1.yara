rule Win_Trojan_DeadByte_1
{
strings:
	$a0 = { 0d0a666f722025256620696e20282a2e6261742920646f2063616c6c202530203720252566 }

condition:
	$a0
}

        
