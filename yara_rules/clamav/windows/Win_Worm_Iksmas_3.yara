rule Win_Worm_Iksmas_3
{
strings:
	$a0 = { 558bec6aff68236f400068b410400064a10000 }
	$a1 = { 5522694b78992154f3b36d90208326adacac2055226947 }

condition:
	$a0 and $a1
}

        
