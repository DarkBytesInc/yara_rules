rule Win_Trojan_UX_1
{
strings:
	$a0 = { b200c800010068201c9a8a02b200a30602891608026800209a8a02b200a30a0289160c028dbe00ff16576a009a }

condition:
	$a0
}

        
