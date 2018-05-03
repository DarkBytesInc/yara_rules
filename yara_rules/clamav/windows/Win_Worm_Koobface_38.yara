rule Win_Worm_Koobface_38
{
strings:
	$a0 = { 696f6e5c5200000025735c00433a }
	$a1 = { 633a5c77696e646f77735c257325732e657865 }
	$a2 = { 474554 }
	$a3 = { 424c41434b4c4142454c }

condition:
	$a0 and $a1 and $a2 and $a3
}

        
