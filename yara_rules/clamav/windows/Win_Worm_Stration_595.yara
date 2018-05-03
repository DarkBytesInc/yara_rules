rule Win_Worm_Stration_595
{
strings:
	$a0 = { 5c0000002e65786500000000916494d5fa0b5ffba1aff8b328ee32 }

condition:
	$a0
}

        
