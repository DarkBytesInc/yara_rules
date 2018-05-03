rule Win_Worm_Stration_599
{
strings:
	$a0 = { 5c0000002e657865000000007ba7f31e342f54 }

condition:
	$a0
}

        
