rule Win_Worm_Stration_532
{
strings:
	$a0 = { 5c0000002e657865000000005d7a727b6679 }

condition:
	$a0
}

        
