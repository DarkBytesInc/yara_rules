rule Win_Worm_Netres_5
{
strings:
	$a0 = { ff8b0d3c5e0551a1d05f05518b008b157c410551e847baffffa1d05f05518b00e8bbbaffffe8b6f5faff0000ffffffff080000004e6574 }

condition:
	$a0
}

        
