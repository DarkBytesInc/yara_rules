rule Win_Worm_Netres_6
{
strings:
	$a0 = { ff8b0d3c6e0551a1d06f05518b008b1540430551e8bbb8ffffa1d06f05518b00e82fb9ffffe8d6f2faff0000ffffffff080000004e6574 }

condition:
	$a0
}

        
