rule Win_Worm_Netres_4
{
strings:
	$a0 = { ff8b0d3c6e0551a1d06f05518b008b1540430551e803b8ffffa1d06f05518b00e877b8ffffe81ef2faff0000ffffffff080000004e6574 }

condition:
	$a0
}

        
