rule Win_Worm_Netres_3
{
strings:
	$a0 = { ff8b0d64500551a1844f05518b008b15b4260551e803c4ffffa1844f05518b00e877c4ffffe8de05fbff0000ffffffff0f0000004e6574 }

condition:
	$a0
}

        
