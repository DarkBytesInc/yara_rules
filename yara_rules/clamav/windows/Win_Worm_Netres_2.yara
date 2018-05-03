rule Win_Worm_Netres_2
{
strings:
	$a0 = { 64500551a1844f05518b008b15b4260551e8c3c3ffffa1844f05518b00e837c4ffffe89e05fbff0000ffffffff0f0000004e6574 }

condition:
	$a0
}

        
