rule Win_Worm_Kelvir_20
{
strings:
	$a0 = { 656c5669722d46694e414c0050726f6a }
	$a1 = { 6f006f006f0020006c00750063006b007900000000005f5f }

condition:
	$a0 and $a1
}

        
