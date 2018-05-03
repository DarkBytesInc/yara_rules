rule Win_Worm_Stration_467
{
strings:
	$a0 = { 6d33ae1f7309619755374e3179a3417185e52e6a30a4b0df418cbfe9fd9161b897eae2c31220785f663cc92d6785343e4b248d0cccc3ffb9f17732f12ea874640fbd713a38 }

condition:
	$a0
}

        
