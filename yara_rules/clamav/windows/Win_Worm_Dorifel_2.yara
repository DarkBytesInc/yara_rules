rule Win_Worm_Dorifel_2
{
strings:
	$a0 = { 5b2b2b2b66706e65736e70722b2b2b5d }

condition:
	$a0
}

        
