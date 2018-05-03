rule Win_Worm_Agent_35506
{
strings:
	$a0 = { e90c3a000000000000000000[0-229]e8600000000000 }

condition:
	$a0
}

        
