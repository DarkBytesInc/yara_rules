rule Win_Worm_Stration_535
{
strings:
	$a0 = { e80300????8d??2414????e80300[0-6]81c424010000c39090 }

condition:
	$a0
}

        
