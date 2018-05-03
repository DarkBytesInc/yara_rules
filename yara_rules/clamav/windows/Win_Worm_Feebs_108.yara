rule Win_Worm_Feebs_108
{
strings:
	$a0 = { 163265ee8e12d519efad34ce9cc7569db8aaed755ac0098402b0a2fbff17fb28350e38b147aa4d4bd2497b19cffd87eba9cd0c491a4c7bee71ad58911d10c62c3f2eaf30453dcb7ed8b2882958a64bfc2c471cc3bd3fb6611bb448324abb5ae9 }

condition:
	$a0
}

        
