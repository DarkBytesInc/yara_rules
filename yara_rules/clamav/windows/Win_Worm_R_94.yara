rule Win_Worm_R_94
{
strings:
	$a0 = { 81e600f0ffff81ee0010000066813e4d5a75f30fb77e3c03fe8b6f7803ee8b5d2003de33c08bd683c304408b3b03fa }

condition:
	$a0
}

        
