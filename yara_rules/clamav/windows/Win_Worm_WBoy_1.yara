rule Win_Worm_WBoy_1
{
strings:
	$a0 = { 558bec83ec4456ff15705040008bf08a063c2275143c2274088a46014684c075f4803e22750d46eb0a }

condition:
	$a0
}

        
