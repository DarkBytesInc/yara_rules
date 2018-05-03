rule Win_Worm_LoveLorn_1
{
strings:
	$a0 = { 4b6973732e6f6b2e657865002e68746d00612b005c696e642e62616b00612b }

condition:
	$a0
}

        
