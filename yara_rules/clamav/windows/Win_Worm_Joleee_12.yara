rule Win_Worm_Joleee_12
{
strings:
	$a0 = { 55545de848feffff33c05dc3cccccccc558bec64a1180000005dc3 }

condition:
	$a0
}

        
