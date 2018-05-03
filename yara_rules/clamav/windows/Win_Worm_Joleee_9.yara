rule Win_Worm_Joleee_9
{
strings:
	$a0 = { 55545de868feffff6a00ff155c6a410033c05dc3558bec64ff3518000000585dc3cccccc558b }

condition:
	$a0
}

        
