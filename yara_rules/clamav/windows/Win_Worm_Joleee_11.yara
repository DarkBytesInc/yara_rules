rule Win_Worm_Joleee_11
{
strings:
	$a0 = { 55545de84dfeffff6a00ff15ec84410033c05dc3cccccccccccccccc55545d64a1180000005dc3cccccccccc55545d83 }

condition:
	$a0
}

        
