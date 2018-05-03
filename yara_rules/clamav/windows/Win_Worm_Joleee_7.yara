rule Win_Worm_Joleee_7
{
strings:
	$a0 = { 55545de869feffff6a00ff158c6c410033c05dc3cccccccccccccccccccccc55545d64a1180000005dc3cccccccccc55545d83ec28 }

condition:
	$a0
}

        
