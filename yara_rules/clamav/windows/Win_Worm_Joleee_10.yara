rule Win_Worm_Joleee_10
{
strings:
	$a0 = { 558bece87ffeffff6a00ff156c66410033c05dc3cccccccccccccccccccccccccccccc55545d64a1180000005d }

condition:
	$a0
}

        
