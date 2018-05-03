rule Win_Worm_MouseXM_1
{
strings:
	$a0 = { 8d45fcbaf49e4000e8f794ffff8d45fcba109f4000e8ea94ffff }

condition:
	$a0
}

        
