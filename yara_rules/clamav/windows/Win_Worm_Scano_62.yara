rule Win_Worm_Scano_62
{
strings:
	$a0 = { 6888ac1413e83c0000005b8bfbfc33c083c9 }
	$a1 = { fb4661696c752468 }

condition:
	$a0 and $a1
}

        
