rule Win_Worm_Stration_572
{
strings:
	$a0 = { 83ec34b90c00000033c0 }
	$a1 = { 90909090 }

condition:
	$a0 and $a1
}

        
