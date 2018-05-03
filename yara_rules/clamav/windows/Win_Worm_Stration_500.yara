rule Win_Worm_Stration_500
{
strings:
	$a0 = { 5c0000002e65786500 }
	$a1 = { 480f85??00000057b908000000be841040008d7c2430f3a533c05f }

condition:
	$a0 and $a1
}

        
