rule Win_Worm_Stration_551
{
strings:
	$a0 = { 33382e6f752f647964010000007e0000008082 }

condition:
	$a0
}

        
