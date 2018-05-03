rule Win_Worm_Stration_549
{
strings:
	$a0 = { 69732a4b626960736f3d07000000002f00000080 }

condition:
	$a0
}

        
