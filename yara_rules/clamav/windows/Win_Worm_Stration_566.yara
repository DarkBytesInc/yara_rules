rule Win_Worm_Stration_566
{
strings:
	$a0 = { 705c5d47565d471e7f565d54475b0933000000002f000000776b6b6f2530301f00000000b0b2a3d7d284d7bfa3a3a7d8c6d9c6fafdb69494928783cdd7ddd8ddfa }

condition:
	$a0
}

        
