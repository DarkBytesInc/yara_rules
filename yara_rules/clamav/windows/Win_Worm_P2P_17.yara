rule Win_Worm_P2P_17
{
strings:
	$a0 = { 68d9d34100e801000000c3c3ffda09d580e72d240094dbf17fba9738ffc8dc947f95c07f14443f }

condition:
	$a0
}

        
