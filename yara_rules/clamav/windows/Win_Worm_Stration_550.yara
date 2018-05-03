rule Win_Worm_Stration_550
{
strings:
	$a0 = { 316c7b70726c2d376d263b26430000007e00000075 }

condition:
	$a0
}

        
