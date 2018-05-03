rule Win_Worm_Sobig_6
{
strings:
	$a0 = { b291c7ffba0cab7edbdc3beaec457668b6d329ff48de2b3b7f363728bb17361d7a2ecb919199b66a879e22b070edf2c812c7fa37508409e2795ae8c052e403e46a }

condition:
	$a0
}

        
