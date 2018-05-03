rule Win_Worm_Joleee_8
{
strings:
	$a0 = { be8cf256fa81c6b50db90556beabc045fa81c6553fba0556ff155c1040005951ff15301140005981e81e000000505e }

condition:
	$a0
}

        
