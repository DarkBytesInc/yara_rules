rule Win_Worm_Stration_561
{
strings:
	$a0 = { 6a6f664d626e66420300000007393e152835335000000000c7c382ef83829ed4dcdcb000e0e4f6e4c3d6c5c3c2c7b700657962637e0d }

condition:
	$a0
}

        
