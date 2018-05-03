rule Win_Worm_Xolox_2
{
strings:
	$a0 = { 6e303d6f6e20313a4a4f494e3a233a7b }
	$a1 = { 6e323d2f6463632073656e6420246e69636b20633a5c666573746976616c2e657865 }

condition:
	$a0 and $a1
}

        
