rule Win_Worm_Autorun_209
{
strings:
	$a0 = { 4f50454e3d4558504c305245522e657865[0-38]5c436f6d6d616e643d4558504c305245522e657865 }

condition:
	$a0
}

        
