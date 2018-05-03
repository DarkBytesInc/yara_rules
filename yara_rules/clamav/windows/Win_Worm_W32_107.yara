rule Win_Worm_W32_107
{
strings:
	$a0 = { 246e69636b203d3d20246d65[0-29]6e31333d20202f6463632073656e6420246e69636b }

condition:
	$a0
}

        
