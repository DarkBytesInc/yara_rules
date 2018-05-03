rule Win_Worm_N_143
{
strings:
	$a0 = { 6563686f2030202d732003312c302d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d1f466c752d496b616e1f20762e41 }

condition:
	$a0
}

        
