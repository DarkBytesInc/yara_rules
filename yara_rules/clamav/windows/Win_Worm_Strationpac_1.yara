rule Win_Worm_Strationpac_1
{
strings:
	$a0 = { 4d5a4b45524e454c3332 }
	$a1 = { 0000010001002020000001000800a80800000100 }
	$a2 = { 035950483bc172028bc1c1e006b1408d9c857c030000ff56043c048bd8725f33 }

condition:
	$a0 and $a1 and $a2
}

        
