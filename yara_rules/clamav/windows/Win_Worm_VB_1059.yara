rule Win_Worm_VB_1059
{
strings:
	$a0 = { 6814124000e8f0ffffff000000000000300000004000000000000000f8479571 }

condition:
	$a0
}

        
