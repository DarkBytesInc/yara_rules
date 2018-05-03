rule Win_Worm_Hermon_1
{
strings:
	$a0 = { 6a056a006a006848a240006864a24000e8c7b0ffff50e865f9ffff }

condition:
	$a0
}

        
