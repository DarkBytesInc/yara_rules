rule Win_Worm_Ardurk_1
{
strings:
	$a0 = { 8d35201040008d1db43f40008b133116ad3bf375f9e997db }

condition:
	$a0
}

        
