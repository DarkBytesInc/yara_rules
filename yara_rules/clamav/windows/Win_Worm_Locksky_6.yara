rule Win_Worm_Locksky_6
{
strings:
	$a0 = { 73616368c746046f737478c746082e657865c6460c006a0068cd2f40006872314000e8beefffff68ff294000e8c6efffff68 }

condition:
	$a0
}

        
