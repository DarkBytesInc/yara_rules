rule Win_Worm_N_74
{
strings:
	$a0 = { 2f5f7674695f62696e2f2e2e25323535632e2e2f2e2e25323535632e2e2f2e2e25323535632e2e002f5f }

condition:
	$a0
}

        
