rule Win_Worm_Autorun_299
{
strings:
	$a0 = { 7368656c6c657865637574653d66756e2e786c732e657865 }

condition:
	$a0
}

        
