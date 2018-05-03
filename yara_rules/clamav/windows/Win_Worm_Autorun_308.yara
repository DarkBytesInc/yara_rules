rule Win_Worm_Autorun_308
{
strings:
	$a0 = { 7368656c6c657865637574653d777363726970742e657865206d637e2e766265 }

condition:
	$a0
}

        
