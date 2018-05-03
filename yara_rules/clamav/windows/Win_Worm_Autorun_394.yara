rule Win_Worm_Autorun_394
{
strings:
	$a0 = { 7368656c6c657865637574653d777363726970742e657865 }
	$a1 = { 2e766273 }

condition:
	$a0 and $a1
}

        
