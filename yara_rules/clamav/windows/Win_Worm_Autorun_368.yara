rule Win_Worm_Autorun_368
{
strings:
	$a0 = { 633a5c62697440756f6d2e766273 }
	$a1 = { 5368656c6c457865637574653d72656d6f76652e657865 }

condition:
	$a0 and $a1
}

        
