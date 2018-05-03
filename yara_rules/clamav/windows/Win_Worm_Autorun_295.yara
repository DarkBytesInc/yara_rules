rule Win_Worm_Autorun_295
{
strings:
	$a0 = { 7368656c6c657865637574653d7365637265742e657865 }

condition:
	$a0
}

        
