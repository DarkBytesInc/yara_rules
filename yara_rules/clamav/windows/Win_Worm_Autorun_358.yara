rule Win_Worm_Autorun_358
{
strings:
	$a0 = { 7368656c6c657865637574653d2272657379636c65645c626f6f742e636f6d20653a22 }

condition:
	$a0
}

        
