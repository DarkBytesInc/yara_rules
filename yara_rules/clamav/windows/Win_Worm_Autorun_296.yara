rule Win_Worm_Autorun_296
{
strings:
	$a0 = { 7368656c6c657865637574653d777363726970742e65786520222026206d6f6e6e6f6d }

condition:
	$a0
}

        
