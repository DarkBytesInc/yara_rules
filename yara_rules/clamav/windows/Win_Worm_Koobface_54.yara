rule Win_Worm_Koobface_54
{
strings:
	$a0 = { 944ddf00b82bb0007e22c900c023c900f823c900e023c90057696e3332730000 }

condition:
	$a0
}

        
