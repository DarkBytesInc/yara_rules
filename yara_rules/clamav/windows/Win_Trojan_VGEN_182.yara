rule Win_Trojan_VGEN_182
{
strings:
	$a0 = { 90909081f39557bd9001b83e65f7d890909031460083c6007b004583c50183c700904b75edeb44d28d17032bda }

condition:
	$a0
}

        
