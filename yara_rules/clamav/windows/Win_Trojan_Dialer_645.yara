rule Win_Trojan_Dialer_645
{
strings:
	$a0 = { 54574152494adb49a5431914444e533cfdb9dfde0b454e540453494f4e5c1ec3455c4dadb4f48b2f57555250564e071461f7ba4ed36c50a47665cb24bc91 }

condition:
	$a0
}

        
