rule Win_Trojan_Shiznat_2
{
strings:
	$a0 = { 6e333d256d6972637665722076342e32[0-5]7363726970742e70617373206675636b6f6666 }

condition:
	$a0
}

        
