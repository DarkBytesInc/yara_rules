rule Win_Trojan_Autorooter_1
{
strings:
	$a0 = { 666972656461656d6f6e202d6920646c6c33322022633a5c77696e6e745c73 }
	$a1 = { 6d33325c6e657420737461727420646c6c3332 }

condition:
	$a0 and $a1
}

        
