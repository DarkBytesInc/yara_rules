rule Win_Spyware_Banker_2283
{
strings:
	$a0 = { 02c3aade2adfedf81253a412f818dfeeae77f70a724fbc2b47a318d5d6069d5d57a3f147be6fe8315fab7febe785bed68e75a49056afd99bc1dea3ec91a3ace3c7e4f44a3104f2585d861ba8ad963221af38c93bb602dfe7104326cc89ee3f74d54f80d8 }

condition:
	$a0
}

        
