rule Win_Trojan_Spambot_111
{
strings:
	$a0 = { b34b5db24e1de6038bffff8fff5ad71352bd64d8883ba87a9b3f5551287dc9e22810e1a5c2bdabffffff991bde7ba20ffd479e6e5a42881e10b756d51157437ce3f8020f4ffffbff71f74d2b7aa32211a15b9e527a29107860d04663652104ff1f0dfc9160fd1fcf0965a7e27cc5 }

condition:
	$a0
}

        
