rule Win_Trojan_Bancos_1047
{
strings:
	$a0 = { 7f029cad58758c82aa65b899edfa5b3860c66e1372e62e2537af7439fbaa6f99d697a07c96ccaae717922769c9587a8bd86247f47fef43071e4c5b2da56a40e7c8ec68dd29af2ee70aa5f9fb3d81a8aa9cb965dc038a9c7b }

condition:
	$a0
}

        
