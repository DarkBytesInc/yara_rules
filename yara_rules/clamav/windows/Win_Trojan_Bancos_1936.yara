rule Win_Trojan_Bancos_1936
{
strings:
	$a0 = { 4a1f788915878dcbbf92cf9a6c8245a5fe5780a6c4bb9dbb2b0bef2d44cf155fd083f3b7d3623b25cbc279e940859ba7af8b71865d897407602e5bee206a63c97ffd5726c680e2cba0c87a6e81778fd8111020e6d4c2b70da78f }

condition:
	$a0
}

        
