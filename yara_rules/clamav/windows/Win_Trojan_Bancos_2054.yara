rule Win_Trojan_Bancos_2054
{
strings:
	$a0 = { dd098df97fe2ac51bd4c2313dc45605bd1942eba7cc75bef87b427e0f9c0284fc435c062a86446297a4d6267f47f8a35c75f6e1307a54fe9e83eb652dace525451e7a3da23e666961cbb3dd647848c6d5692 }

condition:
	$a0
}

        
