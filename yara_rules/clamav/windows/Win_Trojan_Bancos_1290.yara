rule Win_Trojan_Bancos_1290
{
strings:
	$a0 = { bc3b8ccdb725b7d4123c5faff0aba10700a455353b4daaa2ff92a1664da0d5c2899d7429b042e8f185c185c31c1f198b2bad1acc361a99b8130bbe38e5fe69e6534c506c5203944328985b27f65a0ba86cb9 }

condition:
	$a0
}

        
