rule Win_Trojan_Dialer_703
{
strings:
	$a0 = { f995c5762647dfb90a0880d2f7f18a826c487016c10fb61203205488a14afec321750184e1f5056f83809698846489f161c54f40e040420f8fd8a086ef1fb11027c23f61e8aa161fb3648708fd900ae8228572963ca72125813a88041128294d9889f466241b8845ffbc9d82cf0dc67c971a4dce897df4fb14b258d62104d9270e237442e027151074d62248092338398931 }

condition:
	$a0
}

        