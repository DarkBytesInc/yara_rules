rule Win_Trojan_Bancos_1943
{
strings:
	$a0 = { ac6ed0093493bd6bfa78c662bc93656ba5ddac957fb398ed471957ba86faa761215948144d781bc297b8c7c9ac734663fb21207e5b19eeaf66af74c583dffdd1eca82ff7876aca6fef7dc4240ed248be270fa3de01d671582be3 }

condition:
	$a0
}

        
