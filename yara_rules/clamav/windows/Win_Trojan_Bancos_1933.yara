rule Win_Trojan_Bancos_1933
{
strings:
	$a0 = { 5d98468837b913f2b75b88cd0a6e5965b6bbfefa8500ed1fbc2055fb8e677f039cd3ea3406e66154b11cc9199e21227af28dbf7c8aaa744ab1561fba480c44951a12cdbcf6471a3ba018dc057ca554f29e76c6a0169cc59c867f }

condition:
	$a0
}

        
