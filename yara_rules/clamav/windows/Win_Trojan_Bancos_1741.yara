rule Win_Trojan_Bancos_1741
{
strings:
	$a0 = { 1eef5f695cf030379acd10bfbdb0d19d17be4d587df5f2303d33ed061d3d3d18590dd86166b357be3c19379568851db2974814160a2071e32b26a6e442619faa1a6e1491f4b6 }

condition:
	$a0
}

        
