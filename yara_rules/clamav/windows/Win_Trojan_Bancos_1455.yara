rule Win_Trojan_Bancos_1455
{
strings:
	$a0 = { 5e262fe35615987e31a78ea501a5318a9e4cab1050103041ba8221c3cdae11f4adca0c760700947eb302ef30d6dcd2e0ca32c4b4cd39e9e6eebaf0a6e135cc8e36433bd93b7dc3f78e09402cfec474add30136a499bd6bc813c6d32b780f7b40 }

condition:
	$a0
}

        
