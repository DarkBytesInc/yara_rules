rule Win_Trojan_Bancos_981
{
strings:
	$a0 = { 81b469cbbcc30e6c0cf52d37fd4cd8bda33c34433a2099dfbb7d86907e59573e269fa03aded0191a3d4884acdb8c92366e030b478d09979fab21ab1e2f51ec693afdba9469987acf1967e7dd60ec88a5ef9541795f }

condition:
	$a0
}

        
