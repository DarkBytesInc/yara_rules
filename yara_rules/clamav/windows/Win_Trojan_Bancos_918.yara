rule Win_Trojan_Bancos_918
{
strings:
	$a0 = { 56bd9512cb2cc0f8d90ed10befecf4a44877bc218a942ca61cefc3572a94c384d90ba519087d1da19bbee97e2020ac5441aa67ecb2be8228470ef7da275fefa834452d2b5182dcb8ef6f00439985488c9c978375dd }

condition:
	$a0
}

        
