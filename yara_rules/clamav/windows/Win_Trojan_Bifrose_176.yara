rule Win_Trojan_Bifrose_176
{
strings:
	$a0 = { be3041f3f80e25934ff6c0703a4db20325aab07ce5008381c2c7ce0600705be93b8f3c30b100f8235d28e15f50fc00718089e0e9966e9003ea9d771cb1b7f8135505fcc6 }

condition:
	$a0
}

        
