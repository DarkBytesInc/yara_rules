rule Win_Spyware_Banker_303
{
strings:
	$a0 = { 416f6cebf1386ef5bfc4d05bf848b0285b151449e423e3ec6f9995cca0e0e14385d1b5b4cfb4c14482531820697161b4afeb1a1edf73022481df78be8b83aacbb67d997924039cea6b7eabe72387334ed559c214ef36e1860373938e361e6b897ac8c5702e706672410a5525fae595b6d9386fb4d68993dda2d27a3069cd718eda9fa92c3872dd591413d4ce4ff53ea4db3a64f45cdc }

condition:
	$a0
}

        