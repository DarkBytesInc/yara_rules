rule Win_Trojan_CivilWar_14
{
strings:
	$a0 = { 5e81ee0701bf0001575681c65502fca5a55e33c08ec026813e8600007d7502eb3626a186002e8984510226a184 }

condition:
	$a0
}

        
