rule Win_Trojan_Tvir_1
{
strings:
	$a0 = { fc0633f69c560e8edec706040062018c0e0600c41e0c001f8b1666005252b94700031446e2fb011650008bec814e06 }

condition:
	$a0
}

        
