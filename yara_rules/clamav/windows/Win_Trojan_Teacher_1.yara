rule Win_Trojan_Teacher_1
{
strings:
	$a0 = { 1e0633f69c560e8edec706040062018c0e0600c41e0c001f8b1666005252b94700031446e2fb011650008bec814e06 }

condition:
	$a0
}

        
