rule Email_Trojan_Trojan_691
{
strings:
	$a0 = { 4f6c6861207175656d2066657a20766964656f7a696e686f206361736569726f266e627370 }

condition:
	$a0
}

        
