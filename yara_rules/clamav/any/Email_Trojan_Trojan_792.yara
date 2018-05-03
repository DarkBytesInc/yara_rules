rule Email_Trojan_Trojan_792
{
strings:
	$a0 = { 48616c6c6f[0-25]61732070726f6d697365642063686e676c6f67206174746163686564 }

condition:
	$a0
}

        
