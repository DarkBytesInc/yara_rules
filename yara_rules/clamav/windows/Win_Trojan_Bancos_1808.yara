rule Win_Trojan_Bancos_1808
{
strings:
	$a0 = { 4d8c60682e67ccf24c8ac6a439585c3f59c1eb2437f44327fdb81447244ac2749332011a2c07657aff492fbcfab6d196ce9c39a71f3351880a1445f4dec51cce0914f3abe81f }

condition:
	$a0
}

        
