rule Win_Trojan_W_129
{
strings:
	$a0 = { e8000000005d81ed0510400060b85bf280008db528104000b9a2050000310683c60186c4d1c8e2f5 }

condition:
	$a0
}

        
