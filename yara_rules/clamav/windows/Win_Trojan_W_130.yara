rule Win_Trojan_W_130
{
strings:
	$a0 = { e8000000005d81ed0510400060b8543681008db528104000b9ab050000310683c60186c4d1c8e2f5 }

condition:
	$a0
}

        
