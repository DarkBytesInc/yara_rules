rule Win_Trojan_Trojan_112
{
strings:
	$a0 = { 9090b8000026a3a30226a3a50226a2a702b419cd212ea2fa02b4478ae48bf6b60004018ad2908ad08ad290befc02cd21b40eb200cd21b0013c017502b006b4 }

condition:
	$a0
}

        
