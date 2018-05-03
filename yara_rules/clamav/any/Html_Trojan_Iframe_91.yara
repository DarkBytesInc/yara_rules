rule Html_Trojan_Iframe_91
{
strings:
	$a0 = { 7372633d687474703a2f2f73616d70616f696e746c2e636f6d2f[0-32]3c2f696672616d653e }

condition:
	$a0
}

        
