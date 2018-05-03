rule Email_Trojan_Phishing_10
{
strings:
	$a0 = { 687474703a2f2f73656e73656c696b652e636f6d[0-42]756e7375627363726962652e3c62722f3e46616365626f }

condition:
	$a0
}

        
