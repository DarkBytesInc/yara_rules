rule Email_Phishing_DblDom_26
{
strings:
	$a0 = { 687474703a2f2f736974656b65792e62616e6b6f66616d65726963612e636f6d2e }

condition:
	$a0
}

        
