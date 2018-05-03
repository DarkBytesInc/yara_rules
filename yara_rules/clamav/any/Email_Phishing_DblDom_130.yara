rule Email_Phishing_DblDom_130
{
strings:
	$a0 = { 687474703a2f2f7777772e70617970616c2e636f6d2e636769 }

condition:
	$a0
}

        
