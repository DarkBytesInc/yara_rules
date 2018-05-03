rule Email_Phishing_DblDom_32
{
strings:
	$a0 = { 687474703a2f2f6c6f67696e2e70617970616c2e636f6d2e }

condition:
	$a0
}

        
