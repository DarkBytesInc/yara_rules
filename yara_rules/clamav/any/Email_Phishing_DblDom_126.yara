rule Email_Phishing_DblDom_126
{
strings:
	$a0 = { 2f2e7777772e70617970616c2e69742f2a }

condition:
	$a0
}

        
