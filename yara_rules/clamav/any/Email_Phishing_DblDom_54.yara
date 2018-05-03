rule Email_Phishing_DblDom_54
{
strings:
	$a0 = { 2f2e7777772e70617970616c2e636f6d2f }

condition:
	$a0
}

        
