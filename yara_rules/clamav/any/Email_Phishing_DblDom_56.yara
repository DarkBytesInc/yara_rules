rule Email_Phishing_DblDom_56
{
strings:
	$a0 = { 2e636f6d2f7777772e70617970616c2e636f6d2f }

condition:
	$a0
}

        
