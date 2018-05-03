rule Email_Phishing_DblDom_15
{
strings:
	$a0 = { 2f70617970616c2e636f6d2e61752f70617970616c2e636f6d2e61752f }

condition:
	$a0
}

        
