rule Email_Phishing_DblDom_62
{
strings:
	$a0 = { 2f2e7777772e70617970616c2e636f2e756b }

condition:
	$a0
}

        
