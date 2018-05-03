rule Email_Phishing_DblDom_7
{
strings:
	$a0 = { 687474703a2f2f7777772e7262732e636f2e756b2e }

condition:
	$a0
}

        
