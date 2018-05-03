rule Email_Phishing_DblDom_36
{
strings:
	$a0 = { 687474703a2f2f7777772e35332e636f6d2e }

condition:
	$a0
}

        
