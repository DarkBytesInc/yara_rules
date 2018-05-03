rule Email_Phishing_DblDom_30
{
strings:
	$a0 = { 687474703a2f2f7777772e6d79627573696e65737362616e6b2e636f2e756b2e }

condition:
	$a0
}

        
