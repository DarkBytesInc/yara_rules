rule Email_Phishing_DblDom_3
{
strings:
	$a0 = { 687474703a2f2f7777772e687362632e636f2e756b2e }

condition:
	$a0
}

        
