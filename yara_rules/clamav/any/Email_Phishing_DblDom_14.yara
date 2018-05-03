rule Email_Phishing_DblDom_14
{
strings:
	$a0 = { 687474703a2f2f7777772e6369746962616e6b2e636f2e756b2e }

condition:
	$a0
}

        
