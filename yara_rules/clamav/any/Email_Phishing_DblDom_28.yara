rule Email_Phishing_DblDom_28
{
strings:
	$a0 = { 687474703a2f2f7777772e6e6174776573742e636f2e756b2e }

condition:
	$a0
}

        
