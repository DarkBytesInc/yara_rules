rule Email_Phishing_DblDom_29
{
strings:
	$a0 = { 687474703a2f2f[0-20]2e61626265796e6174696f6e616c2e636f2e756b2e }

condition:
	$a0
}

        
