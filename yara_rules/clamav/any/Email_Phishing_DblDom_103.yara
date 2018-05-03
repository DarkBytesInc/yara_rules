rule Email_Phishing_DblDom_103
{
strings:
	$a0 = { 687474703a2f2f[0-30]6369746962616e6b2e636f6d2e6a }

condition:
	$a0
}

        
