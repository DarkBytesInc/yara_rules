rule Email_Phishing_DblDom_13
{
strings:
	$a0 = { 687474703a2f2f[0-35]2e636974697a656e7362616e6b2e636f6d2e }

condition:
	$a0
}

        
