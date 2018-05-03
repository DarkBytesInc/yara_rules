rule Email_Phishing_DblDom_64
{
strings:
	$a0 = { 687474703a2f2f6e6174776573742e636f6d2e }

condition:
	$a0
}

        
