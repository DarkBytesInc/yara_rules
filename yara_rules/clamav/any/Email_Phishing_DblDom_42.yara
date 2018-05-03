rule Email_Phishing_DblDom_42
{
strings:
	$a0 = { 687474703a2f2f[0-10]2e6e6174776573742e636f6d2e }

condition:
	$a0
}

        
