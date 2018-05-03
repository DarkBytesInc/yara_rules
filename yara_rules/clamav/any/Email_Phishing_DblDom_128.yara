rule Email_Phishing_DblDom_128
{
strings:
	$a0 = { 687474703a2f2f[1-20]2e6361686f6f742e636f6d2e }

condition:
	$a0
}

        
