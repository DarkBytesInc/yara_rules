rule Email_Phishing_DblDom_12
{
strings:
	$a0 = { 687474703a2f2f6f6c62322e6e6174696f6e65742e636f6d2e }

condition:
	$a0
}

        
