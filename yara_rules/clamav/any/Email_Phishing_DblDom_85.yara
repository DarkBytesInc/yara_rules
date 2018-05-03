rule Email_Phishing_DblDom_85
{
strings:
	$a0 = { 687474703a2f2f6962732e62616e6b776573742e636f6d2e61752e }

condition:
	$a0
}

        
