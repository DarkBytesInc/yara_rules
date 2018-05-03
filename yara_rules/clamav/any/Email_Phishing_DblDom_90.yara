rule Email_Phishing_DblDom_90
{
strings:
	$a0 = { 687474703a2f2f436f6c6f6e69616c62616e6b2e77656262 }

condition:
	$a0
}

        
