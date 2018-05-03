rule Email_Phishing_DblDom_5
{
strings:
	$a0 = { 687474703a2f2f6e6662636f6e6e6563742e6e6f727468666f726b62616e6b2e636f6d2e }

condition:
	$a0
}

        
