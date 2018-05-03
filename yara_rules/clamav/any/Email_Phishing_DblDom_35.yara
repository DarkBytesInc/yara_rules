rule Email_Phishing_DblDom_35
{
strings:
	$a0 = { 687474703a2f2f7777772e62616e6361726f6d612e69742e }

condition:
	$a0
}

        
