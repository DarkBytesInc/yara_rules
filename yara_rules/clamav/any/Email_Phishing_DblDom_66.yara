rule Email_Phishing_DblDom_66
{
strings:
	$a0 = { 687474703a2f2f6369746962616e6b2e636f6d2e617574 }

condition:
	$a0
}

        
