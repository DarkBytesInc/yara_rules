rule Email_Phishing_DblDom_67
{
strings:
	$a0 = { 687474703a2f2f6369746962616e6b2e636f6d2e616f }

condition:
	$a0
}

        
