rule Email_Phishing_DblDom_73
{
strings:
	$a0 = { 687474703a2f2f63697469627573696e6573732e6369746962616e6b2e636f6d2e6161 }

condition:
	$a0
}

        
