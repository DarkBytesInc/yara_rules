rule Email_Phishing_DblDom_83
{
strings:
	$a0 = { 687474703a2f2f63686173656f6e6c696e652e63686173652e636f6d2e }

condition:
	$a0
}

        
