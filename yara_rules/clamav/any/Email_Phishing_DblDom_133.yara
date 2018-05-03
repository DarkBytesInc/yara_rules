rule Email_Phishing_DblDom_133
{
strings:
	$a0 = { 687474703a2f2f[0-30]6369746962616e6b2e636f6d2e70726f746f }

condition:
	$a0
}

        
