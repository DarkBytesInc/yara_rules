rule Email_Phishing_DblDom_23
{
strings:
	$a0 = { 2f2e7777772e62616e6b6f66616d65726963612e636f6d2f }

condition:
	$a0
}

        
