rule Email_Phishing_DblDom_91
{
strings:
	$a0 = { 2f6e65772e6567672e636f6d5f }

condition:
	$a0
}

        
