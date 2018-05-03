rule Email_Phishing_DblDom_125
{
strings:
	$a0 = { 2e636f6d2f7777772e63686173652e636f6d2f }

condition:
	$a0
}

        
