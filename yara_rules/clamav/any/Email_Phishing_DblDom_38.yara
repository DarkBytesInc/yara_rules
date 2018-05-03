rule Email_Phishing_DblDom_38
{
strings:
	$a0 = { 2f2e7777772e6361706974616c6f6e652e636f6d2f }

condition:
	$a0
}

        
