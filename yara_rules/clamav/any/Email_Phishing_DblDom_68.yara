rule Email_Phishing_DblDom_68
{
strings:
	$a0 = { 2f2e61626265792e636f2e756b2f }

condition:
	$a0
}

        
