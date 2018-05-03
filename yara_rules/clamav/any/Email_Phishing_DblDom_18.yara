rule Email_Phishing_DblDom_18
{
strings:
	$a0 = { 2e636f6d2f7777772e6e6174776573742e636f2e756b2f }

condition:
	$a0
}

        
