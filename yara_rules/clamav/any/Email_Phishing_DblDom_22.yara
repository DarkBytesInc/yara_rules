rule Email_Phishing_DblDom_22
{
strings:
	$a0 = { 2f7777772e656261792e636f2e756b2f7777772e656261792e636f2e756b2f }

condition:
	$a0
}

        
