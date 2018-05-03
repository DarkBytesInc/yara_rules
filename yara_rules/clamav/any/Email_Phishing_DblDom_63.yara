rule Email_Phishing_DblDom_63
{
strings:
	$a0 = { 2f2e7777772e68616c696661782d6f6e6c696e652e636f2e756b2f }

condition:
	$a0
}

        
