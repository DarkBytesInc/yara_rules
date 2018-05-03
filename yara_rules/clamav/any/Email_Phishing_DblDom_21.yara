rule Email_Phishing_DblDom_21
{
strings:
	$a0 = { 2f2e68616c696661782d6f6e6c696e652e636f2e756b2f }

condition:
	$a0
}

        
