rule Email_Phishing_DblDom_9
{
strings:
	$a0 = { 687474703a2f2f7777772e68616c696661782d6f6e6c696e652e636f2e756b2e }

condition:
	$a0
}

        
