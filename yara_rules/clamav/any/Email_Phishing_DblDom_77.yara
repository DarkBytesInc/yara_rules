rule Email_Phishing_DblDom_77
{
strings:
	$a0 = { 687474703a2f2f68616c696661782d6f6e6c696e652e636f2e756b2e }

condition:
	$a0
}

        
