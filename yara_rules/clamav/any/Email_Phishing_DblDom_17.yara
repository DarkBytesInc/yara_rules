rule Email_Phishing_DblDom_17
{
strings:
	$a0 = { 687474703a2f2f68616c696661782e636f2e756b2e }

condition:
	$a0
}

        
