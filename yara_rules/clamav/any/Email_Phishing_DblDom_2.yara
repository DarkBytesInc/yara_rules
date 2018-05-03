rule Email_Phishing_DblDom_2
{
strings:
	$a0 = { 687474703a2f2f7777772e68616c696661782e636f2e756b2e }

condition:
	$a0
}

        
