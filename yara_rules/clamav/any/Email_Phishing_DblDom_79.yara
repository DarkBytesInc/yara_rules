rule Email_Phishing_DblDom_79
{
strings:
	$a0 = { 687474703a2f2f68616c696661782d636f2d756b2e }

condition:
	$a0
}

        
