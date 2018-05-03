rule Email_Phishing_DblDom_80
{
strings:
	$a0 = { 687474703a2f2f7777772e68616c696661782d636f2d756b2e }

condition:
	$a0
}

        
