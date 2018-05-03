rule Email_Phishing_DblDom_74
{
strings:
	$a0 = { 687474703a2f2f6f6e6c696e6562616e6b696e672e68616c696661782e636f2e756b2e }

condition:
	$a0
}

        
