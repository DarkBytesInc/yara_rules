rule Email_Phishing_DblDom_27
{
strings:
	$a0 = { 687474703a2f2f686972696e672d[0-16]2e6d6f6e737465722e636f6d2e }

condition:
	$a0
}

        
