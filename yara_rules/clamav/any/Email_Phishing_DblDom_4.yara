rule Email_Phishing_DblDom_4
{
strings:
	$a0 = { 687474703a2f2f6d79627573696e65737362616e6b2e616c6c69616e63652d6c65696365737465722e636f2e756b2e }

condition:
	$a0
}

        
