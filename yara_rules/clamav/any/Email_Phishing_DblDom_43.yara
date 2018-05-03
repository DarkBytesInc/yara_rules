rule Email_Phishing_DblDom_43
{
strings:
	$a0 = { 687474703a2f2f6d79[0-5]2e696e74656c6c6967656e7466696e616e63652e636f2e756b2e }

condition:
	$a0
}

        
