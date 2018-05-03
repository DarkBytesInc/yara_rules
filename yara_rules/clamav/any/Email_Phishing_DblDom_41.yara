rule Email_Phishing_DblDom_41
{
strings:
	$a0 = { 687474703a2f2f[0-10]2e696e74656c6c6967656e7466696e616e63652e636f6d2d }

condition:
	$a0
}

        
