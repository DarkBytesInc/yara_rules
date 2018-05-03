rule Email_Phishing_DblDom_58
{
strings:
	$a0 = { 687474703a2f2f[0-10]2e7262736469676974616c2e636f6d2e }

condition:
	$a0
}

        
