rule Email_Phishing_DblDom_1
{
strings:
	$a0 = { 687474703a2f2f7777772e7262736469676974616c2e636f6d2e }

condition:
	$a0
}

        
