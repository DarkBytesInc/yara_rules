rule Email_Phishing_DblDom_16
{
strings:
	$a0 = { 687474703a2f2f7777772e6e776f6c622e636f6d2e }

condition:
	$a0
}

        
