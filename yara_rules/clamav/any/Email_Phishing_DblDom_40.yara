rule Email_Phishing_DblDom_40
{
strings:
	$a0 = { 687474703a2f2f[0-10]2e6e776f6c622e636f6d2e }

condition:
	$a0
}

        
