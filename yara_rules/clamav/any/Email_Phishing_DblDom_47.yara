rule Email_Phishing_DblDom_47
{
strings:
	$a0 = { 687474703a2f2f[0-10]2e69662e636f6d2d }

condition:
	$a0
}

        
