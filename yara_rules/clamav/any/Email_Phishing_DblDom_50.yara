rule Email_Phishing_DblDom_50
{
strings:
	$a0 = { 687474703a2f2f[0-10]2e69662e636f2e756b2e }

condition:
	$a0
}

        
