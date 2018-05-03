rule Email_Phishing_DblDom_48
{
strings:
	$a0 = { 687474703a2f2f[0-10]2e69662e636f2e756b2d }

condition:
	$a0
}

        
