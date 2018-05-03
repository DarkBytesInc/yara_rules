rule Email_Phishing_DblDom_8
{
strings:
	$a0 = { 687474703a2f2f[0-35]2e7262732e636f2e756b2e }

condition:
	$a0
}

        
