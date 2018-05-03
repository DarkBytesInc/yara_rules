rule Email_Phishing_DblDom_44
{
strings:
	$a0 = { 687474703a2f2f[0-10]2e6e776f6c622e636f2e756b2d }

condition:
	$a0
}

        
