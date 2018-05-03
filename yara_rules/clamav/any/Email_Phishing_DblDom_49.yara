rule Email_Phishing_DblDom_49
{
strings:
	$a0 = { 687474703a2f2f[0-10]2e6e6174776573742e636f2e756b2d }

condition:
	$a0
}

        
