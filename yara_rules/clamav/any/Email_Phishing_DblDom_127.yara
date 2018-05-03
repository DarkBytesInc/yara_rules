rule Email_Phishing_DblDom_127
{
strings:
	$a0 = { 687474703a2f2f[5-100]2f2e6e6174696f6e776964652e636f2e756b }

condition:
	$a0
}

        
