rule Email_Phishing_DblDom_20
{
strings:
	$a0 = { 2f687474702f6e6174696f6e776964652e636f2e756b2f }

condition:
	$a0
}

        
