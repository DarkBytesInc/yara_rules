rule Email_Phishing_DblDom_37
{
strings:
	$a0 = { 2f687474702f687474702f7365637572652f6562616e6b2e687362632e636f2e756b2f }

condition:
	$a0
}

        
