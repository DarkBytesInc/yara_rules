rule Email_Phishing_DblDom_89
{
strings:
	$a0 = { 2f6c6c6f7964737473622e636f2e756b2f6c6c6f7964737473622e636f2e756b2f }

condition:
	$a0
}

        
