rule Email_Phishing_DblDom_10
{
strings:
	$a0 = { 687474703a2f2f7777772e6f6e6c696e652e6c6c6f7964737473622e636f2e756b2e }

condition:
	$a0
}

        